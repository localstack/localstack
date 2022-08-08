import copy
import json
import logging
import random
import re
import time
import traceback
from typing import Dict, List

import requests
import werkzeug

from localstack import config, constants
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceResponse,
    handler,
)
from localstack.aws.api.dynamodb import (
    BatchExecuteStatementOutput,
    BatchGetItemOutput,
    BatchGetRequestMap,
    BatchWriteItemInput,
    BatchWriteItemOutput,
    BillingMode,
    CreateGlobalTableOutput,
    CreateTableInput,
    CreateTableOutput,
    DeleteItemInput,
    DeleteItemOutput,
    DeleteTableOutput,
    DescribeGlobalTableOutput,
    DescribeKinesisStreamingDestinationOutput,
    DescribeTableOutput,
    DescribeTimeToLiveOutput,
    DynamodbApi,
    ExecuteStatementInput,
    ExecuteStatementOutput,
    ExecuteTransactionInput,
    ExecuteTransactionOutput,
    GetItemInput,
    GetItemOutput,
    GlobalTableAlreadyExistsException,
    GlobalTableNotFoundException,
    KinesisStreamingDestinationOutput,
    ListGlobalTablesOutput,
    ListTablesInputLimit,
    ListTablesOutput,
    ListTagsOfResourceOutput,
    NextTokenString,
    PartiQLBatchRequest,
    PositiveIntegerObject,
    ProvisionedThroughputExceededException,
    PutItemInput,
    PutItemOutput,
    QueryInput,
    QueryOutput,
    RegionName,
    ReplicaList,
    ReplicaUpdateList,
    ResourceArnString,
    ResourceInUseException,
    ResourceNotFoundException,
    ReturnConsumedCapacity,
    ScanInput,
    ScanOutput,
    StreamArn,
    TableName,
    TagKeyList,
    TagList,
    TimeToLiveSpecification,
    TransactGetItemList,
    TransactGetItemsOutput,
    TransactWriteItemsInput,
    TransactWriteItemsOutput,
    UpdateGlobalTableOutput,
    UpdateItemInput,
    UpdateItemOutput,
    UpdateTableInput,
    UpdateTableOutput,
    UpdateTimeToLiveOutput,
)
from localstack.aws.forwarder import HttpFallbackDispatcher, get_request_forwarder_http
from localstack.aws.proxy import AwsApiListener
from localstack.constants import LOCALHOST
from localstack.http import Response
from localstack.services.awslambda import lambda_api
from localstack.services.dynamodb import server
from localstack.services.dynamodb.models import DynamoDBStore, dynamodb_stores
from localstack.services.dynamodb.server import start_dynamodb, wait_for_dynamodb
from localstack.services.dynamodb.utils import (
    ItemFinder,
    ItemSet,
    SchemaExtractor,
    calculate_crc32,
    extract_table_name_from_partiql_update,
)
from localstack.services.dynamodbstreams import dynamodbstreams_api
from localstack.services.dynamodbstreams.dynamodbstreams_api import (
    get_and_increment_sequence_number_counter,
)
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.collections import select_attributes
from localstack.utils.common import short_uid, to_bytes
from localstack.utils.json import BytesEncoder, canonical_json
from localstack.utils.strings import long_uid, to_str
from localstack.utils.threads import start_worker_thread

# set up logger
LOG = logging.getLogger(__name__)

# action header prefix
ACTION_PREFIX = "DynamoDB_20120810."

# list of actions subject to throughput limitations
READ_THROTTLED_ACTIONS = [
    "GetItem",
    "Query",
    "Scan",
    "TransactGetItems",
    "BatchGetItem",
]
WRITE_THROTTLED_ACTIONS = [
    "PutItem",
    "BatchWriteItem",
    "UpdateItem",
    "DeleteItem",
    "TransactWriteItems",
]
THROTTLED_ACTIONS = READ_THROTTLED_ACTIONS + WRITE_THROTTLED_ACTIONS

MANAGED_KMS_KEYS = {}


class EventForwarder:
    @classmethod
    def forward_to_targets(cls, records: List[Dict], background: bool = True):
        def _forward(*args):
            # forward to kinesis stream
            records_to_kinesis = copy.deepcopy(records)
            cls.forward_to_kinesis_stream(records_to_kinesis)

            # forward to lambda and ddb_streams
            forward_records = cls.prepare_records_to_forward_to_ddb_stream(records)
            records_to_ddb = copy.deepcopy(forward_records)
            cls.forward_to_ddb_stream(records_to_ddb)

        if background:
            return start_worker_thread(_forward)
        _forward()

    @staticmethod
    def forward_to_ddb_stream(records):
        dynamodbstreams_api.forward_events(records)

    @staticmethod
    def forward_to_kinesis_stream(records):
        kinesis = aws_stack.connect_to_service("kinesis")
        table_definitions = get_store().table_definitions
        for record in records:
            event_source_arn = record.get("eventSourceARN")
            if not event_source_arn:
                continue
            table_name = event_source_arn.split("/", 1)[-1]
            table_def = table_definitions.get(table_name) or {}
            if table_def.get("KinesisDataStreamDestinationStatus") != "ACTIVE":
                continue
            stream_arn = table_def["KinesisDataStreamDestinations"][-1]["StreamArn"]
            stream_name = stream_arn.split("/", 1)[-1]
            record["tableName"] = table_name
            record.pop("eventSourceARN", None)
            record["dynamodb"].pop("StreamViewType", None)
            hash_keys = list(filter(lambda key: key["KeyType"] == "HASH", table_def["KeySchema"]))
            partition_key = hash_keys[0]["AttributeName"]
            kinesis.put_record(
                StreamName=stream_name,
                Data=json.dumps(record, cls=BytesEncoder),
                PartitionKey=partition_key,
            )

    @classmethod
    def prepare_records_to_forward_to_ddb_stream(cls, records):
        # StreamViewType determines what information is written to the stream for the table
        # When an item in the table is inserted, updated or deleted
        for record in records:
            ddb_record = record["dynamodb"]
            stream_type = ddb_record.get("StreamViewType")
            if not stream_type:
                continue
            if "SequenceNumber" not in ddb_record:
                ddb_record["SequenceNumber"] = str(get_and_increment_sequence_number_counter())
            # KEYS_ONLY  - Only the key attributes of the modified item are written to the stream
            if stream_type == "KEYS_ONLY":
                ddb_record.pop("OldImage", None)
                ddb_record.pop("NewImage", None)
            # NEW_IMAGE - The entire item, as it appears after it was modified, is written to the stream
            elif stream_type == "NEW_IMAGE":
                ddb_record.pop("OldImage", None)
            # OLD_IMAGE - The entire item, as it appeared before it was modified, is written to the stream
            elif stream_type == "OLD_IMAGE":
                ddb_record.pop("NewImage", None)
        return records

    @classmethod
    def is_kinesis_stream_exists(cls, stream_arn):
        kinesis = aws_stack.connect_to_service("kinesis")
        stream_name_from_arn = stream_arn.split("/", 1)[1]
        # check if the stream exists in kinesis for the user
        filtered = list(
            filter(
                lambda stream_name: stream_name == stream_name_from_arn,
                kinesis.list_streams()["StreamNames"],
            )
        )
        return bool(filtered)


class SSEUtils:
    """Utils for server-side encryption (SSE)"""

    @classmethod
    def get_sse_kms_managed_key(cls):
        from localstack.services.kms import provider

        existing_key = MANAGED_KMS_KEYS.get(aws_stack.get_region())
        if existing_key:
            return existing_key
        kms_client = aws_stack.connect_to_service("kms")
        key_data = kms_client.create_key(Description="Default key that protects DynamoDB data")
        key_id = key_data["KeyMetadata"]["KeyId"]

        provider.set_key_managed(key_id)
        MANAGED_KMS_KEYS[aws_stack.get_region()] = key_id
        return key_id

    @classmethod
    def get_sse_description(cls, data):
        if data.get("Enabled"):
            kms_master_key_id = data.get("KMSMasterKeyId")
            if not kms_master_key_id:
                # this is of course not the actual key for dynamodb, just a better, since existing, mock
                kms_master_key_id = cls.get_sse_kms_managed_key()
            kms_master_key_id = aws_stack.kms_key_arn(kms_master_key_id)
            return {
                "Status": "ENABLED",
                "SSEType": "KMS",  # no other value is allowed here
                "KMSMasterKeyArn": kms_master_key_id,
            }
        return {}


class ValidationException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__(code="ValidationException", status_code=400, message=message)


class DynamoDBApiListener(AwsApiListener):
    def __init__(self, provider=None):
        provider = provider or DynamoDBProvider()
        self.provider = provider
        super().__init__("dynamodb", HttpFallbackDispatcher(provider, provider.get_forward_url))

    def return_response(self, method, path, data, headers, response):
        if response._content:
            response_content = to_str(response._content)
            # fix the table and latest stream ARNs (DynamoDBLocal hardcodes "ddblocal" as the region)
            content_replaced = re.sub(
                r'("TableArn"|"LatestStreamArn"|"StreamArn")\s*:\s*"arn:([a-z-]+):dynamodb:ddblocal:([^"]+)"',
                rf'\1: "arn:\2:dynamodb:{aws_stack.get_region()}:\3"',
                response_content,
            )
            if content_replaced != response_content:
                response._content = content_replaced

        # set x-amz-crc32 headers required by some client
        fix_headers_for_updated_response(response)

        # update table definitions
        data = json.loads(to_str(data))
        if data and "TableName" in data and "KeySchema" in data:
            table_definitions = get_store().table_definitions
            table_definitions[data["TableName"]] = data


def get_store(context: RequestContext | None = None) -> DynamoDBStore:
    # todo: create an explicit protocol for to retrieve stores for each provider
    _account_id: str = context.account_id if context else get_aws_account_id()
    _region: str = context.region if context else aws_stack.get_region()
    return dynamodb_stores[_account_id][_region]


class DynamoDBProvider(DynamodbApi, ServiceLifecycleHook):
    def __init__(self):
        self.request_forwarder = get_request_forwarder_http(self.get_forward_url)

    def on_after_init(self):
        ROUTER.add(
            path="/shell",
            endpoint=self.handle_shell_ui_redirect,
            methods=["GET"],
        )
        ROUTER.add(
            path="/shell/<regex('.*'):req_path>",
            endpoint=self.handle_shell_ui_request,
        )

    def forward_request(
        self, context: RequestContext, service_request: ServiceRequest = None
    ) -> ServiceResponse:
        # check rate limiting for this request and raise an error, if provisioned throughput is exceeded
        self.check_provisioned_throughput(context.operation.name)

        # note: modifying headers in-place here before forwarding the request
        self.prepare_request_headers(context.request.headers)
        return self.request_forwarder(context, service_request)

    def get_forward_url(self) -> str:
        """Return the URL of the backend DynamoDBLocal server to forward requests to"""
        return f"http://{LOCALHOST}:{server.get_server().port}"

    def on_before_start(self):
        start_dynamodb()
        wait_for_dynamodb()

    def handle_shell_ui_redirect(self, request: werkzeug.Request) -> Response:
        headers = {"Refresh": f"0; url={config.service_url('dynamodb')}/shell/index.html"}
        return Response("", headers=headers)

    def handle_shell_ui_request(self, request: werkzeug.Request, req_path: str) -> Response:
        # TODO: "DynamoDB Local Web Shell was deprecated with version 1.16.X and is not available any
        #  longer from 1.17.X to latest. There are no immediate plans for a new Web Shell to be introduced."
        #  -> keeping this for now, to allow configuring custom installs; should consider removing it in the future
        # https://repost.aws/questions/QUHyIzoEDqQ3iOKlUEp1LPWQ#ANdBm9Nz9TRf6VqR3jZtcA1g
        req_path = f"/{req_path}" if not req_path.startswith("/") else req_path
        url = f"{self.get_forward_url()}/shell{req_path}"
        result = requests.request(
            method=request.method, url=url, headers=request.headers, data=request.data
        )
        return Response(result.content, headers=dict(result.headers), status=result.status_code)

    @handler("CreateTable", expand=False)
    def create_table(
        self,
        context: RequestContext,
        create_table_input: CreateTableInput,
    ) -> CreateTableOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        table_name = create_table_input["TableName"]
        if self.table_exists(table_name):
            raise ResourceInUseException("Cannot create preexisting table")
        billing_mode = create_table_input.get("BillingMode")
        provisioned_throughput = create_table_input.get("ProvisionedThroughput")
        if billing_mode == BillingMode.PAY_PER_REQUEST and provisioned_throughput is not None:
            raise ValidationException(
                "One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits can be "
                "specified when BillingMode is PAY_PER_REQUEST"
            )

        # forward request to backend
        result = self.forward_request(context)
        table_description = result["TableDescription"]

        backend = get_store(context)
        backend.table_definitions[table_name] = table_definitions = dict(create_table_input)

        if "TableId" not in table_definitions:
            table_definitions["TableId"] = long_uid()

        if "SSESpecification" in table_definitions:
            sse_specification = table_definitions.pop("SSESpecification")
            table_definitions["SSEDescription"] = SSEUtils.get_sse_description(sse_specification)

        if table_definitions:
            table_content = result.get("Table", {})
            table_content.update(table_definitions)
            table_description.update(table_content)

        if "StreamSpecification" in table_definitions:
            create_dynamodb_stream(table_definitions, table_description.get("LatestStreamLabel"))

        if "TableClass" in table_definitions:
            table_class = table_description.pop("TableClass", None) or table_definitions.pop(
                "TableClass"
            )
            table_description["TableClassSummary"] = {"TableClass": table_class}

        tags = table_definitions.pop("Tags", [])
        if tags:
            table_arn = table_description["TableArn"]
            table_arn = self.fix_table_arn(table_arn)
            get_store(context).TABLE_TAGS[table_arn] = {tag["Key"]: tag["Value"] for tag in tags}

        # remove invalid attributes from result
        table_description.pop("Tags", None)
        table_description.pop("BillingMode", None)

        event_publisher.fire_event(
            event_publisher.EVENT_DYNAMODB_CREATE_TABLE,
            payload={"n": event_publisher.get_hash(table_name)},
        )

        return result

    def delete_table(self, context: RequestContext, table_name: TableName) -> DeleteTableOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        if not self.table_exists(table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")

        # forward request to backend
        result = self.forward_request(context)

        event_publisher.fire_event(
            event_publisher.EVENT_DYNAMODB_DELETE_TABLE,
            payload={"n": event_publisher.get_hash(table_name)},
        )
        table_arn = result.get("TableDescription", {}).get("TableArn")
        table_arn = self.fix_table_arn(table_arn)
        self.delete_all_event_source_mappings(table_arn)
        dynamodbstreams_api.delete_streams(table_arn)
        get_store(context).TABLE_TAGS.pop(table_arn, None)

        return result

    def describe_table(self, context: RequestContext, table_name: TableName) -> DescribeTableOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        if not self.table_exists(table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")

        # forward request to backend
        result = self.forward_request(context)

        # update response with additional props
        table_props = get_store(context).table_properties.get(table_name)
        if table_props:
            result.get("Table", {}).update(table_props)

        # update only TableId and SSEDescription if present
        table_definitions = get_store(context).table_definitions.get(table_name)
        if table_definitions:
            for key in ["TableId", "SSEDescription"]:
                if table_definitions.get(key):
                    result.get("Table", {})[key] = table_definitions[key]
            if "TableClass" in table_definitions:
                result.get("Table", {})["TableClassSummary"] = {
                    "TableClass": table_definitions["TableClass"]
                }

        return result

    @handler("UpdateTable", expand=False)
    def update_table(
        self, context: RequestContext, update_table_input: UpdateTableInput
    ) -> UpdateTableOutput:
        try:
            # forward request to backend
            result = self.forward_request(context)
        except CommonServiceException as e:
            is_no_update_error = (
                e.code == "ValidationException" and "Nothing to update" in e.message
            )
            if not is_no_update_error or not list(
                {"TableClass", "ReplicaUpdates"} & set(update_table_input.keys())
            ):
                raise

            table_name = update_table_input.get("TableName")

            if update_table_input.get("TableClass"):
                table_definitions = get_store(context).table_definitions.setdefault(table_name, {})
                table_definitions["TableClass"] = update_table_input.get("TableClass")

            if update_table_input.get("ReplicaUpdates"):
                # update local table props (replicas)
                table_properties = get_store(context).table_properties
                table_properties[table_name] = table_props = table_properties.get(table_name) or {}
                table_props["Replicas"] = replicas = table_props.get("Replicas") or []
                for repl_update in update_table_input["ReplicaUpdates"]:
                    for key, details in repl_update.items():
                        region = details.get("RegionName")
                        if key == "Create":
                            details["ReplicaStatus"] = details.get("ReplicaStatus") or "ACTIVE"
                            replicas.append(details)
                        if key == "Update":
                            replica = [r for r in replicas if r.get("RegionName") == region]
                            if replica:
                                replica[0].update(details)
                        if key == "Delete":
                            table_props["Replicas"] = [
                                r for r in replicas if r.get("RegionName") != region
                            ]

            # update response content
            schema = SchemaExtractor.get_table_schema(table_name)
            return UpdateTableOutput(TableDescription=schema["Table"])

        if "StreamSpecification" in update_table_input:
            create_dynamodb_stream(
                update_table_input, result["TableDescription"].get("LatestStreamLabel")
            )

        return result

    def list_tables(
        self,
        context: RequestContext,
        exclusive_start_table_name: TableName = None,
        limit: ListTablesInputLimit = None,
    ) -> ListTablesOutput:
        return self.forward_request(context)

    @handler("PutItem", expand=False)
    def put_item(self, context: RequestContext, put_item_input: PutItemInput) -> PutItemOutput:
        existing_item = None
        table_name = put_item_input["TableName"]
        event_sources_or_streams_enabled = has_event_sources_or_streams_enabled(table_name)
        if event_sources_or_streams_enabled:
            existing_item = ItemFinder.find_existing_item(put_item_input)

        # forward request to backend
        result = self.forward_request(context, put_item_input)

        # Get stream specifications details for the table
        if event_sources_or_streams_enabled:
            stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
            item = put_item_input["Item"]
            # prepare record keys
            keys = SchemaExtractor.extract_keys(item=item, table_name=table_name)
            # create record
            record = self.get_record_template()
            record["eventName"] = "INSERT" if not existing_item else "MODIFY"
            record["dynamodb"].update(
                {
                    "Keys": keys,
                    "NewImage": item,
                    "SizeBytes": _get_size_bytes(item),
                }
            )
            if stream_spec:
                record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
            if existing_item:
                record["dynamodb"]["OldImage"] = existing_item
            self.forward_stream_records([record], table_name=table_name)
        return result

    @handler("DeleteItem", expand=False)
    def delete_item(
        self,
        context: RequestContext,
        delete_item_input: DeleteItemInput,
    ) -> DeleteItemOutput:
        existing_item = None
        table_name = delete_item_input["TableName"]
        if has_event_sources_or_streams_enabled(table_name):
            existing_item = ItemFinder.find_existing_item(delete_item_input)

        # forward request to backend
        result = self.forward_request(context, delete_item_input)

        # determine and forward stream record
        if existing_item:
            event_sources_or_streams_enabled = has_event_sources_or_streams_enabled(table_name)
            if event_sources_or_streams_enabled:
                # create record
                record = self.get_record_template()
                record["eventName"] = "REMOVE"
                record["dynamodb"].update(
                    {
                        "Keys": delete_item_input["Key"],
                        "OldImage": existing_item,
                        "SizeBytes": _get_size_bytes(existing_item),
                    }
                )
                # Get stream specifications details for the table
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                self.forward_stream_records([record], table_name=table_name)

        return result

    @handler("UpdateItem", expand=False)
    def update_item(
        self,
        context: RequestContext,
        update_item_input: UpdateItemInput,
    ) -> UpdateItemOutput:
        existing_item = None
        table_name = update_item_input["TableName"]
        event_sources_or_streams_enabled = has_event_sources_or_streams_enabled(table_name)
        if event_sources_or_streams_enabled:
            existing_item = ItemFinder.find_existing_item(update_item_input)

        # forward request to backend
        result = self.forward_request(context, update_item_input)

        # construct and forward stream record
        if event_sources_or_streams_enabled:
            updated_item = ItemFinder.find_existing_item(update_item_input)
            if updated_item:
                record = self.get_record_template()
                record["eventName"] = "INSERT" if not existing_item else "MODIFY"
                record["dynamodb"].update(
                    {
                        "Keys": update_item_input["Key"],
                        "NewImage": updated_item,
                        "SizeBytes": _get_size_bytes(updated_item),
                    }
                )
                if existing_item:
                    record["dynamodb"]["OldImage"] = existing_item
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                self.forward_stream_records([record], table_name=table_name)
        return result

    @handler("GetItem", expand=False)
    def get_item(self, context: RequestContext, get_item_input: GetItemInput) -> GetItemOutput:
        result = self.forward_request(context)
        self.fix_consumed_capacity(get_item_input, result)
        return result

    @handler("Query", expand=False)
    def query(self, context: RequestContext, query_input: QueryInput) -> QueryOutput:
        index_name = query_input.get("IndexName")
        if index_name:
            if not is_index_query_valid(query_input):
                raise ValidationException(
                    "One or more parameter values were invalid: Select type ALL_ATTRIBUTES "
                    "is not supported for global secondary index id-index because its projection "
                    "type is not ALL",
                )

        result = self.forward_request(context)
        self.fix_consumed_capacity(query_input, result)
        return result

    @handler("Scan", expand=False)
    def scan(self, context: RequestContext, scan_input: ScanInput) -> ScanOutput:
        return self.forward_request(context)

    @handler("BatchWriteItem", expand=False)
    def batch_write_item(
        self,
        context: RequestContext,
        batch_write_item_input: BatchWriteItemInput,
    ) -> BatchWriteItemOutput:
        existing_items = []
        unprocessed_put_items = []
        unprocessed_delete_items = []
        request_items = batch_write_item_input["RequestItems"]
        for table_name in sorted(request_items.keys()):
            for request in request_items[table_name]:
                for key in ["PutRequest", "DeleteRequest"]:
                    inner_request = request.get(key)
                    if inner_request:
                        if self.should_throttle("BatchWriteItem"):
                            if key == "PutRequest":
                                unprocessed_put_items.append(inner_request)
                            elif key == "DeleteRequest":
                                unprocessed_delete_items.append(inner_request)
                        else:
                            item = ItemFinder.find_existing_item(inner_request, table_name)
                            existing_items.append(item)

        # forward request to backend
        result = self.forward_request(context)

        # determine and forward stream records
        request_items = batch_write_item_input["RequestItems"]
        records, unprocessed_items = self.prepare_batch_write_item_records(
            request_items=request_items,
            unprocessed_put_items=unprocessed_put_items,
            unprocessed_delete_items=unprocessed_delete_items,
            existing_items=existing_items,
        )
        streams_enabled_cache = {}
        event_sources_or_streams_enabled = False
        for record in records:
            event_sources_or_streams_enabled = (
                event_sources_or_streams_enabled
                or has_event_sources_or_streams_enabled(
                    record["eventSourceARN"], cache=streams_enabled_cache
                )
            )
        if event_sources_or_streams_enabled:
            self.forward_stream_records(records)

        # update response
        if any(unprocessed_items):
            table_name = list(request_items.keys())[0]
            unprocessed = result["UnprocessedItems"]
            if table_name not in unprocessed:
                unprocessed[table_name] = []
            for key in ["PutRequest", "DeleteRequest"]:
                if any(unprocessed_items[key]):
                    unprocessed_items[table_name].append({key: unprocessed_items[key]})
            for key in list(unprocessed.keys()):
                if not unprocessed.get(key):
                    del unprocessed[key]

        return result

    @handler("BatchGetItem")
    def batch_get_item(
        self,
        context: RequestContext,
        request_items: BatchGetRequestMap,
        return_consumed_capacity: ReturnConsumedCapacity = None,
    ) -> BatchGetItemOutput:
        return self.forward_request(context)

    @handler("TransactWriteItems", expand=False)
    def transact_write_items(
        self,
        context: RequestContext,
        transact_write_items_input: TransactWriteItemsInput,
    ) -> TransactWriteItemsOutput:
        existing_items = []
        for item in transact_write_items_input["TransactItems"]:
            for key in ["Put", "Update", "Delete"]:
                inner_item = item.get(key)
                if inner_item:
                    existing_items.append(ItemFinder.find_existing_item(inner_item))

        client_token: str | None = transact_write_items_input.get("ClientRequestToken")

        if client_token:
            # we sort the payload since identical payload but with different order could cause
            # IdempotentParameterMismatchException error if a client token is provided
            context.request.data = to_bytes(canonical_json(json.loads(context.request.data)))

        # forward request to backend
        result = self.forward_request(context)

        # determine and forward stream records
        streams_enabled_cache = {}
        records = self.prepare_transact_write_item_records(
            transact_items=transact_write_items_input["TransactItems"],
            existing_items=existing_items,
        )
        event_sources_or_streams_enabled = False
        for record in records:
            event_sources_or_streams_enabled = (
                event_sources_or_streams_enabled
                or has_event_sources_or_streams_enabled(
                    record["eventSourceARN"],
                    streams_enabled_cache,
                )
            )
        if event_sources_or_streams_enabled:
            self.forward_stream_records(records)

        return result

    @handler("TransactGetItems", expand=False)
    def transact_get_items(
        self,
        context: RequestContext,
        transact_items: TransactGetItemList,
        return_consumed_capacity: ReturnConsumedCapacity = None,
    ) -> TransactGetItemsOutput:
        return self.forward_request(context)

    @handler("ExecuteTransaction", expand=False)
    def execute_transaction(
        self, context: RequestContext, execute_transaction_input: ExecuteTransactionInput
    ) -> ExecuteTransactionOutput:
        result = self.forward_request(context)
        return result

    @handler("ExecuteStatement", expand=False)
    def execute_statement(
        self,
        context: RequestContext,
        execute_statement_input: ExecuteStatementInput,
    ) -> ExecuteStatementOutput:
        statement = execute_statement_input["Statement"]
        table_name = extract_table_name_from_partiql_update(statement)
        existing_items = None
        if table_name and has_event_sources_or_streams_enabled(table_name):
            # Note: fetching the entire list of items is hugely inefficient, especially for larger tables
            # TODO: find a mechanism to hook into the PartiQL update mechanism of DynamoDB Local directly!
            existing_items = ItemFinder.list_existing_items_for_statement(statement)

        # forward request to backend
        result = self.forward_request(context)

        # construct and forward stream record
        event_sources_or_streams_enabled = table_name and has_event_sources_or_streams_enabled(
            table_name
        )
        if event_sources_or_streams_enabled:
            records = get_updated_records(table_name, existing_items)
            self.forward_stream_records(records, table_name=table_name)

        return result

    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArnString, tags: TagList
    ) -> None:
        table_tags = get_store(context).TABLE_TAGS
        if resource_arn not in table_tags:
            table_tags[resource_arn] = {}
        table_tags[resource_arn].update({tag["Key"]: tag["Value"] for tag in tags})

    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArnString, tag_keys: TagKeyList
    ) -> None:
        for tag_key in tag_keys or []:
            get_store(context).TABLE_TAGS.get(resource_arn, {}).pop(tag_key, None)

    def list_tags_of_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        next_token: NextTokenString = None,
    ) -> ListTagsOfResourceOutput:
        result = [
            {"Key": k, "Value": v}
            for k, v in get_store(context).TABLE_TAGS.get(resource_arn, {}).items()
        ]
        return ListTagsOfResourceOutput(Tags=result)

    def describe_time_to_live(
        self, context: RequestContext, table_name: TableName
    ) -> DescribeTimeToLiveOutput:
        backend = get_store(context)

        ttl_spec = backend.ttl_specifications.get(table_name)
        result = {"TimeToLiveStatus": "DISABLED"}
        if ttl_spec:
            if ttl_spec.get("Enabled"):
                ttl_status = "ENABLED"
            else:
                ttl_status = "DISABLED"
            result = {
                "AttributeName": ttl_spec.get("AttributeName"),
                "TimeToLiveStatus": ttl_status,
            }

        return DescribeTimeToLiveOutput(TimeToLiveDescription=result)

    def update_time_to_live(
        self,
        context: RequestContext,
        table_name: TableName,
        time_to_live_specification: TimeToLiveSpecification,
    ) -> UpdateTimeToLiveOutput:
        # TODO: TTL status is maintained/mocked but no real expiry is happening for items
        backend = get_store(context)
        backend.ttl_specifications[table_name] = time_to_live_specification
        return UpdateTimeToLiveOutput(TimeToLiveSpecification=time_to_live_specification)

    def create_global_table(
        self, context: RequestContext, global_table_name: TableName, replication_group: ReplicaList
    ) -> CreateGlobalTableOutput:
        global_tables: Dict = get_store(context).GLOBAL_TABLES
        if global_table_name in global_tables:
            raise GlobalTableAlreadyExistsException("Global table with this name already exists")
        replication_group = [grp.copy() for grp in replication_group or []]
        data = {"GlobalTableName": global_table_name, "ReplicationGroup": replication_group}
        global_tables[global_table_name] = data
        for group in replication_group:
            group["ReplicaStatus"] = "ACTIVE"
            group["ReplicaStatusDescription"] = "Replica active"
        return CreateGlobalTableOutput(GlobalTableDescription=data)

    def describe_global_table(
        self, context: RequestContext, global_table_name: TableName
    ) -> DescribeGlobalTableOutput:
        details = get_store(context).GLOBAL_TABLES.get(global_table_name)
        if not details:
            raise GlobalTableNotFoundException("Global table with this name does not exist")
        return DescribeGlobalTableOutput(GlobalTableDescription=details)

    def list_global_tables(
        self,
        context: RequestContext,
        exclusive_start_global_table_name: TableName = None,
        limit: PositiveIntegerObject = None,
        region_name: RegionName = None,
    ) -> ListGlobalTablesOutput:
        # TODO: add paging support
        result = [
            select_attributes(tab, ["GlobalTableName", "ReplicationGroup"])
            for tab in get_store(context).GLOBAL_TABLES.values()
        ]
        return ListGlobalTablesOutput(GlobalTables=result)

    def update_global_table(
        self,
        context: RequestContext,
        global_table_name: TableName,
        replica_updates: ReplicaUpdateList,
    ) -> UpdateGlobalTableOutput:
        details = get_store(context).GLOBAL_TABLES.get(global_table_name)
        if not details:
            raise GlobalTableNotFoundException("Global table with this name does not exist")
        for update in replica_updates or []:
            repl_group = details["ReplicationGroup"]
            # delete existing
            delete = update.get("Delete")
            if delete:
                details["ReplicationGroup"] = [
                    g for g in repl_group if g["RegionName"] != delete["RegionName"]
                ]
            # create new
            create = update.get("Create")
            if create:
                exists = [g for g in repl_group if g["RegionName"] == create["RegionName"]]
                if exists:
                    continue
                new_group = {
                    "RegionName": create["RegionName"],
                    "ReplicaStatus": "ACTIVE",
                    "ReplicaStatusDescription": "Replica active",
                }
                details["ReplicationGroup"].append(new_group)
        return UpdateGlobalTableOutput(GlobalTableDescription=details)

    def enable_kinesis_streaming_destination(
        self, context: RequestContext, table_name: TableName, stream_arn: StreamArn
    ) -> KinesisStreamingDestinationOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        if not self.table_exists(table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")
        stream = EventForwarder.is_kinesis_stream_exists(stream_arn=stream_arn)
        if not stream:
            raise ValidationException("User does not have a permission to use kinesis stream")

        table_def = get_store(context).table_definitions.setdefault(table_name, {})

        dest_status = table_def.get("KinesisDataStreamDestinationStatus")
        if dest_status not in ["DISABLED", "ENABLE_FAILED", None]:
            raise ValidationException(
                "Table is not in a valid state to enable Kinesis Streaming "
                "Destination:EnableKinesisStreamingDestination must be DISABLED or ENABLE_FAILED "
                "to perform ENABLE operation."
            )

        table_def["KinesisDataStreamDestinations"] = (
            table_def.get("KinesisDataStreamDestinations") or []
        )
        # remove the stream destination if already present
        table_def["KinesisDataStreamDestinations"] = [
            t for t in table_def["KinesisDataStreamDestinations"] if t["StreamArn"] != stream_arn
        ]
        # append the active stream destination at the end of the list
        table_def["KinesisDataStreamDestinations"].append(
            {
                "DestinationStatus": "ACTIVE",
                "DestinationStatusDescription": "Stream is active",
                "StreamArn": stream_arn,
            }
        )
        table_def["KinesisDataStreamDestinationStatus"] = "ACTIVE"
        return KinesisStreamingDestinationOutput(
            DestinationStatus="ACTIVE", StreamArn=stream_arn, TableName=table_name
        )

    def disable_kinesis_streaming_destination(
        self, context: RequestContext, table_name: TableName, stream_arn: StreamArn
    ) -> KinesisStreamingDestinationOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        if not self.table_exists(table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")
        stream = EventForwarder.is_kinesis_stream_exists(stream_arn=stream_arn)
        if not stream:
            raise ValidationException(
                "User does not have a permission to use kinesis stream",
            )

        table_def = get_store(context).table_definitions.setdefault(table_name, {})

        stream_destinations = table_def.get("KinesisDataStreamDestinations")
        if stream_destinations:
            if table_def["KinesisDataStreamDestinationStatus"] == "ACTIVE":
                for dest in stream_destinations:
                    if dest["StreamArn"] == stream_arn and dest["DestinationStatus"] == "ACTIVE":
                        dest["DestinationStatus"] = "DISABLED"
                        dest["DestinationStatusDescription"] = ("Stream is disabled",)
                        table_def["KinesisDataStreamDestinationStatus"] = "DISABLED"
                        return KinesisStreamingDestinationOutput(
                            DestinationStatus="DISABLED",
                            StreamArn=stream_arn,
                            TableName=table_name,
                        )
        raise ValidationException(
            "Table is not in a valid state to disable Kinesis Streaming Destination:"
            "DisableKinesisStreamingDestination must be ACTIVE to perform DISABLE operation."
        )

    def describe_kinesis_streaming_destination(
        self, context: RequestContext, table_name: TableName
    ) -> DescribeKinesisStreamingDestinationOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        if not self.table_exists(table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")

        table_def = get_store(context).table_definitions.get(table_name) or {}

        stream_destinations = table_def.get("KinesisDataStreamDestinations") or []
        return DescribeKinesisStreamingDestinationOutput(
            KinesisDataStreamDestinations=stream_destinations, TableName=table_name
        )

    @staticmethod
    def table_exists(table_name):
        return aws_stack.dynamodb_table_exists(table_name)

    @staticmethod
    def prepare_request_headers(headers):
        def _replace(regex, replace):
            headers["Authorization"] = re.sub(
                regex, replace, headers.get("Authorization") or "", flags=re.IGNORECASE
            )

        # Note: We need to ensure that the same access key is used here for all requests,
        # otherwise DynamoDBLocal stores tables/items in separate namespaces
        _replace(r"Credential=[^/]+/", rf"Credential={constants.INTERNAL_AWS_ACCESS_KEY_ID}/")
        # Note: The NoSQL Workbench sends "localhost" or "local" as the region name, which we need to fix here
        _replace(
            r"Credential=([^/]+/[^/]+)/local(host)?/",
            rf"Credential=\1/{aws_stack.get_local_region()}/",
        )

    def fix_consumed_capacity(self, request: Dict, result: Dict):
        # make sure we append 'ConsumedCapacity', which is properly
        # returned by dynalite, but not by AWS's DynamoDBLocal
        table_name = request.get("TableName")
        return_cap = request.get("ReturnConsumedCapacity")
        if "ConsumedCapacity" not in result and return_cap in ["TOTAL", "INDEXES"]:
            request["ConsumedCapacity"] = {
                "TableName": table_name,
                "CapacityUnits": 5,  # TODO hardcoded
                "ReadCapacityUnits": 2,
                "WriteCapacityUnits": 3,
            }

    def fix_table_arn(self, table_arn: str) -> str:
        return re.sub(
            "arn:aws:dynamodb:ddblocal:",
            f"arn:aws:dynamodb:{aws_stack.get_region()}:",
            table_arn,
        )

    def prepare_transact_write_item_records(self, transact_items, existing_items):
        records = []
        record = self.get_record_template()
        # Fix issue #2745: existing_items only contain the Put/Update/Delete records,
        # so we will increase the index based on these events
        i = 0
        for request in transact_items:
            put_request = request.get("Put")
            if put_request:
                existing_item = existing_items[i]
                table_name = put_request["TableName"]
                keys = SchemaExtractor.extract_keys(item=put_request["Item"], table_name=table_name)
                # Add stream view type to record if ddb stream is enabled
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = copy.deepcopy(record)
                new_record["eventID"] = short_uid()
                new_record["eventName"] = "INSERT" if not existing_item else "MODIFY"
                new_record["dynamodb"]["Keys"] = keys
                new_record["dynamodb"]["NewImage"] = put_request["Item"]
                if existing_item:
                    new_record["dynamodb"]["OldImage"] = existing_item
                new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                new_record["dynamodb"]["SizeBytes"] = _get_size_bytes(put_request["Item"])
                records.append(new_record)
                i += 1
            update_request = request.get("Update")
            if update_request:
                table_name = update_request["TableName"]
                keys = update_request["Key"]
                updated_item = ItemFinder.find_existing_item(update_request, table_name)
                if not updated_item:
                    return []
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = copy.deepcopy(record)
                new_record["eventID"] = short_uid()
                new_record["eventName"] = "MODIFY"
                new_record["dynamodb"]["Keys"] = keys
                new_record["dynamodb"]["OldImage"] = existing_items[i]
                new_record["dynamodb"]["NewImage"] = updated_item
                new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                new_record["dynamodb"]["SizeBytes"] = _get_size_bytes(updated_item)
                records.append(new_record)
                i += 1
            delete_request = request.get("Delete")
            if delete_request:
                table_name = delete_request["TableName"]
                keys = delete_request["Key"]
                existing_item = existing_items[i]
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = copy.deepcopy(record)
                new_record["eventID"] = short_uid()
                new_record["eventName"] = "REMOVE"
                new_record["dynamodb"]["Keys"] = keys
                new_record["dynamodb"]["OldImage"] = existing_item
                new_record["dynamodb"]["SizeBytes"] = _get_size_bytes(existing_items)
                new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                records.append(new_record)
                i += 1
        return records

    def batch_execute_statement(
        self,
        context: RequestContext,
        statements: PartiQLBatchRequest,
        return_consumed_capacity: ReturnConsumedCapacity = None,
    ) -> BatchExecuteStatementOutput:
        result = self.forward_request(context)
        return result

    def prepare_batch_write_item_records(
        self,
        request_items,
        existing_items,
        unprocessed_put_items: List,
        unprocessed_delete_items: List,
    ):
        records = []
        record = self.get_record_template()
        unprocessed_items = {"PutRequest": {}, "DeleteRequest": {}}
        i = 0
        for table_name in sorted(request_items.keys()):
            # Add stream view type to record if ddb stream is enabled
            stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
            if stream_spec:
                record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
            for request in request_items[table_name]:
                put_request = request.get("PutRequest")
                if put_request:
                    if existing_items and len(existing_items) > i:
                        existing_item = existing_items[i]
                        keys = SchemaExtractor.extract_keys(
                            item=put_request["Item"], table_name=table_name
                        )
                        new_record = copy.deepcopy(record)
                        new_record["eventID"] = short_uid()
                        new_record["dynamodb"]["SizeBytes"] = _get_size_bytes(put_request["Item"])
                        new_record["eventName"] = "INSERT" if not existing_item else "MODIFY"
                        new_record["dynamodb"]["Keys"] = keys
                        new_record["dynamodb"]["NewImage"] = put_request["Item"]
                        if existing_item:
                            new_record["dynamodb"]["OldImage"] = existing_item
                        new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                        records.append(new_record)
                    if unprocessed_put_items and len(unprocessed_put_items) > i:
                        unprocessed_item = unprocessed_put_items[i]
                        if unprocessed_item:
                            unprocessed_items["PutRequest"].update(
                                json.loads(json.dumps(unprocessed_item, cls=BytesEncoder))
                            )
                delete_request = request.get("DeleteRequest")
                if delete_request:
                    if existing_items and len(existing_items) > i:
                        keys = delete_request["Key"]
                        new_record = copy.deepcopy(record)
                        new_record["eventID"] = short_uid()
                        new_record["eventName"] = "REMOVE"
                        new_record["dynamodb"]["Keys"] = keys
                        new_record["dynamodb"]["OldImage"] = existing_items[i]
                        new_record["dynamodb"]["SizeBytes"] = _get_size_bytes(existing_items[i])
                        new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                        records.append(new_record)
                    if unprocessed_delete_items and len(unprocessed_delete_items) > i:
                        unprocessed_item = unprocessed_delete_items[i]
                        if unprocessed_item:
                            unprocessed_items["DeleteRequest"].update(
                                json.loads(json.dumps(unprocessed_item, cls=BytesEncoder))
                            )
                i += 1
        return records, unprocessed_items

    def forward_stream_records(self, records: List[Dict], table_name: str = None):
        if records and "eventName" in records[0]:
            if table_name:
                for record in records:
                    record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
            EventForwarder.forward_to_targets(records, background=True)

    def delete_all_event_source_mappings(self, table_arn):
        if table_arn:

            lambda_client = aws_stack.connect_to_service("lambda")
            result = lambda_client.list_event_source_mappings(EventSourceArn=table_arn)
            for event in result["EventSourceMappings"]:
                event_source_mapping_id = event["UUID"]
                lambda_client.delete_event_source_mapping(UUID=event_source_mapping_id)

    def get_record_template(self) -> Dict:
        return {
            "eventID": short_uid(),
            "eventVersion": "1.1",
            "dynamodb": {
                # expects nearest second rounded down
                "ApproximateCreationDateTime": int(time.time()),
                # 'StreamViewType': 'NEW_AND_OLD_IMAGES',
                "SizeBytes": -1,
            },
            "awsRegion": aws_stack.get_region(),
            "eventSource": "aws:dynamodb",
        }

    def check_provisioned_throughput(self, action):
        if self.should_throttle(action):
            message = (
                "The level of configured provisioned throughput for the table was exceeded. "
                + "Consider increasing your provisioning level with the UpdateTable API"
            )
            raise ProvisionedThroughputExceededException(message)

    def action_should_throttle(self, action, actions):
        throttled = [f"{ACTION_PREFIX}{a}" for a in actions]
        return (action in throttled) or (action in actions)

    def should_throttle(self, action):
        rand = random.random()
        if rand < config.DYNAMODB_READ_ERROR_PROBABILITY and self.action_should_throttle(
            action, READ_THROTTLED_ACTIONS
        ):
            return True
        elif rand < config.DYNAMODB_WRITE_ERROR_PROBABILITY and self.action_should_throttle(
            action, WRITE_THROTTLED_ACTIONS
        ):
            return True
        elif rand < config.DYNAMODB_ERROR_PROBABILITY and self.action_should_throttle(
            action, THROTTLED_ACTIONS
        ):
            return True
        return False


# ---
# Misc. util functions
# ---
def _get_size_bytes(item) -> int:
    try:
        size_bytes = len(json.dumps(item))
    except TypeError:
        size_bytes = len(str(item))
    return size_bytes


def get_global_secondary_index(table_name, index_name):
    schema = SchemaExtractor.get_table_schema(table_name)
    for index in schema["Table"].get("GlobalSecondaryIndexes", []):
        if index["IndexName"] == index_name:
            return index
    raise ResourceNotFoundException("Index not found")


def is_local_secondary_index(table_name, index_name) -> bool:
    schema = SchemaExtractor.get_table_schema(table_name)
    for index in schema["Table"].get("LocalSecondaryIndexes", []):
        if index["IndexName"] == index_name:
            return True
    return False


def is_index_query_valid(query_data: dict) -> bool:
    table_name = to_str(query_data["TableName"])
    index_name = to_str(query_data["IndexName"])
    if is_local_secondary_index(table_name, index_name):
        return True
    index_query_type = query_data.get("Select")
    index = get_global_secondary_index(table_name, index_name)
    index_projection_type = index.get("Projection").get("ProjectionType")
    if index_query_type == "ALL_ATTRIBUTES" and index_projection_type != "ALL":
        return False
    return True


def has_event_sources_or_streams_enabled(table_name: str, cache: Dict = None):
    if cache is None:
        cache = {}
    if not table_name:
        return
    table_arn = aws_stack.dynamodb_table_arn(table_name)
    cached = cache.get(table_arn)
    if isinstance(cached, bool):
        return cached
    sources = lambda_api.get_event_sources(source_arn=table_arn)
    result = False
    if sources:
        result = True
    if not result and dynamodbstreams_api.get_stream_for_table(table_arn):
        result = True

    # if kinesis streaming destination is enabled
    # get table name from table_arn
    # since batch_write and transact write operations passing table_arn instead of table_name
    table_name = table_arn.split("/", 1)[-1]
    table_definitions: Dict = get_store().table_definitions
    if not result and table_definitions.get(table_name):
        if table_definitions[table_name].get("KinesisDataStreamDestinationStatus") == "ACTIVE":
            result = True
    cache[table_arn] = result
    return result


def get_updated_records(table_name: str, existing_items: List) -> List:
    """
    Determine the list of record updates, to be sent to a DDB stream after a PartiQL update operation.

    Note: This is currently a fairly expensive operation, as we need to retrieve the list of all items
          from the table, and compare the items to the previously available. This is a limitation as
          we're currently using the DynamoDB Local backend as a blackbox. In future, we should consider hooking
          into the PartiQL query execution inside DynamoDB Local and directly extract the list of updated items.
    """
    result = []
    stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)

    key_schema = SchemaExtractor.get_key_schema(table_name)
    before = ItemSet(existing_items, key_schema=key_schema)
    after = ItemSet(ItemFinder.get_all_table_items(table_name), key_schema=key_schema)

    def _add_record(item, comparison_set: ItemSet):
        matching_item = comparison_set.find_item(item)
        if matching_item == item:
            return

        # determine event type
        if comparison_set == after:
            if matching_item:
                return
            event_name = "REMOVE"
        else:
            event_name = "INSERT" if not matching_item else "MODIFY"

        old_image = item if event_name == "REMOVE" else matching_item
        new_image = matching_item if event_name == "REMOVE" else item

        # prepare record
        keys = SchemaExtractor.extract_keys_for_schema(item=item, key_schema=key_schema)
        record = {
            "eventName": event_name,
            "eventID": short_uid(),
            "dynamodb": {
                "Keys": keys,
                "NewImage": new_image,
                "SizeBytes": _get_size_bytes(item),
            },
        }
        if stream_spec:
            record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
        if old_image:
            record["dynamodb"]["OldImage"] = old_image
        result.append(record)

    # loop over items in new item list (find INSERT/MODIFY events)
    for item in after.items_list:
        _add_record(item, before)
    # loop over items in old item list (find REMOVE events)
    for item in before.items_list:
        _add_record(item, after)
    return result


def fix_headers_for_updated_response(response):
    response.headers["Content-Length"] = len(to_bytes(response.content))
    response.headers["x-amz-crc32"] = calculate_crc32(response)


def create_dynamodb_stream(data, latest_stream_label):
    stream = data["StreamSpecification"]
    enabled = stream.get("StreamEnabled")

    if enabled not in [False, "False"]:
        table_name = data["TableName"]
        view_type = stream["StreamViewType"]

        dynamodbstreams_api.add_dynamodb_stream(
            table_name=table_name,
            latest_stream_label=latest_stream_label,
            view_type=view_type,
            enabled=enabled,
        )


def dynamodb_get_table_stream_specification(table_name):
    try:
        table_schema = SchemaExtractor.get_table_schema(table_name)
        return table_schema["Table"].get("StreamSpecification")
    except Exception as e:
        LOG.info(
            "Unable to get stream specification for table %s: %s %s",
            table_name,
            e,
            traceback.format_exc(),
        )
        raise e
