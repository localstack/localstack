import copy
import json
import logging
import random
import re
import time
import traceback
from binascii import crc32
from contextlib import contextmanager
from typing import Dict, List

import requests
import werkzeug

from localstack import config
from localstack.aws import handlers
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
    ReplicaDescription,
    ReplicaList,
    ReplicaStatus,
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
from localstack.aws.forwarder import get_request_forwarder_http
from localstack.constants import AUTH_CREDENTIAL_REGEX, LOCALHOST, TEST_AWS_SECRET_ACCESS_KEY
from localstack.http import Response
from localstack.services.dynamodb import server
from localstack.services.dynamodb.models import DynamoDBStore, dynamodb_stores
from localstack.services.dynamodb.server import start_dynamodb, wait_for_dynamodb
from localstack.services.dynamodb.utils import (
    ItemFinder,
    ItemSet,
    SchemaExtractor,
    extract_table_name_from_partiql_update,
)
from localstack.services.dynamodbstreams import dynamodbstreams_api
from localstack.services.dynamodbstreams.dynamodbstreams_api import (
    get_and_increment_sequence_number_counter,
)
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import arns, aws_stack
from localstack.utils.aws.arns import extract_account_id_from_arn, extract_region_from_arn
from localstack.utils.aws.aws_stack import get_valid_regions_for_service
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


def dynamodb_table_exists(table_name, client=None):
    client = client or aws_stack.connect_to_service("dynamodb")
    paginator = client.get_paginator("list_tables")
    pages = paginator.paginate(PaginationConfig={"PageSize": 100})
    for page in pages:
        table_names = page["TableNames"]
        if to_str(table_name) in table_names:
            return True
    return False


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
        for record in records:
            event_source_arn = record.get("eventSourceARN")
            if not event_source_arn:
                continue
            table_name = event_source_arn.split("/", 1)[-1]
            account_id = extract_account_id_from_arn(event_source_arn)
            region_name = extract_region_from_arn(event_source_arn)
            store = get_store(account_id, region_name)
            table_def = store.table_definitions.get(table_name) or {}
            if table_def.get("KinesisDataStreamDestinationStatus") != "ACTIVE":
                continue
            stream_arn = table_def["KinesisDataStreamDestinations"][-1]["StreamArn"]
            stream_name = stream_arn.split("/", 1)[-1]
            record["tableName"] = table_name
            record.pop("eventSourceARN", None)
            record["dynamodb"].pop("StreamViewType", None)
            hash_keys = list(filter(lambda key: key["KeyType"] == "HASH", table_def["KeySchema"]))
            partition_key = hash_keys[0]["AttributeName"]

            stream_account_id = extract_account_id_from_arn(stream_arn)
            stream_region_name = extract_region_from_arn(stream_arn)
            kinesis = aws_stack.connect_to_service(
                "kinesis",
                aws_access_key_id=stream_account_id,
                aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
                region_name=stream_region_name,
            )
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
        account_id = extract_account_id_from_arn(stream_arn)
        region_name = extract_region_from_arn(stream_arn)

        kinesis = aws_stack.connect_to_service(
            "kinesis",
            aws_access_key_id=account_id,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            region_name=region_name,
        )
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
    def get_sse_kms_managed_key(cls, account_id: str, region_name: str):
        from localstack.services.kms import provider

        existing_key = MANAGED_KMS_KEYS.get(region_name)
        if existing_key:
            return existing_key
        kms_client = aws_stack.connect_to_service(
            "kms",
            aws_access_key_id=account_id,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            region_name=region_name,
        )
        key_data = kms_client.create_key(
            Description="Default key that protects my DynamoDB data when no other key is defined"
        )
        key_id = key_data["KeyMetadata"]["KeyId"]

        provider.set_key_managed(key_id, account_id, region_name)
        MANAGED_KMS_KEYS[aws_stack.get_region()] = key_id
        return key_id

    @classmethod
    def get_sse_description(cls, account_id: str, region_name: str, data):
        if data.get("Enabled"):
            kms_master_key_id = data.get("KMSMasterKeyId")
            if not kms_master_key_id:
                # this is of course not the actual key for dynamodb, just a better, since existing, mock
                kms_master_key_id = cls.get_sse_kms_managed_key(account_id, region_name)
            kms_master_key_id = arns.kms_key_arn(kms_master_key_id)
            return {
                "Status": "ENABLED",
                "SSEType": "KMS",  # no other value is allowed here
                "KMSMasterKeyArn": kms_master_key_id,
            }
        return {}


class ValidationException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__(code="ValidationException", status_code=400, message=message)


def get_store(account_id: str, region_name: str) -> DynamoDBStore:
    # special case: AWS NoSQL Workbench sends "localhost" as region - replace with proper region here
    region_name = DynamoDBProvider.ddb_region_name(region_name)
    return dynamodb_stores[account_id][region_name]


@contextmanager
def modify_context_region(context: RequestContext, region: str):
    """
    Context manager that modifies the region of a `RequestContext`. At the exit, the context is restored to its
    original state.

    :param context: the context to modify
    :param region: the modified region
    :return: a modified `RequestContext`
    """
    original_region = context.region
    original_authorization = context.request.headers.get("Authorization")

    key = DynamoDBProvider.ddb_access_key(context.account_id, region)

    context.region = region
    context.request.headers["Authorization"] = re.sub(
        AUTH_CREDENTIAL_REGEX,
        rf"Credential={key}/\2/{region}/\4/",
        original_authorization or "",
        flags=re.IGNORECASE,
    )

    yield context

    # revert the original context
    context.region = original_region
    context.request.headers["Authorization"] = original_authorization


class DynamoDBProvider(DynamodbApi, ServiceLifecycleHook):
    def __init__(self):
        self.request_forwarder = get_request_forwarder_http(self.get_forward_url)

    def on_after_init(self):
        # add response processor specific to ddblocal
        handlers.modify_service_response.append(self.service, self._modify_ddblocal_arns)

        # routes for the shell ui
        ROUTER.add(
            path="/shell",
            endpoint=self.handle_shell_ui_redirect,
            methods=["GET"],
        )
        ROUTER.add(
            path="/shell/<regex('.*'):req_path>",
            endpoint=self.handle_shell_ui_request,
        )

    def _modify_ddblocal_arns(self, chain, context: RequestContext, response: Response):
        """A service response handler that modifies the dynamodb backend response."""
        if response_content := response.get_data(as_text=True):
            # fix the table and latest stream ARNs (DynamoDBLocal hardcodes "ddblocal" as the region)
            content_replaced = re.sub(
                r'("TableArn"|"LatestStreamArn"|"StreamArn")\s*:\s*"arn:([a-z-]+):dynamodb:ddblocal:000000000000:([^"]+)"',
                rf'\1: "arn:\2:dynamodb:{context.region}:{context.account_id}:\3"',
                response_content,
            )
            if content_replaced != response_content:
                response.data = content_replaced
                context.service_response = (
                    None  # make sure the service response is parsed again later
                )

        # update x-amz-crc32 header required by some clients
        response.headers["x-amz-crc32"] = crc32(response.data) & 0xFFFFFFFF

    def _forward_request(self, context: RequestContext, region: str | None) -> ServiceResponse:
        """
        Modify the context region and then forward request to DynamoDB Local.

        This is used for operations impacted by global tables. In LocalStack, a single copy of global table
        is kept, and any requests to replicated tables are forwarded to this original table.
        """
        if region:
            with modify_context_region(context, region):
                return self.forward_request(context)
        return self.forward_request(context)

    def forward_request(
        self, context: RequestContext, service_request: ServiceRequest = None
    ) -> ServiceResponse:
        """
        Forward a request to DynamoDB Local.
        """
        self.check_provisioned_throughput(context.operation.name)
        self.prepare_request_headers(
            context.request.headers, account_id=context.account_id, region_name=context.region
        )
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

    #
    # Table ops
    #

    @handler("CreateTable", expand=False)
    def create_table(
        self,
        context: RequestContext,
        create_table_input: CreateTableInput,
    ) -> CreateTableOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        table_name = create_table_input["TableName"]
        if self.table_exists(context.account_id, context.region, table_name):
            raise ResourceInUseException(f"Table already exists: {table_name}")
        billing_mode = create_table_input.get("BillingMode")
        provisioned_throughput = create_table_input.get("ProvisionedThroughput")
        if billing_mode == BillingMode.PAY_PER_REQUEST and provisioned_throughput is not None:
            raise ValidationException(
                "One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits can be "
                "specified when BillingMode is PAY_PER_REQUEST"
            )

        result = self.forward_request(context)

        table_description = result["TableDescription"]
        table_description["TableArn"] = table_arn = self.fix_table_arn(
            table_description["TableArn"]
        )

        backend = get_store(context.account_id, context.region)
        backend.table_definitions[table_name] = table_definitions = dict(create_table_input)

        if "TableId" not in table_definitions:
            table_definitions["TableId"] = long_uid()

        if "SSESpecification" in table_definitions:
            sse_specification = table_definitions.pop("SSESpecification")
            table_definitions["SSEDescription"] = SSEUtils.get_sse_description(
                context.account_id, context.region, sse_specification
            )

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
            get_store(context.account_id, context.region).TABLE_TAGS[table_arn] = {
                tag["Key"]: tag["Value"] for tag in tags
            }

        # remove invalid attributes from result
        table_description.pop("Tags", None)
        table_description.pop("BillingMode", None)

        return result

    def delete_table(self, context: RequestContext, table_name: TableName) -> DeleteTableOutput:
        global_table_region = self.get_global_table_region(context, table_name)

        # Limitation note: On AWS, for a replicated table, if the source table is deleted, the replicated tables continue to exist.
        # This is not the case for LocalStack, where all replicated tables will also be removed if source is deleted.

        result = self._forward_request(context=context, region=global_table_region)

        table_arn = result.get("TableDescription", {}).get("TableArn")
        table_arn = self.fix_table_arn(table_arn)
        dynamodbstreams_api.delete_streams(table_arn)
        get_store(context.account_id, context.region).TABLE_TAGS.pop(table_arn, None)

        return result

    def describe_table(self, context: RequestContext, table_name: TableName) -> DescribeTableOutput:
        global_table_region = self.get_global_table_region(context, table_name)

        result = self._forward_request(context=context, region=global_table_region)

        # Update table properties from LocalStack stores
        table_props = get_store(context.account_id, context.region).table_properties.get(table_name)
        if table_props:
            result.get("Table", {}).update(table_props)

        store = get_store(context.account_id, context.region)

        # Update replication details
        replicas: dict[str, set[str]] = store.REPLICA_UPDATES.get(table_name, {})

        replica_description_list = []
        for source_region, replicated_regions in replicas.items():
            # Contrary to AWS, we show all regions including the current context region where a replica exists
            # This is due to the limitation of internal request forwarding mechanism for global tables
            replica_description_list.append(
                ReplicaDescription(RegionName=source_region, ReplicaStatus=ReplicaStatus.ACTIVE)
            )
            for replicated_region in replicated_regions:
                replica_description_list.append(
                    ReplicaDescription(
                        RegionName=replicated_region, ReplicaStatus=ReplicaStatus.ACTIVE
                    )
                )
        result.get("Table", {}).update({"Replicas": replica_description_list})

        # update only TableId and SSEDescription if present
        table_definitions = get_store(context.account_id, context.region).table_definitions.get(
            table_name
        )
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
        table_name = update_table_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)

        try:
            result = self._forward_request(context=context, region=global_table_region)
        except CommonServiceException as exc:
            # DynamoDBLocal refuses to update certain table params and raises.
            # But we still need to update this info in LocalStack stores
            if not (exc.code == "ValidationException" and exc.message == "Nothing to update"):
                raise

            if table_class := update_table_input.get("TableClass"):
                table_definitions = get_store(
                    context.account_id, context.region
                ).table_definitions.setdefault(table_name, {})
                table_definitions["TableClass"] = table_class

            if replica_updates := update_table_input.get("ReplicaUpdates"):
                store = get_store(context.account_id, global_table_region)

                # Dict with source region to set of replicated regions
                replicas: dict[str, set(str)] = store.REPLICA_UPDATES.get(table_name, {})
                replicas.setdefault(global_table_region, set())

                for replica_update in replica_updates:
                    for key, details in replica_update.items():
                        # Replicated region
                        target_region = details.get("RegionName")

                        # Check if replicated region is valid
                        if target_region not in get_valid_regions_for_service("dynamodb"):
                            raise ValidationException(f"Region {target_region} is not supported")

                        match key:
                            case "Create":
                                if target_region in replicas[global_table_region]:
                                    raise ValidationException(
                                        f"Failed to create a the new replica of table with name: '{table_name}' because one or more replicas already existed as tables."
                                    )
                                replicas[global_table_region].add(target_region)
                            case "Delete":
                                try:
                                    replicas[global_table_region].remove(target_region)
                                    if len(replicas[global_table_region]) == 0:
                                        # Removing the set indicates that replication is disabled
                                        replicas.pop(global_table_region)
                                except KeyError:
                                    raise ValidationException(
                                        "Update global table operation failed because one or more replicas were not part of the global table."
                                    )

                store.REPLICA_UPDATES[table_name] = replicas

            # update response content
            schema = SchemaExtractor.get_table_schema(
                table_name, context.account_id, global_table_region
            )
            return UpdateTableOutput(TableDescription=schema["Table"])

        # TODO: DDB streams must also be created for replicas
        if update_table_input.get("StreamSpecification"):
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
        response = self.forward_request(context)

        # Add replicated tables
        replicas = get_store(context.account_id, context.region).REPLICA_UPDATES
        for replicated_table, replications in replicas.items():
            for original_region, replicated_regions in replications.items():
                if context.region in replicated_regions:
                    response["TableNames"].append(replicated_table)

        return response

    #
    # Item ops
    #

    @handler("PutItem", expand=False)
    def put_item(self, context: RequestContext, put_item_input: PutItemInput) -> PutItemOutput:
        table_name = put_item_input["TableName"]

        existing_item = None
        event_sources_or_streams_enabled = has_event_sources_or_streams_enabled(table_name)
        if event_sources_or_streams_enabled:
            existing_item = ItemFinder.find_existing_item(
                put_item_input, account_id=context.account_id, region_name=context.region
            )

        global_table_region = self.get_global_table_region(context, table_name)
        result = self._forward_request(context=context, region=global_table_region)

        # Since this operation makes use of global table region, we need to use the same region for all
        # calls made via the inter-service client. This is taken care of by passing the account ID and
        # region, eg. when getting the stream spec

        # Get stream specifications details for the table
        if event_sources_or_streams_enabled:
            stream_spec = dynamodb_get_table_stream_specification(
                account_id=context.account_id,
                region_name=global_table_region,
                table_name=table_name,
            )
            item = put_item_input["Item"]
            # prepare record keys
            keys = SchemaExtractor.extract_keys(
                item=item,
                table_name=table_name,
                account_id=context.account_id,
                region_name=global_table_region,
            )
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
        table_name = delete_item_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)

        existing_item = None
        if has_event_sources_or_streams_enabled(table_name):
            existing_item = ItemFinder.find_existing_item(delete_item_input)

        result = self._forward_request(context=context, region=global_table_region)

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
                stream_spec = dynamodb_get_table_stream_specification(
                    account_id=context.account_id, region_name=context.region, table_name=table_name
                )
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
        table_name = update_item_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)

        existing_item = None
        event_sources_or_streams_enabled = has_event_sources_or_streams_enabled(table_name)
        if event_sources_or_streams_enabled:
            existing_item = ItemFinder.find_existing_item(update_item_input)

        result = self._forward_request(context=context, region=global_table_region)

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
                stream_spec = dynamodb_get_table_stream_specification(
                    account_id=context.account_id, region_name=context.region, table_name=table_name
                )
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                self.forward_stream_records([record], table_name=table_name)
        return result

    @handler("GetItem", expand=False)
    def get_item(self, context: RequestContext, get_item_input: GetItemInput) -> GetItemOutput:
        table_name = get_item_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)
        result = self._forward_request(context=context, region=global_table_region)
        self.fix_consumed_capacity(get_item_input, result)
        return result

    #
    # Queries
    #

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

    #
    # Batch ops
    #

    @handler("BatchWriteItem", expand=False)
    def batch_write_item(
        self,
        context: RequestContext,
        batch_write_item_input: BatchWriteItemInput,
    ) -> BatchWriteItemOutput:
        # TODO: add global table support
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
        # TODO: add global table support
        return self.forward_request(context)

    #
    # Transactions
    #

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

        result = self.forward_request(context)

        # construct and forward stream record
        event_sources_or_streams_enabled = table_name and has_event_sources_or_streams_enabled(
            table_name
        )
        if event_sources_or_streams_enabled:
            records = get_updated_records(table_name, existing_items)
            self.forward_stream_records(records, table_name=table_name)

        return result

    #
    # Tags
    #

    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArnString, tags: TagList
    ) -> None:
        table_tags = get_store(context.account_id, context.region).TABLE_TAGS
        if resource_arn not in table_tags:
            table_tags[resource_arn] = {}
        table_tags[resource_arn].update({tag["Key"]: tag["Value"] for tag in tags})

    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArnString, tag_keys: TagKeyList
    ) -> None:
        for tag_key in tag_keys or []:
            get_store(context.account_id, context.region).TABLE_TAGS.get(resource_arn, {}).pop(
                tag_key, None
            )

    def list_tags_of_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        next_token: NextTokenString = None,
    ) -> ListTagsOfResourceOutput:
        result = [
            {"Key": k, "Value": v}
            for k, v in get_store(context.account_id, context.region)
            .TABLE_TAGS.get(resource_arn, {})
            .items()
        ]
        return ListTagsOfResourceOutput(Tags=result)

    #
    # TTLs
    #

    def describe_time_to_live(
        self, context: RequestContext, table_name: TableName
    ) -> DescribeTimeToLiveOutput:
        backend = get_store(context.account_id, context.region)

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
        backend = get_store(context.account_id, context.region)
        backend.ttl_specifications[table_name] = time_to_live_specification
        return UpdateTimeToLiveOutput(TimeToLiveSpecification=time_to_live_specification)

    #
    # Global tables
    #

    def create_global_table(
        self, context: RequestContext, global_table_name: TableName, replication_group: ReplicaList
    ) -> CreateGlobalTableOutput:
        global_tables: Dict = get_store(context.account_id, context.region).GLOBAL_TABLES
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
        details = get_store(context.account_id, context.region).GLOBAL_TABLES.get(global_table_name)
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
            for tab in get_store(context.account_id, context.region).GLOBAL_TABLES.values()
        ]
        return ListGlobalTablesOutput(GlobalTables=result)

    def update_global_table(
        self,
        context: RequestContext,
        global_table_name: TableName,
        replica_updates: ReplicaUpdateList,
    ) -> UpdateGlobalTableOutput:
        details = get_store(context.account_id, context.region).GLOBAL_TABLES.get(global_table_name)
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

    #
    # Kinesis Streaming
    #

    def enable_kinesis_streaming_destination(
        self, context: RequestContext, table_name: TableName, stream_arn: StreamArn
    ) -> KinesisStreamingDestinationOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        if not self.table_exists(context.account_id, context.region, table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")
        stream = EventForwarder.is_kinesis_stream_exists(stream_arn=stream_arn)
        if not stream:
            raise ValidationException("User does not have a permission to use kinesis stream")

        table_def = get_store(context.account_id, context.region).table_definitions.setdefault(
            table_name, {}
        )

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
        if not self.table_exists(context.account_id, context.region, table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")
        stream = EventForwarder.is_kinesis_stream_exists(stream_arn=stream_arn)
        if not stream:
            raise ValidationException(
                "User does not have a permission to use kinesis stream",
            )

        table_def = get_store(context.account_id, context.region).table_definitions.setdefault(
            table_name, {}
        )

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
        if not self.table_exists(context.account_id, context.region, table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")

        table_def = (
            get_store(context.account_id, context.region).table_definitions.get(table_name) or {}
        )

        stream_destinations = table_def.get("KinesisDataStreamDestinations") or []
        return DescribeKinesisStreamingDestinationOutput(
            KinesisDataStreamDestinations=stream_destinations, TableName=table_name
        )

    #
    # Helpers
    #

    @staticmethod
    def ddb_access_key(account_id: str, region_name: str) -> str:
        """
        Get the access key to be used while communicating with DynamoDB Local.

        DDBLocal supports namespacing as an undocumented feature. It works based on the value of the `Credentials`
        field of the `Authorization` header. We use a concatenated value of account ID and region to achieve
        namespacing.
        """
        return "{account_id}{region_name}".format(
            account_id=account_id, region_name=region_name
        ).replace("-", "")

    @staticmethod
    def ddb_region_name(region_name: str) -> str:
        """Map `local` or `localhost` region to the default region. These values are used by NoSQL Workbench."""
        # TODO: could this be somehow moved into the request handler chain?
        if region_name in ("local", "localhost"):
            region_name = aws_stack.get_local_region()

        return region_name

    @staticmethod
    def table_exists(account_id: str, region_name: str, table_name: str) -> bool:
        region_name = DynamoDBProvider.ddb_region_name(region_name)

        client = aws_stack.connect_to_service(
            "dynamodb",
            aws_access_key_id=account_id,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            region_name=region_name,
        )
        return dynamodb_table_exists(table_name, client)

    @staticmethod
    def get_global_table_region(context: RequestContext, table_name: str) -> str:
        """
        Return the table region considering that it might be a replicated table and that it exists within DDBLocal.
        :param context: request context
        :param table_name: table name
        :return: region
        :raise: ResourceNotFoundException if table does not exist in DynamoDB Local
        """
        replicas = get_store(context.account_id, context.region).REPLICA_UPDATES.get(table_name)
        if replicas:
            global_table_region = list(replicas.keys())[0]
            replicated_at = replicas[global_table_region]
            # Ensure that a replica exists in the current context region, and that the table exists in DDB Local
            if (
                context.region == global_table_region or context.region in replicated_at
            ) and DynamoDBProvider.table_exists(
                context.account_id, global_table_region, table_name
            ):
                return global_table_region
        else:
            if DynamoDBProvider.table_exists(context.account_id, context.region, table_name):
                return context.region

        raise ResourceNotFoundException("Cannot do operations on a non-existent table")

    @staticmethod
    def prepare_request_headers(headers: Dict, account_id: str, region_name: str):
        """
        Modify the Credentials field of Authorization header to achieve namespacing in DynamoDBLocal.
        """
        region_name = DynamoDBProvider.ddb_region_name(region_name)
        key = DynamoDBProvider.ddb_access_key(account_id, region_name)

        # DynamoDBLocal namespaces based on the value of Credentials
        # Since we want to namespace by both account ID and region, use an aggregate key
        # We also replace the region to keep compatibilty with NoSQL Workbench
        headers["Authorization"] = re.sub(
            AUTH_CREDENTIAL_REGEX,
            rf"Credential={key}/\2/{region_name}/\4/",
            headers.get("Authorization") or "",
            flags=re.IGNORECASE,
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

    def fix_table_arn(self, arn: str) -> str:
        """
        Set the correct account ID and region in ARNs returned by DynamoDB Local.
        """
        return arn.replace(":ddblocal:", f":{aws_stack.get_region()}:").replace(
            ":000000000000:", f":{get_aws_account_id()}:"
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
                stream_spec = dynamodb_get_table_stream_specification(
                    account_id=get_aws_account_id(),
                    region_name=aws_stack.get_region(),
                    table_name=table_name,
                )
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = copy.deepcopy(record)
                new_record["eventID"] = short_uid()
                new_record["eventName"] = "INSERT" if not existing_item else "MODIFY"
                new_record["dynamodb"]["Keys"] = keys
                new_record["dynamodb"]["NewImage"] = put_request["Item"]
                if existing_item:
                    new_record["dynamodb"]["OldImage"] = existing_item
                new_record["eventSourceARN"] = arns.dynamodb_table_arn(table_name)
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
                stream_spec = dynamodb_get_table_stream_specification(
                    account_id=get_aws_account_id(),
                    region_name=aws_stack.get_region(),
                    table_name=table_name,
                )
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = copy.deepcopy(record)
                new_record["eventID"] = short_uid()
                new_record["eventName"] = "MODIFY"
                new_record["dynamodb"]["Keys"] = keys
                new_record["dynamodb"]["OldImage"] = existing_items[i]
                new_record["dynamodb"]["NewImage"] = updated_item
                new_record["eventSourceARN"] = arns.dynamodb_table_arn(table_name)
                new_record["dynamodb"]["SizeBytes"] = _get_size_bytes(updated_item)
                records.append(new_record)
                i += 1
            delete_request = request.get("Delete")
            if delete_request:
                table_name = delete_request["TableName"]
                keys = delete_request["Key"]
                existing_item = existing_items[i]
                stream_spec = dynamodb_get_table_stream_specification(
                    account_id=get_aws_account_id(),
                    region_name=aws_stack.get_region(),
                    table_name=table_name,
                )
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = copy.deepcopy(record)
                new_record["eventID"] = short_uid()
                new_record["eventName"] = "REMOVE"
                new_record["dynamodb"]["Keys"] = keys
                new_record["dynamodb"]["OldImage"] = existing_item
                new_record["dynamodb"]["SizeBytes"] = _get_size_bytes(existing_items)
                new_record["eventSourceARN"] = arns.dynamodb_table_arn(table_name)
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
            stream_spec = dynamodb_get_table_stream_specification(
                account_id=get_aws_account_id(),
                region_name=aws_stack.get_region(),
                table_name=table_name,
            )
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
                        new_record["eventSourceARN"] = arns.dynamodb_table_arn(table_name)
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
                        new_record["eventSourceARN"] = arns.dynamodb_table_arn(table_name)
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
                    record["eventSourceARN"] = arns.dynamodb_table_arn(table_name)
            EventForwarder.forward_to_targets(records, background=True)

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
        """
        Check rate limiting for an API operation and raise an error if provisioned throughput is exceeded.
        """
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
    table_arn = arns.dynamodb_table_arn(table_name)
    cached = cache.get(table_arn)
    if isinstance(cached, bool):
        return cached
    lambda_client = aws_stack.connect_to_service("lambda")
    sources = lambda_client.list_event_source_mappings(EventSourceArn=table_arn)[
        "EventSourceMappings"
    ]
    result = False
    if sources:
        result = True
    if not result and dynamodbstreams_api.get_stream_for_table(table_arn):
        result = True

    # if kinesis streaming destination is enabled
    # get table name from table_arn
    # since batch_write and transact write operations passing table_arn instead of table_name
    table_name = table_arn.split("/", 1)[-1]
    account_id = extract_account_id_from_arn(table_arn)
    region_name = extract_region_from_arn(table_arn)
    table_definitions: Dict = get_store(account_id, region_name).table_definitions
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
    stream_spec = dynamodb_get_table_stream_specification(
        account_id=get_aws_account_id(), region_name=aws_stack.get_region(), table_name=table_name
    )

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


def dynamodb_get_table_stream_specification(account_id: str, region_name: str, table_name: str):
    try:
        table_schema = SchemaExtractor.get_table_schema(
            table_name, account_id=account_id, region_name=region_name
        )
        return table_schema["Table"].get("StreamSpecification")
    except Exception as e:
        LOG.info(
            "Unable to get stream specification for table %s: %s %s",
            table_name,
            e,
            traceback.format_exc(),
        )
        raise e
