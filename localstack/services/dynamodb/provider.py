import copy
import json
import random
import re
import time
from typing import Dict, List

import requests

from localstack import config, constants
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.dynamodb import (
    BatchWriteItemInput,
    BatchWriteItemOutput,
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
    ScanInput,
    ScanOutput,
    StreamArn,
    TableName,
    TagKeyList,
    TagList,
    TimeToLiveSpecification,
    TransactWriteItemsInput,
    TransactWriteItemsOutput,
    UpdateGlobalTableOutput,
    UpdateItemInput,
    UpdateItemOutput,
    UpdateTableInput,
    UpdateTableOutput,
    UpdateTimeToLiveOutput,
)
from localstack.aws.proxy import AwsApiListener
from localstack.constants import LOCALHOST
from localstack.services.dynamodb import dynamodb_starter
from localstack.services.dynamodb.dynamodb_listener import (
    ACTION_PREFIX,
    READ_THROTTLED_ACTIONS,
    THROTTLED_ACTIONS,
    WRITE_THROTTLED_ACTIONS,
    DynamoDBRegion,
    EventForwarder,
    SSEUtils,
    create_dynamodb_stream,
    dynamodb_get_table_stream_specification,
    fix_headers_for_updated_response,
    get_updated_records,
    has_event_sources_or_streams_enabled,
    is_index_query_valid,
)
from localstack.services.dynamodb.dynamodb_starter import start_dynamodb, wait_for_dynamodb
from localstack.services.dynamodb.utils import (
    ItemFinder,
    SchemaExtractor,
    extract_table_name_from_partiql_update,
)
from localstack.services.dynamodbstreams import dynamodbstreams_api
from localstack.services.forwarder import (
    ExternalProcessFallbackDispatcher,
    ServiceRequestType,
    request_forwarder,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_responses, aws_stack
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.collections import select_attributes
from localstack.utils.strings import long_uid, short_uid, to_str


class ValidationException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__(code="ValidationException", status_code=400, message=message)


class DynamoDBApiListener(AwsApiListener):
    def __init__(self):
        self.provider = provider = DynamoDBProvider()
        super().__init__(
            "dynamodb", ExternalProcessFallbackDispatcher(provider, provider.get_forward_url)
        )

    def forward_request(self, method, path, data, headers):
        result = self.provider.handle_special_request(method, path, data, headers)
        if result is not None:
            return result

        action = headers.get("X-Amz-Target", "")
        action = action.replace(ACTION_PREFIX, "")
        if self.provider.should_throttle(action):
            message = (
                "The level of configured provisioned throughput for the table was exceeded. "
                + "Consider increasing your provisioning level with the UpdateTable API"
            )
            raise ProvisionedThroughputExceededException(message)

        return super().forward_request(method, path, data, headers)

    def return_response(self, method, path, data, headers, response):
        if path.startswith("/shell") or method == "GET":
            return

        if response._content:
            # fix the table and latest stream ARNs (DynamoDBLocal hardcodes "ddblocal" as the region)
            content_replaced = re.sub(
                r'("TableArn"|"LatestStreamArn"|"StreamArn")\s*:\s*"arn:aws:dynamodb:ddblocal:([^"]+)"',
                rf'\1: "arn:aws:dynamodb:{aws_stack.get_region()}:\2"',
                to_str(response._content),
            )
            if content_replaced != response._content:
                response._content = content_replaced

        # set x-amz-crc32 headers required by some client
        fix_headers_for_updated_response(response)

        # update table definitions
        data = json.loads(to_str(data))
        if data and "TableName" in data and "KeySchema" in data:
            table_definitions = DynamoDBRegion.get().table_definitions
            table_definitions[data["TableName"]] = data


class DynamoDBProvider(DynamodbApi, ServiceLifecycleHook):
    def __init__(self):
        self.request_forwarder = request_forwarder(self.get_forward_url)

    def forward_request(self, context: RequestContext, service_request: ServiceRequestType = None):
        # note: modifying headers in-place here before forwarding the request
        self.prepare_request_headers(context.request.headers)
        return self.request_forwarder(context, service_request=service_request)

    def get_forward_url(self):
        """Return the URL of the backend DynamoDBLocal server to forward requests to"""
        return f"http://{LOCALHOST}:{dynamodb_starter._server.port}"

    def on_before_start(self):
        start_dynamodb()
        wait_for_dynamodb()

    def handle_special_request(self, method, path, data, headers):
        if path.startswith("/shell") or method == "GET":
            if path == "/shell":
                headers = {"Refresh": f"0; url={config.service_url('dynamodb')}/shell/"}
                return aws_responses.requests_response("", headers=headers)
            if path.startswith("/shell"):
                url = f"{self.get_forward_url()}{path}"
                return requests.request(method=method, url=url, headers=headers, data=data)
            return True

        if method == "OPTIONS":
            return 200

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

        # forward request to backend
        result = self.forward_request(context)

        backend = DynamoDBRegion.get()
        backend.table_definitions[table_name] = table_definitions = dict(create_table_input)

        if "TableId" not in table_definitions:
            table_definitions["TableId"] = long_uid()

        if "SSESpecification" in table_definitions:
            sse_specification = table_definitions.pop("SSESpecification")
            table_definitions["SSEDescription"] = SSEUtils.get_sse_description(sse_specification)

        if table_definitions:
            table_content = result.get("Table", {})
            table_content.update(table_definitions)
            result["TableDescription"].update(table_content)

        if "StreamSpecification" in table_definitions:
            create_dynamodb_stream(
                table_definitions, result["TableDescription"].get("LatestStreamLabel")
            )

        tags = table_definitions.pop("Tags", [])
        result["TableDescription"].pop("Tags", None)
        if tags:
            table_arn = result["TableDescription"]["TableArn"]
            table_arn = self.fix_table_arn(table_arn)
            DynamoDBRegion.TABLE_TAGS[table_arn] = {tag["Key"]: tag["Value"] for tag in tags}

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
        DynamoDBRegion.TABLE_TAGS.pop(table_arn, None)

        return result

    def describe_table(self, context: RequestContext, table_name: TableName) -> DescribeTableOutput:
        # Check if table exists, to avoid error log output from DynamoDBLocal
        if not self.table_exists(table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")

        # forward request to backend
        result = self.forward_request(context)

        # update response with additional props
        table_props = DynamoDBRegion.get().table_properties.get(table_name)
        if table_props:
            result.get("Table", {}).update(table_props)

        # update only TableId and SSEDescription if present
        table_definitions = DynamoDBRegion.get().table_definitions.get(table_name)
        if table_definitions:
            for key in ["TableId", "SSEDescription"]:
                if table_definitions.get(key):
                    result.get("Table", {})[key] = table_definitions[key]

        return result

    @handler("UpdateTable", expand=False)
    def update_table(
        self, context: RequestContext, update_table_input: UpdateTableInput
    ) -> UpdateTableOutput:
        try:
            # forward request to backend
            result = self.forward_request(context)
        except Exception as e:
            if "Nothing to update" in str(e) and update_table_input.get("ReplicaUpdates"):
                table_name = update_table_input.get("TableName")
                # update local table props (replicas)
                table_properties = DynamoDBRegion.get().table_properties
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
            raise

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
        self.fix_return_consumed_capacity(put_item_input)
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
                    "SizeBytes": len(json.dumps(item)),
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
        self.fix_return_consumed_capacity(delete_item_input)
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
                        "SizeBytes": len(json.dumps(existing_item)),
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
        self.fix_return_consumed_capacity(update_item_input)
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
                        "SizeBytes": len(json.dumps(updated_item)),
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
        if query_input.get("IndexName"):
            if not is_index_query_valid(
                to_str(query_input["TableName"]), query_input.get("Select")
            ):
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
                    record["eventSourceARN"], streams_enabled_cache
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

            # TODO update CRC32 headers?
            # fix_headers_for_updated_response(response)

        return result

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
                    record["eventSourceARN"], streams_enabled_cache
                )
            )
        if event_sources_or_streams_enabled:
            self.forward_stream_records(records)

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
        table_tags = DynamoDBRegion.TABLE_TAGS
        if resource_arn not in table_tags:
            table_tags[resource_arn] = {}
        table_tags[resource_arn].update({tag["Key"]: tag["Value"] for tag in tags})

    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArnString, tag_keys: TagKeyList
    ) -> None:
        for tag_key in tag_keys or []:
            DynamoDBRegion.TABLE_TAGS.get(resource_arn, {}).pop(tag_key, None)

    def list_tags_of_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        next_token: NextTokenString = None,
    ) -> ListTagsOfResourceOutput:
        result = [
            {"Key": k, "Value": v}
            for k, v in DynamoDBRegion.TABLE_TAGS.get(resource_arn, {}).items()
        ]
        return ListTagsOfResourceOutput(Tags=result)

    def describe_time_to_live(
        self, context: RequestContext, table_name: TableName
    ) -> DescribeTimeToLiveOutput:
        backend = DynamoDBRegion.get()

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
        backend = DynamoDBRegion.get()
        backend.ttl_specifications[table_name] = time_to_live_specification
        return UpdateTimeToLiveOutput(TimeToLiveSpecification=time_to_live_specification)

    def create_global_table(
        self, context: RequestContext, global_table_name: TableName, replication_group: ReplicaList
    ) -> CreateGlobalTableOutput:
        if global_table_name in DynamoDBRegion.GLOBAL_TABLES:
            raise GlobalTableAlreadyExistsException("Global table with this name already exists")
        replication_group = [grp.copy() for grp in replication_group or []]
        data = {"GlobalTableName": global_table_name, "ReplicationGroup": replication_group}
        DynamoDBRegion.GLOBAL_TABLES[global_table_name] = data
        for group in replication_group:
            group["ReplicaStatus"] = "ACTIVE"
            group["ReplicaStatusDescription"] = "Replica active"
        return CreateGlobalTableOutput(GlobalTableDescription=data)

    def describe_global_table(
        self, context: RequestContext, global_table_name: TableName
    ) -> DescribeGlobalTableOutput:
        details = DynamoDBRegion.GLOBAL_TABLES.get(global_table_name)
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
            for tab in DynamoDBRegion.GLOBAL_TABLES.values()
        ]
        return ListGlobalTablesOutput(GlobalTables=result)

    def update_global_table(
        self,
        context: RequestContext,
        global_table_name: TableName,
        replica_updates: ReplicaUpdateList,
    ) -> UpdateGlobalTableOutput:
        details = DynamoDBRegion.GLOBAL_TABLES.get(global_table_name)
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

        table_def = DynamoDBRegion.get().table_definitions.setdefault(table_name, {})

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

        table_def = DynamoDBRegion.get().table_definitions.setdefault(table_name, {})

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

        table_def = DynamoDBRegion.get().table_definitions.get(table_name)

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

    def fix_return_consumed_capacity(self, request_dict):
        # Fix incorrect values if ReturnValues==ALL_OLD and ReturnConsumedCapacity is
        # empty, see https://github.com/localstack/localstack/issues/2049
        return_values_all = (request_dict.get("ReturnValues") == "ALL_OLD") or (
            not request_dict.get("ReturnValues")
        )
        if return_values_all and not request_dict.get("ReturnConsumedCapacity"):
            request_dict["ReturnConsumedCapacity"] = "TOTAL"

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
                new_record["dynamodb"]["SizeBytes"] = len(json.dumps(put_request["Item"]))
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
                new_record["dynamodb"]["SizeBytes"] = len(json.dumps(updated_item))
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
                new_record["dynamodb"]["SizeBytes"] = len(json.dumps(existing_item))
                new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                records.append(new_record)
                i += 1
        return records

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
                        new_record["dynamodb"]["SizeBytes"] = len(json.dumps(put_request["Item"]))
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
                                json.loads(json.dumps(unprocessed_item))
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
                        new_record["dynamodb"]["SizeBytes"] = len(json.dumps(existing_items[i]))
                        new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                        records.append(new_record)
                    if unprocessed_delete_items and len(unprocessed_delete_items) > i:
                        unprocessed_item = unprocessed_delete_items[i]
                        if unprocessed_item:
                            unprocessed_items["DeleteRequest"].update(
                                json.loads(json.dumps(unprocessed_item))
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
            # fix start dynamodb service without lambda
            if not is_api_enabled("lambda"):
                return

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
        else:
            return False
