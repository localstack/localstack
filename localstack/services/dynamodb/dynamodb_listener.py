import copy
import json
import logging
import random
import re
import threading
import time
import traceback
from binascii import crc32

from cachetools import TTLCache
from requests.models import Request, Response

from localstack import config, constants
from localstack.services.awslambda import lambda_api
from localstack.services.dynamodbstreams import dynamodbstreams_api
from localstack.services.generic_proxy import ProxyListener, RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_responses, aws_stack
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.common import (
    clone,
    json_safe,
    long_uid,
    select_attributes,
    short_uid,
    to_bytes,
    to_str,
)

# set up logger
LOGGER = logging.getLogger(__name__)

# cache schema definitions
SCHEMA_CACHE = TTLCache(maxsize=50, ttl=20)

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


class DynamoDBRegion(RegionBackend):
    # maps global table names to configurations
    GLOBAL_TABLES = {}
    # cache table taggings
    TABLE_TAGS = {}

    def __init__(self):
        # maps table names to cached table definitions
        self.table_definitions = {}
        # maps table names to additional table properties that are not stored upstream (e.g., ReplicaUpdates)
        self.table_properties = {}


class ProxyListenerDynamoDB(ProxyListener):
    thread_local = threading.local()

    def __init__(self):
        self._table_ttl_map = {}

    @staticmethod
    def table_exists(ddb_client, table_name):
        return aws_stack.dynamodb_table_exists(table_name, client=ddb_client)

    def action_should_throttle(self, action, actions):
        throttled = ["%s%s" % (ACTION_PREFIX, a) for a in actions]
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

    def forward_request(self, method, path, data, headers):
        result = handle_special_request(method, path, data, headers)
        if result is not None:
            return result

        # prepare request headers
        self.prepare_request_headers(headers)

        data_orig = data
        data = data or "{}"
        data = json.loads(to_str(data))
        ddb_client = aws_stack.connect_to_service("dynamodb")
        action = headers.get("X-Amz-Target", "")
        action = action.replace(ACTION_PREFIX, "")

        if self.should_throttle(action):
            return error_response_throughput()

        ProxyListenerDynamoDB.thread_local.existing_item = None
        table_def = None
        if "TableName" in data:
            table_def = DynamoDBRegion.get().table_definitions.get(data["TableName"]) or {}

        if action == "CreateTable":
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if self.table_exists(ddb_client, data["TableName"]):
                return error_response(
                    message="Table already created",
                    error_type="ResourceInUseException",
                    code=400,
                )

        elif action == "CreateGlobalTable":
            return create_global_table(data)

        elif action == "DescribeGlobalTable":
            return describe_global_table(data)

        elif action == "ListGlobalTables":
            return list_global_tables(data)

        elif action == "UpdateGlobalTable":
            return update_global_table(data)

        elif action in ("PutItem", "UpdateItem", "DeleteItem"):
            # find an existing item and store it in a thread-local, so we can access it in return_response,
            # in order to determine whether an item already existed (MODIFY) or not (INSERT)
            try:
                if has_event_sources_or_streams_enabled(data["TableName"]):
                    ProxyListenerDynamoDB.thread_local.existing_item = find_existing_item(data)
            except Exception as e:
                if "ResourceNotFoundException" in str(e):
                    return get_table_not_found_error()
                raise

            # Fix incorrect values if ReturnValues==ALL_OLD and ReturnConsumedCapacity is
            # empty, see https://github.com/localstack/localstack/issues/2049
            if (
                (data.get("ReturnValues") == "ALL_OLD") or (not data.get("ReturnValues"))
            ) and not data.get("ReturnConsumedCapacity"):
                data["ReturnConsumedCapacity"] = "TOTAL"
                return Request(data=json.dumps(data), method=method, headers=headers)

        elif action == "DescribeTable":
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if not self.table_exists(ddb_client, data["TableName"]):
                return get_table_not_found_error()

        elif action == "DeleteTable":
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if not self.table_exists(ddb_client, data["TableName"]):
                return get_table_not_found_error()

        elif action == "BatchWriteItem":
            existing_items = []
            unprocessed_put_items = []
            unprocessed_delete_items = []
            for table_name in sorted(data["RequestItems"].keys()):
                for request in data["RequestItems"][table_name]:
                    for key in ["PutRequest", "DeleteRequest"]:
                        inner_request = request.get(key)
                        if inner_request:
                            if self.should_throttle(action):
                                if key == "PutRequest":
                                    unprocessed_put_items.append(inner_request)
                                elif key == "DeleteRequest":
                                    unprocessed_delete_items.append(inner_request)
                            else:
                                item = find_existing_item(inner_request, table_name)
                                existing_items.append(item)
            ProxyListenerDynamoDB.thread_local.existing_items = existing_items
            ProxyListenerDynamoDB.thread_local.unprocessed_put_items = unprocessed_put_items
            ProxyListenerDynamoDB.thread_local.unprocessed_delete_items = unprocessed_delete_items

        elif action == "Query":
            if data.get("IndexName"):
                if not is_index_query_valid(to_str(data["TableName"]), data.get("Select")):
                    return error_response(
                        message="One or more parameter values were invalid: Select type ALL_ATTRIBUTES "
                        "is not supported for global secondary index id-index because its projection "
                        "type is not ALL",
                        error_type="ValidationException",
                        code=400,
                    )

        elif action == "TransactWriteItems":
            existing_items = []
            for item in data["TransactItems"]:
                for key in ["Put", "Update", "Delete"]:
                    inner_item = item.get(key)
                    if inner_item:
                        existing_items.append(find_existing_item(inner_item))
            ProxyListenerDynamoDB.thread_local.existing_items = existing_items

        elif action == "UpdateTimeToLive":
            # TODO: TTL status is maintained/mocked but no real expiry is happening for items
            response = Response()
            response.status_code = 200
            self._table_ttl_map[data["TableName"]] = {
                "AttributeName": data["TimeToLiveSpecification"]["AttributeName"],
                "Status": data["TimeToLiveSpecification"]["Enabled"],
            }
            response._content = json.dumps(
                {"TimeToLiveSpecification": data["TimeToLiveSpecification"]}
            )
            fix_headers_for_updated_response(response)
            return response

        elif action == "DescribeTimeToLive":
            response = Response()
            response.status_code = 200
            if data["TableName"] in self._table_ttl_map:
                if self._table_ttl_map[data["TableName"]]["Status"]:
                    ttl_status = "ENABLED"
                else:
                    ttl_status = "DISABLED"
                response._content = json.dumps(
                    {
                        "TimeToLiveDescription": {
                            "AttributeName": self._table_ttl_map[data["TableName"]][
                                "AttributeName"
                            ],
                            "TimeToLiveStatus": ttl_status,
                        }
                    }
                )
            else:  # TTL for dynamodb table not set
                response._content = json.dumps(
                    {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}
                )

            fix_headers_for_updated_response(response)
            return response

        elif action in ("TagResource", "UntagResource"):
            response = Response()
            response.status_code = 200
            response._content = ""  # returns an empty body on success.
            fix_headers_for_updated_response(response)
            return response

        elif action == "ListTagsOfResource":
            response = Response()
            response.status_code = 200
            response._content = json.dumps(
                {
                    "Tags": [
                        {"Key": k, "Value": v}
                        for k, v in DynamoDBRegion.TABLE_TAGS.get(data["ResourceArn"], {}).items()
                    ]
                }
            )
            fix_headers_for_updated_response(response)
            return response

        elif action == "EnableKinesisStreamingDestination":
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if not self.table_exists(ddb_client, data["TableName"]):
                return get_table_not_found_error()
            stream = is_kinesis_stream_exists(stream_arn=data["StreamArn"])
            if not stream:
                return error_response(
                    error_type="ValidationException",
                    message="User does not have a permission to use kinesis stream",
                )

            return dynamodb_enable_kinesis_streaming_destination(data, table_def)

        elif action == "DisableKinesisStreamingDestination":
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if not self.table_exists(ddb_client, data["TableName"]):
                return get_table_not_found_error()
            stream = is_kinesis_stream_exists(stream_arn=data["StreamArn"])
            if not stream:
                return error_response(
                    error_type="ValidationException",
                    message="User does not have a permission to use kinesis stream",
                )

            return dynamodb_disable_kinesis_streaming_destination(data, table_def)

        elif action == "DescribeKinesisStreamingDestination":
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if not self.table_exists(ddb_client, data["TableName"]):
                return get_table_not_found_error()
            response = aws_responses.requests_response(
                {
                    "KinesisDataStreamDestinations": table_def.get("KinesisDataStreamDestinations")
                    or [],
                    "TableName": data["TableName"],
                }
            )
            return response

        return Request(data=data_orig, method=method, headers=headers)

    def return_response(self, method, path, data, headers, response):
        if path.startswith("/shell") or method == "GET":
            return

        data = json.loads(to_str(data))

        # update table definitions
        if data and "TableName" in data and "KeySchema" in data:
            table_definitions = DynamoDBRegion.get().table_definitions
            table_definitions[data["TableName"]] = data
        if response._content:
            # fix the table and latest stream ARNs (DynamoDBLocal hardcodes "ddblocal" as the region)
            content_replaced = re.sub(
                r'("TableArn"|"LatestStreamArn"|"StreamArn")\s*:\s*"arn:aws:dynamodb:ddblocal:([^"]+)"',
                r'\1: "arn:aws:dynamodb:%s:\2"' % aws_stack.get_region(),
                to_str(response._content),
            )
            if content_replaced != response._content:
                response._content = content_replaced
                fix_headers_for_updated_response(response)

        action = headers.get("X-Amz-Target", "")
        action = action.replace(ACTION_PREFIX, "")
        if not action:
            return
        # upgrade event version to 1.1
        record = {
            "eventID": "1",
            "eventVersion": "1.1",
            "dynamodb": {
                "ApproximateCreationDateTime": time.time(),
                # 'StreamViewType': 'NEW_AND_OLD_IMAGES',
                "SizeBytes": -1,
            },
            "awsRegion": aws_stack.get_region(),
            "eventSource": "aws:dynamodb",
        }
        records = [record]

        streams_enabled_cache = {}
        table_name = data.get("TableName")
        event_sources_or_streams_enabled = has_event_sources_or_streams_enabled(
            table_name, streams_enabled_cache
        )

        if action == "UpdateItem":
            if response.status_code == 200 and event_sources_or_streams_enabled:
                existing_item = self._thread_local("existing_item")
                record["eventName"] = "INSERT" if not existing_item else "MODIFY"
                record["eventID"] = short_uid()
                updated_item = find_existing_item(data)
                if not updated_item:
                    return
                record["dynamodb"]["Keys"] = data["Key"]
                if existing_item:
                    record["dynamodb"]["OldImage"] = existing_item
                record["dynamodb"]["NewImage"] = updated_item
                record["dynamodb"]["SizeBytes"] = len(json.dumps(updated_item))
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]

        elif action == "BatchWriteItem":
            records, unprocessed_items = self.prepare_batch_write_item_records(record, data)
            for record in records:
                event_sources_or_streams_enabled = (
                    event_sources_or_streams_enabled
                    or has_event_sources_or_streams_enabled(
                        record["eventSourceARN"], streams_enabled_cache
                    )
                )
            if response.status_code == 200 and any(unprocessed_items):
                content = json.loads(to_str(response.content))
                table_name = list(data["RequestItems"].keys())[0]
                if table_name not in content["UnprocessedItems"]:
                    content["UnprocessedItems"][table_name] = []
                for key in ["PutRequest", "DeleteRequest"]:
                    if any(unprocessed_items[key]):
                        content["UnprocessedItems"][table_name].append(
                            {key: unprocessed_items[key]}
                        )
                unprocessed = content["UnprocessedItems"]
                for key in list(unprocessed.keys()):
                    if not unprocessed.get(key):
                        del unprocessed[key]

                response._content = json.dumps(content)
                fix_headers_for_updated_response(response)

        elif action == "TransactWriteItems":
            records = self.prepare_transact_write_item_records(record, data)
            for record in records:
                event_sources_or_streams_enabled = (
                    event_sources_or_streams_enabled
                    or has_event_sources_or_streams_enabled(
                        record["eventSourceARN"], streams_enabled_cache
                    )
                )

        elif action == "PutItem":
            if response.status_code == 200:
                keys = dynamodb_extract_keys(item=data["Item"], table_name=table_name)
                if isinstance(keys, Response):
                    return keys
                # fix response
                if response._content == "{}":
                    response._content = update_put_item_response_content(data, response._content)
                    fix_headers_for_updated_response(response)
                if event_sources_or_streams_enabled:
                    existing_item = self._thread_local("existing_item")
                    # Get stream specifications details for the table
                    stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                    record["eventName"] = "INSERT" if not existing_item else "MODIFY"
                    # prepare record keys
                    record["dynamodb"]["Keys"] = keys
                    record["dynamodb"]["NewImage"] = data["Item"]
                    record["dynamodb"]["SizeBytes"] = len(json.dumps(data["Item"]))
                    record["eventID"] = short_uid()
                    if stream_spec:
                        record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                    if existing_item:
                        record["dynamodb"]["OldImage"] = existing_item

        elif action in ("GetItem", "Query"):
            if response.status_code == 200:
                content = json.loads(to_str(response.content))
                # make sure we append 'ConsumedCapacity', which is properly
                # returned by dynalite, but not by AWS's DynamoDBLocal
                if "ConsumedCapacity" not in content and data.get("ReturnConsumedCapacity") in [
                    "TOTAL",
                    "INDEXES",
                ]:
                    content["ConsumedCapacity"] = {
                        "TableName": table_name,
                        "CapacityUnits": 5,  # TODO hardcoded
                        "ReadCapacityUnits": 2,
                        "WriteCapacityUnits": 3,
                    }
                    response._content = json.dumps(content)
                    fix_headers_for_updated_response(response)

        elif action == "DeleteItem":
            if response.status_code == 200 and event_sources_or_streams_enabled:
                old_item = self._thread_local("existing_item")
                record["eventID"] = short_uid()
                record["eventName"] = "REMOVE"
                record["dynamodb"]["Keys"] = data["Key"]
                record["dynamodb"]["OldImage"] = old_item
                record["dynamodb"]["SizeBytes"] = len(json.dumps(old_item))
                # Get stream specifications details for the table
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]

        elif action == "CreateTable":
            if response.status_code == 200:

                table_definitions = (
                    DynamoDBRegion.get().table_definitions.get(data["TableName"]) or {}
                )
                if "TableId" not in table_definitions:
                    table_definitions["TableId"] = long_uid()

                if "SSESpecification" in table_definitions:
                    sse_specification = table_definitions.pop("SSESpecification")
                    table_definitions["SSEDescription"] = get_sse_description(sse_specification)

                content = json.loads(to_str(response.content))
                if table_definitions:
                    table_content = content.get("Table", {})
                    table_content.update(table_definitions)
                    content["TableDescription"].update(table_content)
                    update_response_content(response, content)

                if "StreamSpecification" in data:
                    create_dynamodb_stream(
                        data, content["TableDescription"].get("LatestStreamLabel")
                    )

                if data.get("Tags"):
                    table_arn = content["TableDescription"]["TableArn"]
                    DynamoDBRegion.TABLE_TAGS[table_arn] = {
                        tag["Key"]: tag["Value"] for tag in data["Tags"]
                    }

            event_publisher.fire_event(
                event_publisher.EVENT_DYNAMODB_CREATE_TABLE,
                payload={"n": event_publisher.get_hash(table_name)},
            )

            return

        elif action == "DeleteTable":
            if response.status_code == 200:
                table_arn = (
                    json.loads(response._content).get("TableDescription", {}).get("TableArn")
                )
                event_publisher.fire_event(
                    event_publisher.EVENT_DYNAMODB_DELETE_TABLE,
                    payload={"n": event_publisher.get_hash(table_name)},
                )
                self.delete_all_event_source_mappings(table_arn)
                dynamodbstreams_api.delete_streams(table_arn)
                DynamoDBRegion.TABLE_TAGS.pop(table_arn, None)
            return

        elif action == "UpdateTable":
            content_str = to_str(response._content or "")
            if response.status_code == 200 and "StreamSpecification" in data:
                content = json.loads(content_str)
                create_dynamodb_stream(data, content["TableDescription"].get("LatestStreamLabel"))
            if (
                response.status_code >= 400
                and data.get("ReplicaUpdates")
                and "Nothing to update" in content_str
            ):
                table_name = data.get("TableName")
                # update local table props (replicas)
                table_properties = DynamoDBRegion.get().table_properties
                table_properties[table_name] = table_props = table_properties.get(table_name) or {}
                table_props["Replicas"] = replicas = table_props.get("Replicas") or []
                for repl_update in data["ReplicaUpdates"]:
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
                schema = get_table_schema(table_name)
                result = {"TableDescription": schema["Table"]}
                update_response_content(response, json_safe(result), 200)
            return

        elif action == "DescribeTable":
            table_name = data.get("TableName")
            table_props = DynamoDBRegion.get().table_properties.get(table_name)

            if table_props:
                content = json.loads(to_str(response.content))
                content.get("Table", {}).update(table_props)
                update_response_content(response, content)

            # Update only TableId and SSEDescription if present
            table_definitions = DynamoDBRegion.get().table_definitions.get(table_name)
            if table_definitions:
                for key in ["TableId", "SSEDescription"]:
                    if table_definitions.get(key):
                        content = json.loads(to_str(response.content))
                        content.get("Table", {})[key] = table_definitions[key]
                        update_response_content(response, content)

        elif action == "TagResource":
            table_arn = data["ResourceArn"]
            table_tags = DynamoDBRegion.TABLE_TAGS
            if table_arn not in table_tags:
                table_tags[table_arn] = {}
            table_tags[table_arn].update({tag["Key"]: tag["Value"] for tag in data.get("Tags", [])})
            return

        elif action == "UntagResource":
            table_arn = data["ResourceArn"]
            for tag_key in data.get("TagKeys", []):
                DynamoDBRegion.TABLE_TAGS.get(table_arn, {}).pop(tag_key, None)
            return

        else:
            # nothing to do
            return
        if event_sources_or_streams_enabled and records and "eventName" in records[0]:
            if "TableName" in data:
                records[0]["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
            # forward to kinesis stream
            records_to_kinesis = copy.deepcopy(records)
            forward_to_kinesis_stream(records_to_kinesis)
            # forward to lambda and ddb_streams
            forward_to_lambda(records)
            records = self.prepare_records_to_forward_to_ddb_stream(records)
            forward_to_ddb_stream(records)

    # -------------
    # UTIL METHODS
    # -------------

    def prepare_request_headers(self, headers):
        # Note: We need to ensure that the same access key is used here for all requests,
        # otherwise DynamoDBLocal stores tables/items in separate namespaces
        headers["Authorization"] = re.sub(
            r"Credential=[^/]+/",
            r"Credential=%s/" % constants.TEST_AWS_ACCESS_KEY_ID,
            headers.get("Authorization") or "",
        )

    def prepare_batch_write_item_records(self, record, data):
        records = []
        unprocessed_items = {"PutRequest": {}, "DeleteRequest": {}}
        i = 0
        for table_name in sorted(data["RequestItems"].keys()):
            # Add stream view type to record if ddb stream is enabled
            stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
            if stream_spec:
                record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
            for request in data["RequestItems"][table_name]:
                put_request = request.get("PutRequest")
                existing_items = self._thread_local("existing_items")
                if put_request:
                    if existing_items and len(existing_items) > i:
                        existing_item = existing_items[i]
                        keys = dynamodb_extract_keys(
                            item=put_request["Item"], table_name=table_name
                        )
                        if isinstance(keys, Response):
                            return keys
                        new_record = clone(record)
                        new_record["eventID"] = short_uid()
                        new_record["dynamodb"]["SizeBytes"] = len(json.dumps(put_request["Item"]))
                        new_record["eventName"] = "INSERT" if not existing_item else "MODIFY"
                        new_record["dynamodb"]["Keys"] = keys
                        new_record["dynamodb"]["NewImage"] = put_request["Item"]
                        if existing_item:
                            new_record["dynamodb"]["OldImage"] = existing_item
                        new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                        records.append(new_record)
                    unprocessed_put_items = self._thread_local("unprocessed_put_items")
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
                        if isinstance(keys, Response):
                            return keys
                        new_record = clone(record)
                        new_record["eventID"] = short_uid()
                        new_record["eventName"] = "REMOVE"
                        new_record["dynamodb"]["Keys"] = keys
                        new_record["dynamodb"]["OldImage"] = existing_items[i]
                        new_record["dynamodb"]["SizeBytes"] = len(json.dumps(existing_items[i]))
                        new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                        records.append(new_record)
                    unprocessed_delete_items = self._thread_local("unprocessed_delete_items")
                    if unprocessed_delete_items and len(unprocessed_delete_items) > i:
                        unprocessed_item = unprocessed_delete_items[i]
                        if unprocessed_item:
                            unprocessed_items["DeleteRequest"].update(
                                json.loads(json.dumps(unprocessed_item))
                            )
                i += 1
        return records, unprocessed_items

    def prepare_transact_write_item_records(self, record, data):
        records = []
        # Fix issue #2745: existing_items only contain the Put/Update/Delete records,
        # so we will increase the index based on these events
        i = 0
        for request in data["TransactItems"]:
            put_request = request.get("Put")
            if put_request:
                existing_item = self._thread_local("existing_items")[i]
                table_name = put_request["TableName"]
                keys = dynamodb_extract_keys(item=put_request["Item"], table_name=table_name)
                if isinstance(keys, Response):
                    return keys
                # Add stream view type to record if ddb stream is enabled
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = clone(record)
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
                if isinstance(keys, Response):
                    return keys
                updated_item = find_existing_item(update_request, table_name)
                if not updated_item:
                    return []
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = clone(record)
                new_record["eventID"] = short_uid()
                new_record["eventName"] = "MODIFY"
                new_record["dynamodb"]["Keys"] = keys
                new_record["dynamodb"]["OldImage"] = self._thread_local("existing_items")[i]
                new_record["dynamodb"]["NewImage"] = updated_item
                new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                new_record["dynamodb"]["SizeBytes"] = len(json.dumps(updated_item))
                records.append(new_record)
                i += 1
            delete_request = request.get("Delete")
            if delete_request:
                table_name = delete_request["TableName"]
                keys = delete_request["Key"]
                existing_item = self._thread_local("existing_items")[i]
                if isinstance(keys, Response):
                    return keys
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record["dynamodb"]["StreamViewType"] = stream_spec["StreamViewType"]
                new_record = clone(record)
                new_record["eventID"] = short_uid()
                new_record["eventName"] = "REMOVE"
                new_record["dynamodb"]["Keys"] = keys
                new_record["dynamodb"]["OldImage"] = existing_item
                new_record["dynamodb"]["SizeBytes"] = len(json.dumps(existing_item))
                new_record["eventSourceARN"] = aws_stack.dynamodb_table_arn(table_name)
                records.append(new_record)
                i += 1
        return records

    def prepare_records_to_forward_to_ddb_stream(self, records):
        # StreamViewType determines what information is written to the stream for the table
        # When an item in the table is inserted, updated or deleted
        for record in records:
            if record["dynamodb"].get("StreamViewType"):
                # KEYS_ONLY  - Only the key attributes of the modified item are written to the stream
                if record["dynamodb"]["StreamViewType"] == "KEYS_ONLY":
                    record["dynamodb"].pop("OldImage", None)
                    record["dynamodb"].pop("NewImage", None)
                # NEW_IMAGE - The entire item, as it appears after it was modified, is written to the stream
                elif record["dynamodb"]["StreamViewType"] == "NEW_IMAGE":
                    record["dynamodb"].pop("OldImage", None)
                # OLD_IMAGE - The entire item, as it appeared before it was modified, is written to the stream
                elif record["dynamodb"]["StreamViewType"] == "OLD_IMAGE":
                    record["dynamodb"].pop("NewImage", None)
        return records

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

    @staticmethod
    def _thread_local(name, default=None):
        try:
            return getattr(ProxyListenerDynamoDB.thread_local, name)
        except AttributeError:
            return default


def get_sse_description(data):
    return {
        "Status": "ENABLED" if data["Enabled"] else "UPDATING",
        "SSEType": data["SSEType"] if data["Enabled"] else None,
        "KMSMasterKeyArn": aws_stack.kms_key_arn(data["KMSMasterKeyId"])
        if data["Enabled"]
        else None,
    }


def handle_special_request(method, path, data, headers):
    if path.startswith("/shell") or method == "GET":
        if path == "/shell":
            headers = {"Refresh": "0; url=%s/shell/" % config.TEST_DYNAMODB_URL}
            return aws_responses.requests_response("", headers=headers)
        return True

    if method == "OPTIONS":
        return 200


def create_global_table(data):
    table_name = data["GlobalTableName"]
    if table_name in DynamoDBRegion.GLOBAL_TABLES:
        return get_error_message(
            "Global Table with this name already exists",
            "GlobalTableAlreadyExistsException",
        )
    DynamoDBRegion.GLOBAL_TABLES[table_name] = data
    for group in data.get("ReplicationGroup", []):
        group["ReplicaStatus"] = "ACTIVE"
        group["ReplicaStatusDescription"] = "Replica active"
    result = {"GlobalTableDescription": data}
    return result


def describe_global_table(data):
    table_name = data["GlobalTableName"]
    details = DynamoDBRegion.GLOBAL_TABLES.get(table_name)
    if not details:
        return get_error_message(
            "Global Table with this name does not exist", "GlobalTableNotFoundException"
        )
    result = {"GlobalTableDescription": details}
    return result


def list_global_tables(data):
    result = [
        select_attributes(tab, ["GlobalTableName", "ReplicationGroup"])
        for tab in DynamoDBRegion.GLOBAL_TABLES.values()
    ]
    result = {"GlobalTables": result}
    return result


def update_global_table(data):
    table_name = data["GlobalTableName"]
    details = DynamoDBRegion.GLOBAL_TABLES.get(table_name)
    if not details:
        return get_error_message(
            "Global Table with this name does not exist", "GlobalTableNotFoundException"
        )
    for update in data.get("ReplicaUpdates", []):
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
    result = {"GlobalTableDescription": details}
    return result


def is_index_query_valid(table_name, index_query_type):
    schema = get_table_schema(table_name)
    for index in schema["Table"].get("GlobalSecondaryIndexes", []):
        index_projection_type = index.get("Projection").get("ProjectionType")
        if index_query_type == "ALL_ATTRIBUTES" and index_projection_type != "ALL":
            return False
    return True


def has_event_sources_or_streams_enabled(table_name, cache={}):
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
    cache[table_arn] = result
    # if kinesis streaming destination is enabled
    # get table name from table_arn
    # since batch_wrtie and transact write operations passing table_arn instead of table_name
    table_name = table_arn.split("/", 1)[-1]
    table_definitions = DynamoDBRegion.get().table_definitions
    if not result and table_definitions.get(table_name):
        if table_definitions[table_name].get("KinesisDataStreamDestinationStatus") == "ACTIVE":
            result = True
    return result


def get_table_schema(table_name):
    key = "%s/%s" % (aws_stack.get_region(), table_name)
    schema = SCHEMA_CACHE.get(key)
    if not schema:
        ddb_client = aws_stack.connect_to_service("dynamodb")
        schema = ddb_client.describe_table(TableName=table_name)
        SCHEMA_CACHE[key] = schema
    return schema


def find_existing_item(put_item, table_name=None):
    table_name = table_name or put_item["TableName"]
    ddb_client = aws_stack.connect_to_service("dynamodb")

    search_key = {}
    if "Key" in put_item:
        search_key = put_item["Key"]
    else:
        schema = get_table_schema(table_name)
        schemas = [schema["Table"]["KeySchema"]]
        for index in schema["Table"].get("GlobalSecondaryIndexes", []):
            # TODO
            # schemas.append(index['KeySchema'])
            pass
        for schema in schemas:
            for key in schema:
                key_name = key["AttributeName"]
                search_key[key_name] = put_item["Item"][key_name]
        if not search_key:
            return

    req = {"TableName": table_name, "Key": search_key}
    existing_item = aws_stack.dynamodb_get_item_raw(req)
    if not existing_item:
        return existing_item
    if "Item" not in existing_item:
        if "message" in existing_item:
            table_names = ddb_client.list_tables()["TableNames"]
            msg = "Unable to get item from DynamoDB (existing tables: %s ...truncated if >100 tables): %s" % (
                table_names,
                existing_item["message"],
            )
            LOGGER.warning(msg)
        return
    return existing_item.get("Item")


def get_error_message(message, error_type):
    response = error_response(message=message, error_type=error_type)
    fix_headers_for_updated_response(response)
    return response


def get_table_not_found_error():
    return get_error_message(
        message="Cannot do operations on a non-existent table",
        error_type="ResourceNotFoundException",
    )


def fix_headers_for_updated_response(response):
    response.headers["Content-Length"] = len(to_bytes(response.content))
    response.headers["x-amz-crc32"] = calculate_crc32(response)


def update_response_content(response, content, status_code=None):
    aws_responses.set_response_content(response, content)
    if status_code:
        response.status_code = status_code
    fix_headers_for_updated_response(response)


def update_put_item_response_content(data, response_content):
    # when return-values variable is set only then attribute data should be returned
    # in the response otherwise by default is should not return any data.
    # https://github.com/localstack/localstack/issues/2121
    if data.get("ReturnValues"):
        response_content = json.dumps({"Attributes": data["Item"]})
    return response_content


def calculate_crc32(response):
    return crc32(to_bytes(response.content)) & 0xFFFFFFFF


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


def forward_to_lambda(records):
    for record in records:
        sources = lambda_api.get_event_sources(source_arn=record["eventSourceARN"])
        event = {"Records": [record]}
        for src in sources:
            if src.get("State") != "Enabled":
                continue
            lambda_api.run_lambda(
                func_arn=src["FunctionArn"],
                event=event,
                context={},
                asynchronous=not config.SYNCHRONOUS_DYNAMODB_EVENTS,
            )


def forward_to_ddb_stream(records):
    dynamodbstreams_api.forward_events(records)


def forward_to_kinesis_stream(records):
    kinesis = aws_stack.connect_to_service("kinesis")
    table_definitions = DynamoDBRegion.get().table_definitions
    for record in records:
        if record.get("eventSourceARN"):
            table_name = record["eventSourceARN"].split("/", 1)[-1]
            table_def = table_definitions.get(table_name) or {}
            if table_def.get("KinesisDataStreamDestinationStatus") == "ACTIVE":
                stream_name = table_def["KinesisDataStreamDestinations"][-1]["StreamArn"].split(
                    "/", 1
                )[-1]
                record["tableName"] = table_name
                record.pop("eventSourceARN", None)
                record["dynamodb"].pop("StreamViewType", None)
                partition_key = list(
                    filter(lambda key: key["KeyType"] == "HASH", table_def["KeySchema"])
                )[0]["AttributeName"]
                kinesis.put_record(
                    StreamName=stream_name,
                    Data=json.dumps(record),
                    PartitionKey=partition_key,
                )


def dynamodb_extract_keys(item, table_name):
    result = {}
    table_definitions = DynamoDBRegion.get().table_definitions
    if table_name not in table_definitions:
        LOGGER.warning("Unknown table: %s not found in %s" % (table_name, table_definitions))
        return None

    for key in table_definitions[table_name]["KeySchema"]:
        attr_name = key["AttributeName"]
        if attr_name not in item:
            return error_response(
                error_type="ValidationException",
                message="One of the required keys was not given a value",
            )

        result[attr_name] = item[attr_name]

    return result


def dynamodb_get_table_stream_specification(table_name):
    try:
        return get_table_schema(table_name)["Table"].get("StreamSpecification")
    except Exception as e:
        LOGGER.info(
            "Unable to get stream specification for table %s : %s %s"
            % (table_name, e, traceback.format_exc())
        )
        raise e


def is_kinesis_stream_exists(stream_arn):
    # connect to kinesis
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


def dynamodb_enable_kinesis_streaming_destination(data, table_def):
    if table_def.get("KinesisDataStreamDestinationStatus") in [
        "DISABLED",
        "ENABLE_FAILED",
        None,
    ]:
        table_def["KinesisDataStreamDestinations"] = (
            table_def.get("KinesisDataStreamDestinations") or []
        )
        # remove the stream destination if already present
        table_def["KinesisDataStreamDestinations"] = [
            t
            for t in table_def["KinesisDataStreamDestinations"]
            if t["StreamArn"] != data["StreamArn"]
        ]
        # append the active stream destination at the end of the list
        table_def["KinesisDataStreamDestinations"].append(
            {
                "DestinationStatus": "ACTIVE",
                "DestinationStatusDescription": "Stream is active",
                "StreamArn": data["StreamArn"],
            }
        )
        table_def["KinesisDataStreamDestinationStatus"] = "ACTIVE"
        response = aws_responses.requests_response(
            {
                "DestinationStatus": "ACTIVE",
                "StreamArn": data["StreamArn"],
                "TableName": data["TableName"],
            }
        )
        return response

    return error_response(
        error_type="ValidationException",
        message="Table is not in a valid state to enable Kinesis Streaming "
        "Destination:EnableKinesisStreamingDestination must be DISABLED or ENABLE_FAILED "
        "to perform ENABLE operation.",
    )


def dynamodb_disable_kinesis_streaming_destination(data, table_def):
    if table_def.get("KinesisDataStreamDestinations"):
        if table_def["KinesisDataStreamDestinationStatus"] == "ACTIVE":

            for dest in table_def["KinesisDataStreamDestinations"]:
                if dest["StreamArn"] == data["StreamArn"] and dest["DestinationStatus"] == "ACTIVE":
                    dest["DestinationStatus"] = "DISABLED"
                    dest["DestinationStatusDescription"] = ("Stream is disabled",)

                    table_def["KinesisDataStreamDestinationStatus"] = "DISABLED"
                    response = aws_responses.requests_response(
                        {
                            "DestinationStatus": "DISABLED",
                            "StreamArn": data["StreamArn"],
                            "TableName": data["TableName"],
                        }
                    )
                    return response
    return error_response(
        error_type="ValidationException",
        message="Table is not in a valid state to disable Kinesis Streaming Destination:"
        "DisableKinesisStreamingDestination must be ACTIVE to perform DISABLE operation.",
    )


def error_response(message=None, error_type=None, code=400):
    if not message:
        message = "Unknown error"
    if not error_type:
        error_type = "UnknownError"
    if "com.amazonaws.dynamodb" not in error_type:
        error_type = "com.amazonaws.dynamodb.v20120810#%s" % error_type
    response = Response()
    response.status_code = code
    content = {"message": message, "__type": error_type}
    response._content = json.dumps(content)
    return response


def error_response_throughput():
    message = (
        "The level of configured provisioned throughput for the table was exceeded. "
        + "Consider increasing your provisioning level with the UpdateTable API"
    )
    error_type = "ProvisionedThroughputExceededException"
    return error_response(message, error_type)


# instantiate listener
UPDATE_DYNAMODB = ProxyListenerDynamoDB()
