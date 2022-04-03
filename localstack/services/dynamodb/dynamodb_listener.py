import copy
import json
import logging
import traceback
from typing import Dict, List

from localstack import config
from localstack.services.awslambda import lambda_api
from localstack.services.dynamodb.utils import ItemFinder, ItemSet, SchemaExtractor, calculate_crc32
from localstack.services.dynamodbstreams import dynamodbstreams_api
from localstack.services.generic_proxy import ProxyListener, RegionBackend
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, to_bytes
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


class DynamoDBRegion(RegionBackend):
    # maps global table names to configurations
    GLOBAL_TABLES: Dict[str, Dict] = {}
    # cache table taggings - maps table ARN to tags dict
    TABLE_TAGS: Dict[str, Dict] = {}
    # maps table names to cached table definitions
    table_definitions: Dict[str, Dict]
    # maps table names to additional table properties that are not stored upstream (e.g., ReplicaUpdates)
    table_properties: Dict[str, Dict]
    # maps table names to TTL specifications
    ttl_specifications: Dict[str, Dict]

    def __init__(self):
        self.table_definitions = {}
        self.table_properties = {}
        self.ttl_specifications = {}


class EventForwarder:
    @classmethod
    def forward_to_targets(cls, records: List[Dict], background: bool = True):
        def _forward(*args):
            # forward to kinesis stream
            records_to_kinesis = copy.deepcopy(records)
            cls.forward_to_kinesis_stream(records_to_kinesis)

            # forward to lambda and ddb_streams
            forward_records = cls.prepare_records_to_forward_to_ddb_stream(records)
            cls.forward_to_ddb_stream(forward_records)
            # lambda receives the same records as the ddb streams
            cls.forward_to_lambda(forward_records)

        if background:
            return start_worker_thread(_forward)
        _forward()

    @staticmethod
    def forward_to_lambda(records):
        for record in records:
            sources = lambda_api.get_event_sources(source_arn=record.get("eventSourceARN"))
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

    @staticmethod
    def forward_to_ddb_stream(records):
        dynamodbstreams_api.forward_events(records)

    @staticmethod
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

    @classmethod
    def prepare_records_to_forward_to_ddb_stream(cls, records):
        # StreamViewType determines what information is written to the stream for the table
        # When an item in the table is inserted, updated or deleted
        for record in records:
            record.pop("eventID", None)
            if record["dynamodb"].get("StreamViewType"):
                if "SequenceNumber" not in record["dynamodb"]:
                    record["dynamodb"]["SequenceNumber"] = str(
                        dynamodbstreams_api.DynamoDBStreamsBackend.SEQUENCE_NUMBER_COUNTER
                    )
                    dynamodbstreams_api.DynamoDBStreamsBackend.SEQUENCE_NUMBER_COUNTER += 1
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


class ProxyListenerDynamoDB(ProxyListener):
    pass


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


# ---
# Misc. util functions (TODO: refactor/cleanup)
# ---


def get_global_secondary_index(table_name, index_name):
    schema = SchemaExtractor.get_table_schema(table_name)
    for index in schema["Table"].get("GlobalSecondaryIndexes", []):
        if index["IndexName"] == index_name:
            return index
    raise Exception("Index not found")  # TODO: add proper exception handling


def is_index_query_valid(query_data: dict) -> bool:
    table_name = to_str(query_data["TableName"])
    index_name = to_str(query_data["IndexName"])
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
    # since batch_wrtie and transact write operations passing table_arn instead of table_name
    table_name = table_arn.split("/", 1)[-1]
    table_definitions = DynamoDBRegion.get().table_definitions
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
                "SizeBytes": len(json.dumps(item)),
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
