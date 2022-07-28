import json
import logging
import threading
import time
from typing import Dict

from localstack.aws.api.dynamodbstreams import StreamStatus, StreamViewType
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.common import now_utc
from localstack.utils.json import BytesEncoder

DDB_KINESIS_STREAM_NAME_PREFIX = "__ddb_stream_"

LOG = logging.getLogger(__name__)

_SEQUENCE_MTX = threading.RLock()
_SEQUENCE_NUMBER_COUNTER = 1


class DynamoDBStreamsBackend(RegionBackend):
    # maps table names to DynamoDB stream descriptions
    ddb_streams: Dict[str, dict]

    def __init__(self):
        self.ddb_streams = {}


def get_and_increment_sequence_number_counter() -> int:
    global _SEQUENCE_NUMBER_COUNTER
    with _SEQUENCE_MTX:
        cnt = _SEQUENCE_NUMBER_COUNTER
        _SEQUENCE_NUMBER_COUNTER += 1
        return cnt


def add_dynamodb_stream(
    table_name, latest_stream_label=None, view_type=StreamViewType.NEW_AND_OLD_IMAGES, enabled=True
):
    if enabled:
        region = DynamoDBStreamsBackend.get()
        # create kinesis stream as a backend
        stream_name = get_kinesis_stream_name(table_name)
        aws_stack.create_kinesis_stream(stream_name)
        latest_stream_label = latest_stream_label or "latest"
        stream = {
            "StreamArn": aws_stack.dynamodb_stream_arn(
                table_name=table_name, latest_stream_label=latest_stream_label
            ),
            "TableName": table_name,
            "StreamLabel": latest_stream_label,
            "StreamStatus": StreamStatus.ENABLING,
            "KeySchema": [],
            "Shards": [],
            "StreamViewType": view_type,
            "shards_id_map": {},
        }
        region.ddb_streams[table_name] = stream
        # record event
        event_publisher.fire_event(
            event_publisher.EVENT_DYNAMODB_CREATE_STREAM,
            payload={"n": event_publisher.get_hash(table_name)},
        )


def get_stream_for_table(table_arn: str) -> dict:
    region = DynamoDBStreamsBackend.get()
    table_name = table_name_from_stream_arn(table_arn)
    return region.ddb_streams.get(table_name)


def forward_events(records: Dict) -> None:
    kinesis = aws_stack.connect_to_service("kinesis")
    for record in records:
        table_arn = record.pop("eventSourceARN", "")
        stream = get_stream_for_table(table_arn)
        if stream:
            table_name = table_name_from_stream_arn(stream["StreamArn"])
            stream_name = get_kinesis_stream_name(table_name)
            kinesis.put_record(
                StreamName=stream_name,
                Data=json.dumps(record, cls=BytesEncoder),
                PartitionKey="TODO",
            )


def delete_streams(table_arn: str) -> None:
    region = DynamoDBStreamsBackend.get()
    table_name = table_name_from_table_arn(table_arn)
    stream = region.ddb_streams.pop(table_name, None)
    if stream:
        stream_name = get_kinesis_stream_name(table_name)
        try:
            aws_stack.connect_to_service("kinesis").delete_stream(StreamName=stream_name)
            # sleep a bit, as stream deletion can take some time ...
            time.sleep(1)
        except Exception:
            pass  # ignore "stream not found" errors


def get_kinesis_stream_name(table_name: str) -> str:
    return DDB_KINESIS_STREAM_NAME_PREFIX + table_name


def table_name_from_stream_arn(stream_arn: str) -> str:
    return stream_arn.split(":table/", 1)[-1].split("/")[0]


def table_name_from_table_arn(table_arn: str) -> str:
    return table_name_from_stream_arn(table_arn)


def stream_name_from_stream_arn(stream_arn: str) -> str:
    table_name = table_name_from_stream_arn(stream_arn)
    return get_kinesis_stream_name(table_name)


def shard_id(kinesis_shard_id: str) -> str:
    timestamp = str(int(now_utc()))
    timestamp = f"{timestamp[:-5]}00000000".rjust(20, "0")
    kinesis_shard_params = kinesis_shard_id.split("-")
    return f"{kinesis_shard_params[0]}-{timestamp}-{kinesis_shard_params[-1][:32]}"


def kinesis_shard_id(dynamodbstream_shard_id: str) -> str:
    shard_params = dynamodbstream_shard_id.rsplit("-")
    return f"{shard_params[0]}-{shard_params[-1]}"


def get_shard_id(stream: Dict, kinesis_shard_id: str) -> str:
    ddb_stream_shard_id = stream.get("shards_id_map", {}).get(kinesis_shard_id)
    if not ddb_stream_shard_id:
        ddb_stream_shard_id = shard_id(kinesis_shard_id)
        stream["shards_id_map"][kinesis_shard_id] = ddb_stream_shard_id

    return ddb_stream_shard_id
