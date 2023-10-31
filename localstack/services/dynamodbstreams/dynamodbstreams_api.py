import contextlib
import logging
import threading
import time
from typing import Dict

from bson.json_util import dumps

from localstack.aws.api.dynamodbstreams import StreamStatus, StreamViewType
from localstack.aws.connect import connect_to
from localstack.services.dynamodbstreams.models import DynamoDbStreamsStore, dynamodbstreams_stores
from localstack.utils.aws import arns, resources
from localstack.utils.common import now_utc

DDB_KINESIS_STREAM_NAME_PREFIX = "__ddb_stream_"

LOG = logging.getLogger(__name__)

_SEQUENCE_MTX = threading.RLock()
_SEQUENCE_NUMBER_COUNTER = 1


def get_dynamodbstreams_store(account_id: str, region: str) -> DynamoDbStreamsStore:
    return dynamodbstreams_stores[account_id][region]


def get_and_increment_sequence_number_counter() -> int:
    global _SEQUENCE_NUMBER_COUNTER
    with _SEQUENCE_MTX:
        cnt = _SEQUENCE_NUMBER_COUNTER
        _SEQUENCE_NUMBER_COUNTER += 1
        return cnt


def add_dynamodb_stream(
    account_id: str,
    region_name: str,
    table_name: str,
    latest_stream_label: str | None = None,
    view_type: StreamViewType = StreamViewType.NEW_AND_OLD_IMAGES,
    enabled: bool = True,
) -> None:
    if not enabled:
        return

    store = get_dynamodbstreams_store(account_id, region_name)
    # create kinesis stream as a backend
    stream_name = get_kinesis_stream_name(table_name)
    resources.create_kinesis_stream(
        connect_to(aws_access_key_id=account_id, region_name=region_name).kinesis,
        stream_name=stream_name,
    )
    latest_stream_label = latest_stream_label or "latest"
    stream = {
        "StreamArn": arns.dynamodb_stream_arn(
            table_name=table_name,
            latest_stream_label=latest_stream_label,
            account_id=account_id,
            region_name=region_name,
        ),
        "TableName": table_name,
        "StreamLabel": latest_stream_label,
        "StreamStatus": StreamStatus.ENABLING,
        "KeySchema": [],
        "Shards": [],
        "StreamViewType": view_type,
        "shards_id_map": {},
    }
    store.ddb_streams[table_name] = stream


def get_stream_for_table(account_id: str, region_name: str, table_arn: str) -> dict:
    store = get_dynamodbstreams_store(account_id, region_name)
    table_name = table_name_from_stream_arn(table_arn)
    return store.ddb_streams.get(table_name)


def forward_events(account_id: str, region_name: str, records: dict) -> None:
    kinesis = connect_to(aws_access_key_id=account_id, region_name=region_name).kinesis
    for record in records:
        table_arn = record.pop("eventSourceARN", "")
        if stream := get_stream_for_table(account_id, region_name, table_arn):
            table_name = table_name_from_stream_arn(stream["StreamArn"])
            stream_name = get_kinesis_stream_name(table_name)
            kinesis.put_record(
                StreamName=stream_name,
                Data=dumps(record),
                PartitionKey="TODO",
            )


def delete_streams(account_id: str, region_name: str, table_arn: str) -> None:
    store = get_dynamodbstreams_store(account_id, region_name)
    table_name = table_name_from_table_arn(table_arn)
    if store.ddb_streams.pop(table_name, None):
        stream_name = get_kinesis_stream_name(table_name)
        with contextlib.suppress(Exception):
            connect_to(aws_access_key_id=account_id, region_name=region_name).kinesis.delete_stream(
                StreamName=stream_name
            )
            # sleep a bit, as stream deletion can take some time ...
            time.sleep(1)


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
