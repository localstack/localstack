import json
import logging
import time
from typing import Dict

from localstack.services.generic_proxy import RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.common import now_utc

DDB_KINESIS_STREAM_NAME_PREFIX = "__ddb_stream_"

LOG = logging.getLogger(__name__)


class DynamoDBStreamsBackend(RegionBackend):
    SEQUENCE_NUMBER_COUNTER = 1
    # maps table names to DynamoDB stream details
    ddb_streams: Dict[str, Dict]

    def __init__(self):
        self.ddb_streams = {}


def add_dynamodb_stream(
    table_name, latest_stream_label=None, view_type="NEW_AND_OLD_IMAGES", enabled=True
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
            "StreamStatus": "ENABLING",
            "KeySchema": [],
            "Shards": [],
            "StreamViewType": view_type,
        }
        region.ddb_streams[table_name] = stream
        # record event
        event_publisher.fire_event(
            event_publisher.EVENT_DYNAMODB_CREATE_STREAM,
            payload={"n": event_publisher.get_hash(table_name)},
        )


def get_stream_for_table(table_arn):
    region = DynamoDBStreamsBackend.get()
    table_name = table_name_from_stream_arn(table_arn)
    return region.ddb_streams.get(table_name)


def forward_events(records):
    kinesis = aws_stack.connect_to_service("kinesis")
    for record in records:
        table_arn = record.pop("eventSourceARN", "")
        stream = get_stream_for_table(table_arn)
        if stream:
            table_name = table_name_from_stream_arn(stream["StreamArn"])
            stream_name = get_kinesis_stream_name(table_name)
            kinesis.put_record(StreamName=stream_name, Data=json.dumps(record), PartitionKey="TODO")


def delete_streams(table_arn):
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


def get_kinesis_stream_name(table_name):
    return DDB_KINESIS_STREAM_NAME_PREFIX + table_name


def table_name_from_stream_arn(stream_arn):
    return stream_arn.split(":table/", 1)[-1].split("/")[0]


def table_name_from_table_arn(table_arn):
    return table_name_from_stream_arn(table_arn)


def stream_name_from_stream_arn(stream_arn):
    table_name = table_name_from_stream_arn(stream_arn)
    return get_kinesis_stream_name(table_name)


def shard_id(kinesis_shard_id):
    timestamp = str(int(now_utc()))
    timestamp = "%s00000000" % timestamp[:-5]
    timestamp = "%s%s" % ("0" * (20 - len(timestamp)), timestamp)
    suffix = kinesis_shard_id.replace("shardId-", "")[:32]
    return "shardId-%s-%s" % (timestamp, suffix)


def kinesis_shard_id(dynamodbstream_shard_id):
    shard_params = dynamodbstream_shard_id.rsplit("-")
    return "{0}-{1}".format(shard_params[0], shard_params[-1])
