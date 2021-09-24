import json
import time
from typing import Dict

from flask import Flask, jsonify, make_response, request

from localstack.services import generic_proxy
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.common import now_utc, to_str

APP_NAME = "ddb_streams_api"
app = Flask(APP_NAME)

DDB_KINESIS_STREAM_NAME_PREFIX = "__ddb_stream_"

ACTION_HEADER_PREFIX = "DynamoDBStreams_20120810"


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
            "StreamStatus": "ENABLED",
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
        if "SequenceNumber" not in record["dynamodb"]:
            record["dynamodb"]["SequenceNumber"] = str(
                DynamoDBStreamsBackend.SEQUENCE_NUMBER_COUNTER
            )
            DynamoDBStreamsBackend.SEQUENCE_NUMBER_COUNTER += 1
        table_arn = record["eventSourceARN"]
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


@app.route("/", methods=["POST"])
def post_request():
    region = DynamoDBStreamsBackend.get()
    action = request.headers.get("x-amz-target", "")
    action = action.split(".")[-1]
    data = json.loads(to_str(request.data))
    result = {}
    kinesis = aws_stack.connect_to_service("kinesis")
    if action == "ListStreams":
        result = {"Streams": list(region.ddb_streams.values())}

    elif action == "DescribeStream":
        for stream in region.ddb_streams.values():
            if stream["StreamArn"] == data["StreamArn"]:
                result = {"StreamDescription": stream}
                # get stream details
                dynamodb = aws_stack.connect_to_service("dynamodb")
                table_name = table_name_from_stream_arn(stream["StreamArn"])
                stream_name = get_kinesis_stream_name(table_name)
                stream_details = kinesis.describe_stream(StreamName=stream_name)
                table_details = dynamodb.describe_table(TableName=table_name)
                stream["KeySchema"] = table_details["Table"]["KeySchema"]

                # Replace Kinesis ShardIDs with ones that mimic actual
                # DynamoDBStream ShardIDs.
                stream_shards = stream_details["StreamDescription"]["Shards"]
                for shard in stream_shards:
                    shard["ShardId"] = shard_id(stream_name, shard["ShardId"])
                stream["Shards"] = stream_shards
                break
        if not result:
            return error_response(
                "Requested resource not found", error_type="ResourceNotFoundException"
            )

    elif action == "GetShardIterator":
        # forward request to Kinesis API
        stream_name = stream_name_from_stream_arn(data["StreamArn"])
        stream_shard_id = kinesis_shard_id(data["ShardId"])

        kwargs = (
            {"StartingSequenceNumber": data["SequenceNumber"]} if data.get("SequenceNumber") else {}
        )
        result = kinesis.get_shard_iterator(
            StreamName=stream_name,
            ShardId=stream_shard_id,
            ShardIteratorType=data["ShardIteratorType"],
            **kwargs,
        )

    elif action == "GetRecords":
        kinesis_records = kinesis.get_records(**data)
        result = {
            "Records": [],
            "NextShardIterator": kinesis_records.get("NextShardIterator"),
        }
        for record in kinesis_records["Records"]:
            record_data = json.loads(to_str(record["Data"]))
            record_data["dynamodb"]["SequenceNumber"] = record["SequenceNumber"]
            result["Records"].append(record_data)
    else:
        print('WARNING: Unknown operation "%s"' % action)
    return jsonify(result)


# -----------------
# HELPER FUNCTIONS
# -----------------


def error_response(message=None, error_type=None, code=400):
    if not message:
        message = "Unknown error"
    if not error_type:
        error_type = "UnknownError"
    if "com.amazonaws.dynamodb" not in error_type:
        error_type = "com.amazonaws.dynamodb.v20120810#%s" % error_type
    content = {"message": message, "__type": error_type}
    return make_response(jsonify(content), code)


def get_kinesis_stream_name(table_name):
    return DDB_KINESIS_STREAM_NAME_PREFIX + table_name


def table_name_from_stream_arn(stream_arn):
    return stream_arn.split(":table/", 1)[-1].split("/")[0]


def table_name_from_table_arn(table_arn):
    return table_name_from_stream_arn(table_arn)


def stream_name_from_stream_arn(stream_arn):
    table_name = table_name_from_stream_arn(stream_arn)
    return get_kinesis_stream_name(table_name)


def shard_id(stream_arn, kinesis_shard_id):
    timestamp = str(int(now_utc()))
    timestamp = "%s00000000" % timestamp[:-5]
    timestamp = "%s%s" % ("0" * (20 - len(timestamp)), timestamp)
    suffix = kinesis_shard_id.replace("shardId-", "")[:32]
    return "shardId-%s-%s" % (timestamp, suffix)


def kinesis_shard_id(dynamodbstream_shard_id):
    shard_params = dynamodbstream_shard_id.rsplit("-")
    return "{0}-{1}".format(shard_params[0], shard_params[-1])


def serve(port, quiet=True):
    generic_proxy.serve_flask_app(app=app, port=port)
