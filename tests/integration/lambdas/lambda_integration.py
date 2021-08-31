import base64
import json
import logging
import os
from io import BytesIO

import boto3.dynamodb.types

from localstack.utils.common import to_bytes, to_str

TEST_BUCKET_NAME = "test-bucket"
KINESIS_STREAM_NAME = "test_stream_1"
MSG_BODY_RAISE_ERROR_FLAG = "raise_error"
MSG_BODY_MESSAGE_TARGET = "message_target"

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

# TODO: should be injected by Lambda executor! (Doesn't seem to be the case for default python executor?)
os.environ["AWS_ACCESS_KEY_ID"] = os.environ.get("AWS_ACCESS_KEY_ID") or "test"
os.environ["AWS_SECRET_ACCESS_KEY"] = os.environ.get("AWS_SECRET_ACCESS_KEY") or "test"

ENDPOINT_URL = "http://%s:%s" % (
    os.environ["LOCALSTACK_HOSTNAME"],
    os.environ.get("EDGE_PORT", 4566),
)


# Subclass of boto's TypeDeserializer for DynamoDB
# to adjust for DynamoDB Stream format.
class TypeDeserializer(boto3.dynamodb.types.TypeDeserializer):
    def _deserialize_n(self, value):
        return float(value)

    def _deserialize_b(self, value):
        return value  # already in Base64


def handler(event, context):
    """Generic event forwarder Lambda."""

    # print test messages (to test CloudWatch Logs integration)
    LOGGER.info("Lambda log message - logging module")
    print("Lambda log message - print function")

    if MSG_BODY_RAISE_ERROR_FLAG in event:
        raise Exception("Test exception (this is intentional)")

    if "httpMethod" in event:
        # looks like this is a call from an AWS_PROXY API Gateway
        try:
            body = json.loads(event["body"])
        except Exception:
            body = {}

        body["path"] = event.get("path")
        body["resource"] = event.get("resource")
        body["pathParameters"] = event.get("pathParameters")
        body["requestContext"] = event.get("requestContext")
        body["queryStringParameters"] = event.get("queryStringParameters")
        body["httpMethod"] = event.get("httpMethod")
        body["body"] = event.get("body")
        body["headers"] = event.get("headers")
        if body["httpMethod"] == "DELETE":
            return {"statusCode": 204}

        # This parameter is often just completely excluded from the response.
        base64_response = {}
        is_base_64_encoded = body.get("return_is_base_64_encoded")
        if is_base_64_encoded is not None:
            base64_response["isBase64Encoded"] = is_base_64_encoded

        status_code = body.get("return_status_code", 200)
        headers = body.get("return_headers", {})
        body = body.get("return_raw_body") or body

        return {
            "body": body,
            "statusCode": status_code,
            "headers": headers,
            "multiValueHeaders": {"set-cookie": ["language=en-US", "theme=blue moon"]},
            **base64_response,
        }

    if "Records" not in event:
        result_map = {"event": event, "context": {}}
        result_map["context"]["invoked_function_arn"] = context.invoked_function_arn
        result_map["context"]["function_version"] = context.function_version
        result_map["context"]["function_name"] = context.function_name
        result_map["context"]["memory_limit_in_mb"] = context.memory_limit_in_mb
        result_map["context"]["aws_request_id"] = context.aws_request_id
        result_map["context"]["log_group_name"] = context.log_group_name
        result_map["context"]["log_stream_name"] = context.log_stream_name

        if hasattr(context, "client_context"):
            result_map["context"]["client_context"] = context.client_context

        return result_map

    raw_event_messages = []
    for record in event["Records"]:
        # Deserialize into Python dictionary and extract the
        # "NewImage" (the new version of the full ddb document)
        ddb_new_image = deserialize_event(record)

        if MSG_BODY_RAISE_ERROR_FLAG in ddb_new_image.get("data", {}):
            raise Exception("Test exception (this is intentional)")

        # Place the raw event message document into the Kinesis message format
        kinesis_record = {"PartitionKey": "key123", "Data": json.dumps(ddb_new_image)}

        if MSG_BODY_MESSAGE_TARGET in ddb_new_image.get("data", {}):
            forwarding_target = ddb_new_image["data"][MSG_BODY_MESSAGE_TARGET]
            target_name = forwarding_target.split(":")[-1]
            if forwarding_target.startswith("kinesis:"):
                ddb_new_image["data"][MSG_BODY_MESSAGE_TARGET] = "s3:test_chain_result"
                kinesis_record["Data"] = json.dumps(ddb_new_image["data"])
                forward_event_to_target_stream(kinesis_record, target_name)
            elif forwarding_target.startswith("s3:"):
                s3_client = connect_to_service("s3")
                test_data = to_bytes(json.dumps({"test_data": ddb_new_image["data"]["test_data"]}))
                s3_client.upload_fileobj(BytesIO(test_data), TEST_BUCKET_NAME, target_name)
        else:
            raw_event_messages.append(kinesis_record)

    # Forward messages to Kinesis
    forward_events(raw_event_messages)


def deserialize_event(event):
    # Deserialize into Python dictionary and extract the "NewImage" (the new version of the full ddb document)
    ddb = event.get("dynamodb")
    if ddb:
        result = {
            "__action_type": event.get("eventName"),
        }

        ddb_deserializer = TypeDeserializer()
        if ddb.get("OldImage"):
            result["old_image"] = ddb_deserializer.deserialize({"M": ddb.get("OldImage")})
        if ddb.get("NewImage"):
            result["new_image"] = ddb_deserializer.deserialize({"M": ddb.get("NewImage")})

        return result
    kinesis = event.get("kinesis")
    if kinesis:
        assert kinesis["sequenceNumber"]
        kinesis["data"] = json.loads(to_str(base64.b64decode(kinesis["data"])))
        return kinesis
    sqs = event.get("sqs")
    if sqs:
        result = {"data": event["body"]}
        return result
    sns = event.get("Sns")
    if sns:
        result = {"data": sns["Message"]}
        return result


def forward_events(records):
    if not records:
        return
    kinesis = connect_to_service("kinesis")
    kinesis.put_records(StreamName=KINESIS_STREAM_NAME, Records=records)


def forward_event_to_target_stream(record, stream_name):
    kinesis = connect_to_service("kinesis")
    kinesis.put_record(
        StreamName=stream_name, Data=record["Data"], PartitionKey=record["PartitionKey"]
    )


def connect_to_service(service):
    return boto3.client(service, endpoint_url=ENDPOINT_URL)
