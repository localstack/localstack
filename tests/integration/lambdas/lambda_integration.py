import json
import traceback
import base64
import boto3.dynamodb.types
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str

KINESIS_STREAM_NAME = 'test-stream-1'
MSG_BODY_RAISE_ERROR_FLAG = 'raise_error'


# Subclass of boto's TypeDeserializer for DynamoDB
# to adjust for DynamoDB Stream format.
class TypeDeserializer(boto3.dynamodb.types.TypeDeserializer):
    def _deserialize_n(self, value):
        return float(value)

    def _deserialize_b(self, value):
        return value        # already in Base64


def handler(event, context):
    """
    DynamoDB (ddb) Stream to Kinesis forwarder Lambda.
    """
    if 'Records' not in event:
        return event

    raw_event_messages = []
    for record in event['Records']:
        # Deserialize into Python dictionary and extract the
        # "NewImage" (the new version of the full ddb document)
        ddb_new_image = deserialize_event(record)

        if MSG_BODY_RAISE_ERROR_FLAG in ddb_new_image['data']:
            raise Exception('Test exception (this is intentional)')

        # Place the raw event message document into the Kinesis message format
        kinesis_record = {
            'PartitionKey': 'key123',
            'Data': json.dumps(ddb_new_image)
        }

        raw_event_messages.append(kinesis_record)

    # Forward messages to Kinesis
    forward_events(raw_event_messages)


def deserialize_event(event):
    # Deserialize into Python dictionary and extract the "NewImage" (the new version of the full ddb document)
    ddb = event.get('dynamodb')
    if not ddb:
        result = event.get('kinesis')
        assert result['sequenceNumber']
        result['data'] = json.loads(to_str(base64.b64decode(result['data'])))
        return result
    ddb_deserializer = TypeDeserializer()
    return ddb_deserializer.deserialize({'M': ddb['NewImage']})


def forward_events(records):
    kinesis_connection = aws_stack.connect_to_service('kinesis')
    kinesis_connection.put_records(StreamName=KINESIS_STREAM_NAME, Records=records)
