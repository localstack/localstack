import json
import traceback
import boto3.dynamodb.types
from localstack.utils.aws import aws_stack

KINESIS_STREAM_NAME = 'test-stream-1'


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
    raw_event_messages = []
    for record in event['Records']:
        # Deserialize into Python dictionary and extract the
        # "NewImage" (the new version of the full ddb document)
        ddb_new_image = deserialize_ddb_stream_event(record)

        # Place the raw event message document into the Kinesis message format
        kinesis_record = {
            'PartitionKey': 'key123',
            'Data': json.dumps(ddb_new_image)
        }

        raw_event_messages.append(kinesis_record)

    # Forward messages to Kinesis
    forward_events(raw_event_messages)


def deserialize_ddb_stream_event(ddb_stream_event):
    # Deserialize into Python dictionary and extract the "NewImage" (the new version of the full ddb document)
    ddb = ddb_stream_event['dynamodb']
    ddb_deserializer = TypeDeserializer()
    return ddb_deserializer.deserialize({'M': ddb['NewImage']})


def forward_events(records):
    kinesis_connection = aws_stack.connect_to_service('kinesis')
    kinesis_connection.put_records(StreamName=KINESIS_STREAM_NAME, Records=records)
