import json
import base64
import boto3.dynamodb.types
from io import BytesIO
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, to_bytes

TEST_BUCKET_NAME = 'test_bucket'
KINESIS_STREAM_NAME = 'test_stream_1'
MSG_BODY_RAISE_ERROR_FLAG = 'raise_error'
MSG_BODY_MESSAGE_TARGET = 'message_target'


# Subclass of boto's TypeDeserializer for DynamoDB
# to adjust for DynamoDB Stream format.
class TypeDeserializer(boto3.dynamodb.types.TypeDeserializer):
    def _deserialize_n(self, value):
        return float(value)

    def _deserialize_b(self, value):
        return value        # already in Base64


def handler(event, context):
    """ Generic event forwarder Lambda. """

    if 'httpMethod' in event:
        # looks like this is a call from an AWS_PROXY API Gateway
        body = json.loads(event['body'])
        body['pathParameters'] = event.get('pathParameters')
        return {
            'body': body,
            'statusCode': body.get('return_status_code', 200),
            'headers': body.get('return_headers', {})
        }

    if 'Records' not in event:
        return event

    raw_event_messages = []
    for record in event['Records']:
        # Deserialize into Python dictionary and extract the
        # "NewImage" (the new version of the full ddb document)
        ddb_new_image = deserialize_event(record)

        if MSG_BODY_RAISE_ERROR_FLAG in ddb_new_image.get('data', {}):
            raise Exception('Test exception (this is intentional)')

        # Place the raw event message document into the Kinesis message format
        kinesis_record = {
            'PartitionKey': 'key123',
            'Data': json.dumps(ddb_new_image)
        }

        if MSG_BODY_MESSAGE_TARGET in ddb_new_image.get('data', {}):
            forwarding_target = ddb_new_image['data'][MSG_BODY_MESSAGE_TARGET]
            target_name = forwarding_target.split(':')[-1]
            if forwarding_target.startswith('kinesis:'):
                ddb_new_image['data'][MSG_BODY_MESSAGE_TARGET] = 's3:/test_chain_result'
                kinesis_record['Data'] = json.dumps(ddb_new_image['data'])
                forward_event_to_target_stream(kinesis_record, target_name)
            elif forwarding_target.startswith('s3:'):
                s3_client = aws_stack.connect_to_service('s3')
                test_data = to_bytes(json.dumps({'test_data': ddb_new_image['data']['test_data']}))
                s3_client.upload_fileobj(BytesIO(test_data), TEST_BUCKET_NAME, target_name)
        else:
            raw_event_messages.append(kinesis_record)

    # Forward messages to Kinesis
    forward_events(raw_event_messages)


def deserialize_event(event):
    # Deserialize into Python dictionary and extract the "NewImage" (the new version of the full ddb document)
    ddb = event.get('dynamodb')
    if ddb:
        ddb_deserializer = TypeDeserializer()
        return ddb_deserializer.deserialize({'M': ddb['NewImage']})
    kinesis = event.get('kinesis')
    if kinesis:
        assert kinesis['sequenceNumber']
        kinesis['data'] = json.loads(to_str(base64.b64decode(kinesis['data'])))
        return kinesis
    return event.get('Sns')


def forward_events(records):
    if not records:
        return
    kinesis = aws_stack.connect_to_service('kinesis')
    kinesis.put_records(StreamName=KINESIS_STREAM_NAME, Records=records)


def forward_event_to_target_stream(record, stream_name):
    kinesis = aws_stack.connect_to_service('kinesis')
    kinesis.put_record(StreamName=stream_name, Data=record['Data'], PartitionKey=record['PartitionKey'])
