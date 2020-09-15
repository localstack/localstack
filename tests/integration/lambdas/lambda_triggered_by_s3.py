import boto3
import os
import uuid

# TODO - merge this file with lambda_send_message.py, to avoid duplication

EDGE_PORT = 4566


def handler(event, context):
    # Parse s3 event
    r = event['Records'][0]

    region = r['awsRegion']
    s3_metadata = r['s3']['object']
    table_name = s3_metadata['key']

    protocol = 'https' if os.environ.get('USE_SSL') else 'http'
    endpoint_url = '{}://{}:{}'.format(protocol, os.environ['LOCALSTACK_HOSTNAME'], EDGE_PORT)
    ddb = boto3.resource('dynamodb', endpoint_url=endpoint_url, region_name=region, verify=False)

    ddb.Table(table_name).put_item(
        Item={
            'uuid': str(uuid.uuid4())[0:8],
            'data': r
        }
    )
