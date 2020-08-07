import boto3
import os
import uuid


def handler(event, context):
    # Parse s3 event
    r = event['Records'][0]

    region = r['awsRegion']
    s3_metadata = r['s3']['object']
    table_name = s3_metadata['key']

    protocol = 'https' if os.environ.get('USE_SSL') else 'http'
    ddb = boto3.resource('dynamodb',
                         endpoint_url='{}://{}:4569'.format(protocol, os.environ['LOCALSTACK_HOSTNAME']),
                         region_name=region,
                         verify=False)

    ddb.Table(table_name).put_item(
        Item={
            'uuid': str(uuid.uuid4())[0:8],
            'data': r
        }
    )
