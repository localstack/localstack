import boto3
import os


def handler(event, context):
    protocol = 'https' if os.environ.get('USE_SSL') else 'http'
    ddb = boto3.resource('dynamodb',
                         endpoint_url='{}://{}:4569'.format(protocol, os.environ['LOCALSTACK_HOSTNAME']),
                         region_name=event['region_name'],
                         verify=False)

    table_name = event['table_name']
    for item in event['items']:
        ddb.Table(table_name).put_item(Item=item)
