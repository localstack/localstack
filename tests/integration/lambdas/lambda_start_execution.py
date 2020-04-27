import boto3
import json
import os


def handler(event, context):
    protocol = 'https' if os.environ.get('USE_SSL') else 'http'
    sf = boto3.client('stepfunctions',
                      endpoint_url='{}://{}:4585'.format(protocol, os.environ['LOCALSTACK_HOSTNAME']),
                      region_name=event['region_name'],
                      verify=False)

    sf.start_execution(
        stateMachineArn=event['state_machine_arn'],
        input=json.dumps(event['input'])
    )

    return 0
