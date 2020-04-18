import boto3
import os


def handler(event, context):
    protocol = 'https' if os.environ.get('USE_SSL') else 'http'
    sqs = boto3.client('sqs',
                       verify=False,
                       endpoint_url='{}://{}:4576'.format(protocol, os.environ['LOCALSTACK_HOSTNAME']))

    queue_url = sqs.get_queue_url(QueueName=event['queue_name'])['QueueUrl']
    rs = sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=event['message']
    )

    return rs['MessageId']
