import boto3


def handler(event, context):
    sqs = boto3.client('sqs', endpoint_url=event['sqs_endpoint_url'])
    rs = sqs.send_message(
        QueueUrl=event['queue_url'],
        MessageBody=event['message']
    )

    return rs['MessageId']
