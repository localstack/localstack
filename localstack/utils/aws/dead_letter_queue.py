import json
import uuid
import logging

from json import JSONDecodeError
from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)


def sqs_error_to_dead_letter_queue(queue_arn, event, error):
    client = aws_stack.connect_to_service('sqs')
    queue_url = aws_stack.get_sqs_queue_url(queue_arn)
    attrs = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['RedrivePolicy'])
    attrs = attrs.get('Attributes', {})
    try:
        policy = json.loads(attrs.get('RedrivePolicy') or '{}')
    except JSONDecodeError:
        LOG.warning('Parsing RedrivePolicy {} failed, Queue: {}'.format(attrs.get('RedrivePolicy'), queue_arn))
        return

    target_arn = policy.get('deadLetterTargetArn')
    if not target_arn:
        return
    return _send_to_dead_letter_queue('SQS', queue_arn, target_arn, event, error)


def sns_error_to_dead_letter_queue(sns_subscriber_arn, event, error):
    client = aws_stack.connect_to_service('sns')
    attrs = client.get_subscription_attributes(SubscriptionArn=sns_subscriber_arn)
    attrs = attrs.get('Attributes', {})
    policy = json.loads(attrs.get('RedrivePolicy') or '{}')
    target_arn = policy.get('deadLetterTargetArn')
    if not target_arn:
        return
    return _send_to_dead_letter_queue('SQS', sns_subscriber_arn, target_arn, event, error)


def lambda_error_to_dead_letter_queue(func_details, event, error):
    dlq_arn = (func_details.dead_letter_config or {}).get('TargetArn')
    source_arn = func_details.id
    return _send_to_dead_letter_queue('Lambda', source_arn, dlq_arn, event, error)


def _send_to_dead_letter_queue(source_type, source_arn, dlq_arn, event, error):
    if not dlq_arn:
        return
    LOG.info('Sending failed execution %s to dead letter queue %s' % (source_arn, dlq_arn))
    message = json.dumps(event)
    message_attrs = {
        'RequestID': {'DataType': 'String', 'StringValue': str(uuid.uuid4())},
        'ErrorCode': {'DataType': 'String', 'StringValue': '200'},
        'ErrorMessage': {'DataType': 'String', 'StringValue': str(error)}
    }
    if ':sqs:' in dlq_arn:
        queue_url = aws_stack.get_sqs_queue_url(dlq_arn)
        sqs_client = aws_stack.connect_to_service('sqs')
        error = None
        result_code = None
        try:
            result = sqs_client.send_message(QueueUrl=queue_url, MessageBody=message, MessageAttributes=message_attrs)
            result_code = result.get('ResponseMetadata', {}).get('HTTPStatusCode')
        except Exception as e:
            error = e
        if error or not result_code or result_code >= 400:
            msg = 'Unable to send message to dead letter queue %s (code %s): %s' % (queue_url, result_code, error)
            LOG.info(msg)
            raise Exception(msg)
    elif ':sns:' in dlq_arn:
        sns_client = aws_stack.connect_to_service('sns')
        sns_client.publish(TopicArn=dlq_arn, Message=message, MessageAttributes=message_attrs)
    else:
        LOG.warning('Unsupported dead letter queue type: %s' % dlq_arn)
    return dlq_arn
