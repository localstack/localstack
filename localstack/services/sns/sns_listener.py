import json
import logging
import requests
from requests.models import Response
from six.moves.urllib import parse as urlparse
from localstack.services.awslambda import lambda_api
from localstack.utils.aws import aws_stack

# mappings for SNS topic subscriptions
SNS_SUBSCRIPTIONS = {}

# set up logger
LOGGER = logging.getLogger(__name__)


def update_sns(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(data)
            topic_arn = req_data.get('TargetArn') or req_data.get('TopicArn')
            if topic_arn:
                topic_arn = topic_arn[0]
                if topic_arn not in SNS_SUBSCRIPTIONS:
                    SNS_SUBSCRIPTIONS[topic_arn] = []
            if 'Subscribe' in req_data['Action']:
                subscription = {
                    # http://docs.aws.amazon.com/cli/latest/reference/sns/get-subscription-attributes.html
                    'TopicArn': topic_arn,
                    'Endpoint': req_data['Endpoint'][0],
                    'Protocol': req_data['Protocol'][0],
                    'RawMessageDelivery': 'false'
                }
                SNS_SUBSCRIPTIONS[topic_arn].append(subscription)
            elif 'Publish' in req_data['Action']:
                message = req_data['Message'][0]
                sqs_client = aws_stack.connect_to_service('sqs')
                for subscriber in SNS_SUBSCRIPTIONS[topic_arn]:
                    if subscriber['Protocol'] == 'sqs':
                        queue_name = subscriber['Endpoint'].split(':')[5]
                        queue_url = subscriber.get('sqs_queue_url')
                        if not queue_url:
                            queue_url = aws_stack.get_sqs_queue_url(queue_name)
                            subscriber['sqs_queue_url'] = queue_url
                        sqs_client.send_message(QueueUrl=queue_url,
                            MessageBody=create_sns_message_body(subscriber, req_data))
                    elif subscriber['Protocol'] == 'lambda':
                        lambda_api.process_sns_notification(
                            subscriber['Endpoint'],
                            topic_arn, message, subject=req_data.get('Subject')
                        )
                    elif subscriber['Protocol'] == 'http':
                        requests.post(
                            subscriber['Endpoint'],
                            headers={
                                'Content-Type': 'text/plain',
                                'x-amz-sns-message-type': 'Notification'
                            },
                            data=json.dumps({
                                'Type': 'Notification',
                                'Message': message,
                            })
                        )
                    else:
                        LOGGER.warning('Unexpected protocol "%s" for SNS subscription' % subscriber['Protocol'])
                # return response here because we do not want the request to be forwarded to SNS
                response = Response()
                response._content = """<PublishResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
                    <PublishResult><MessageId>n/a</MessageId></PublishResult>
                    <ResponseMetadata><RequestId>n/a</RequestId></ResponseMetadata></PublishResponse>"""
                response.status_code = 200
                return response
        return True


def create_sns_message_body(subscriber, req_data):
    message = req_data['Message'][0]
    subject = req_data.get('Subject', [None])[0]

    if subscriber['RawMessageDelivery'] == 'true':
        return message

    data = {}
    data['Type'] = 'Notification'
    data['Message'] = message
    data['TopicArn'] = subscriber['TopicArn']
    if subject is not None:
        data['Subject'] = subject
    attributes = get_message_attributes(req_data)
    if attributes:
        data['MessageAttributes'] = attributes
    return json.dumps(data)


def get_message_attributes(req_data):
    attributes = {}
    x = 1
    while True:
        name = req_data.get('MessageAttributes.entry.' + str(x) + ".Name", [None])[0]
        if name is not None:
            attribute = {}
            attribute['Type'] = req_data.get('MessageAttributes.entry.' + str(x) + ".Value.DataType", [None])[0]
            string_value = req_data.get('MessageAttributes.entry.' + str(x) + ".Value.StringValue", [None])[0]
            binary_value = req_data.get('MessageAttributes.entry.' + str(x) + ".Value.BinaryValue", [None])[0]
            if string_value is not None:
                attribute['Value'] = string_value
            elif binary_value is not None:
                attribute['Value'] = binary_value

            attributes[name] = attribute
            x += 1
        else:
            break

    return attributes
