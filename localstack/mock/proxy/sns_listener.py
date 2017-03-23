import urlparse
import logging
from requests.models import Response
from localstack.utils.aws import aws_stack

# mappings for SNS topic subscriptions
SNS_SUBSCRIPTIONS = {}

# set up logger
LOGGER = logging.getLogger(__name__)


def update_sns(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(data)
            topic_arn = req_data.get('TopicArn')
            if topic_arn:
                topic_arn = topic_arn[0]
                if topic_arn not in SNS_SUBSCRIPTIONS:
                    SNS_SUBSCRIPTIONS[topic_arn] = []
            if 'Subscribe' in req_data['Action']:
                subscription = {
                    'topic_arn': topic_arn,
                    'endpoint': req_data['Endpoint'][0],
                    'protocol': req_data['Protocol'][0]
                }
                SNS_SUBSCRIPTIONS[topic_arn].append(subscription)
            elif 'Publish' in req_data['Action']:
                message = req_data['Message'][0]
                sqs_client = aws_stack.connect_to_service('sqs', client=True)
                for subscriber in SNS_SUBSCRIPTIONS[topic_arn]:
                    if subscriber['protocol'] == 'sqs':
                        queue_name = subscriber['endpoint'].split(':')[5]
                        queue_url = subscriber.get('sqs_queue_url')
                        if not queue_url:
                            queue_url = aws_stack.get_sqs_queue_url(queue_name)
                            subscriber['sqs_queue_url'] = queue_url
                        sqs_client.send_message(QueueUrl=queue_url, MessageBody=message)
                    else:
                        LOGGER.warning('Unexpected protocol "%s" for SNS subscription' % subscriber['protocol'])
                # return response here because we do not want the request to be forwarded to SNS
                response = Response()
                response._content = """<PublishResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
                    <PublishResult><MessageId>n/a</MessageId></PublishResult>
                    <ResponseMetadata><RequestId>n/a</RequestId></ResponseMetadata></PublishResponse>"""
                response.status_code = 200
                return response
        return True
