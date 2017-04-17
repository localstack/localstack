import re
import urlparse
import logging
import json
import xml.etree.ElementTree as ET
from requests.models import Response
from localstack.constants import *
from localstack.utils.aws import aws_stack
from localstack.utils.common import timestamp, TIMESTAMP_FORMAT_MILLIS

# mappings for S3 bucket notifications
S3_NOTIFICATIONS = {}

# set up logger
LOGGER = logging.getLogger(__name__)

# XML namespace constants
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'


def match_event(event, action, api_method):
    regex = event.replace('*', '[^:]*')
    action_string = 's3:%s:%s' % (action, api_method)
    return re.match(regex, action_string)


def get_event_message(event_name, bucket_name, file_name='testfile.txt', file_size=1024):
    # Based on: http://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
    return {
        'Records': [{
            'eventVersion': '2.0',
            'eventSource': 'aws:s3',
            'awsRegion': DEFAULT_REGION,
            'eventTime': timestamp(format=TIMESTAMP_FORMAT_MILLIS),
            'eventName': event_name,
            'userIdentity': {
                'principalId': 'AIDAJDPLRKLG7UEXAMPLE'
            },
            's3': {
                's3SchemaVersion': '1.0',
                'configurationId': 'testConfigRule',
                'bucket': {
                    'name': bucket_name,
                    'ownerIdentity': {
                        'principalId': 'A3NL1KOZZKExample'
                    },
                    'arn': 'arn:aws:s3:::%s' % bucket_name
                },
                'object': {
                    'key': file_name,
                    'size': file_size,
                    'eTag': 'd41d8cd98f00b204e9800998ecf8427e',
                    'versionId': '096fKKXTRTtl3on89fVO.nfljtsv6qko',
                    'sequencer': '0055AED6DCD90281E5'
                }
            }
        }]
    }


def send_notifications(method, bucket_name, object_path):
    for bucket, config in S3_NOTIFICATIONS.iteritems():
        if bucket == bucket_name:
            action = {'PUT': 'ObjectCreated', 'DELETE': 'ObjectRemoved'}[method]
            # TODO: support more detailed methods, e.g., DeleteMarkerCreated
            # http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html
            api_method = {'PUT': 'Put', 'DELETE': 'Delete'}[method]
            event_name = '%s:%s' % (action, api_method)
            if match_event(config['Event'], action, api_method):
                # send notification
                message = get_event_message(event_name=event_name, bucket_name=bucket_name)
                message = json.dumps(message)
                result = None
                if config.get('Queue'):
                    sqs_client = aws_stack.connect_to_service('sqs')
                    sqs_client.send_message(QueueUrl=config['Queue'], MessageBody=message)
                if config.get('Topic'):
                    sns_client = aws_stack.connect_to_service('sns')
                    sns_client.publish(TopicArn=config['Topic'], Message=message)
                if config.get('CloudFunction'):
                    lambda_client = aws_stack.connect_to_service('lambda')
                    lambda_client.invoke(FunctionName=config['CloudFunction'], Payload=message)
                if not filter(lambda x: config.get(x), ('Queue', 'Topic', 'CloudFunction')):
                    LOGGER.warn('Neither of Queue/Topic/CloudFunction defined for S3 notification.')


def get_xml_text(node, name, ns=None, default=None):
    if ns is not None:
        name = '{%s}%s' % (ns, name)
    child = node.find(name)
    if child is None:
        return default
    return child.text


def update_s3(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        parsed = urlparse.urlparse(path)
        query = parsed.query
        path = parsed.path
        query_map = urlparse.parse_qs(query)
        if method == 'PUT' and (query == 'notification' or 'notification' in query_map):
            tree = ET.fromstring(data)
            queue_config = tree.find('{%s}QueueConfiguration' % XMLNS_S3)
            if len(queue_config):
                bucket = path[1:]
                S3_NOTIFICATIONS[bucket] = {
                    'Id': get_xml_text(queue_config, 'Id'),
                    'Event': get_xml_text(queue_config, 'Event', ns=XMLNS_S3),
                    'Queue': get_xml_text(queue_config, 'Queue', ns=XMLNS_S3),
                    'Topic': get_xml_text(queue_config, 'Topic', ns=XMLNS_S3),
                    'CloudFunction': get_xml_text(queue_config, 'CloudFunction', ns=XMLNS_S3)
                }
        return True
    if method in ('PUT', 'DELETE') and '/' in path[1:]:
        parts = path[1:].split('/', 1)
        bucket_name = parts[0]
        object_path = '/%s' % parts[1]
        send_notifications(method, bucket_name, object_path)
