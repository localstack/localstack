import re
import logging
import json
import xmltodict
import xml.etree.ElementTree as ET
import six
from six import iteritems
from six.moves.urllib import parse as urlparse
from requests.models import Response, Request
from localstack.constants import *
from localstack.utils import persistence
from localstack.utils.aws import aws_stack
from localstack.utils.common import timestamp, TIMESTAMP_FORMAT_MILLIS

# mappings for S3 bucket notifications
S3_NOTIFICATIONS = {}

# mappings for bucket CORS settings
BUCKET_CORS = {}

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
    for bucket, config in iteritems(S3_NOTIFICATIONS):
        if bucket == bucket_name:
            action = {'PUT': 'ObjectCreated', 'DELETE': 'ObjectRemoved'}[method]
            # TODO: support more detailed methods, e.g., DeleteMarkerCreated
            # http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html
            api_method = {'PUT': 'Put', 'DELETE': 'Delete'}[method]
            event_name = '%s:%s' % (action, api_method)
            if match_event(config['Event'], action, api_method):
                # send notification
                message = get_event_message(
                    event_name=event_name, bucket_name=bucket_name,
                    file_name=urlparse.urlparse(object_path[1:]).path
                )
                message = json.dumps(message)
                result = None
                if config.get('Queue'):
                    sqs_client = aws_stack.connect_to_service('sqs')
                    try:
                        sqs_client.send_message(QueueUrl=config['Queue'], MessageBody=message)
                    except Exception as e:
                        LOGGER.warning('Unable to send notification for bucket "%s" to SQS queue "%s".' %
                            (bucket_name, config['Queue']))
                if config.get('Topic'):
                    sns_client = aws_stack.connect_to_service('sns')
                    try:
                        sns_client.publish(TopicArn=config['Topic'], Message=message)
                    except Exception as e:
                        LOGGER.warning('Unable to send notification for S3 bucket "%s" to SNS topic "%s".' %
                            (bucket_name, config['Topic']))
                if config.get('CloudFunction'):
                    lambda_client = aws_stack.connect_to_service('lambda')
                    try:
                        lambda_client.invoke(FunctionName=config['CloudFunction'], Payload=message)
                    except Exception as e:
                        LOGGER.warning('Unable to send notification for S3 bucket "%s" to Lambda function "%s".' %
                            (bucket_name, config['CloudFunction']))
                if not filter(lambda x: config.get(x), ('Queue', 'Topic', 'CloudFunction')):
                    LOGGER.warning('Neither of Queue/Topic/CloudFunction defined for S3 notification.')


def get_xml_text(node, name, ns=None, default=None):
    if ns is not None:
        name = '{%s}%s' % (ns, name)
    child = node.find(name)
    if child is None:
        return default
    return child.text


def get_cors(bucket_name):
    response = Response()
    cors = BUCKET_CORS.get(bucket_name)
    if not cors:
        # TODO: check if bucket exists, otherwise return 404-like error
        cors = {
            'CORSConfiguration': []
        }
    body = xmltodict.unparse(cors)
    response._content = body
    response.status_code = 200
    return response


def set_cors(bucket_name, cors):
    # TODO: check if bucket exists, otherwise return 404-like error
    if isinstance(cors, six.string_types):
        cors = xmltodict.parse(cors)
    BUCKET_CORS[bucket_name] = cors
    response = Response()
    response.status_code = 200
    return response


def delete_cors(bucket_name):
    # TODO: check if bucket exists, otherwise return 404-like error
    BUCKET_CORS.pop(bucket_name, {})
    response = Response()
    response.status_code = 200
    return response


def append_cors_headers(bucket_name, request_method, request_headers, response):
    cors = BUCKET_CORS.get(bucket_name)
    if not cors:
        return
    origin = request_headers.get('Origin', '')
    for rule in cors['CORSConfiguration']['CORSRule']:
        allowed_methods = rule.get('AllowedMethod', [])
        if request_method in allowed_methods:
            allowed_origins = rule.get('AllowedOrigin', [])
            for allowed in allowed_origins:
                if origin in allowed or re.match(allowed.replace('*', '.*'), origin):
                    response.headers['Access-Control-Allow-Origin'] = origin
                    break


def strip_chunk_signatures(data):
    # For clients that use streaming v4 authentication, the request contains chunk signatures
    # in the HTTP body (see example below) which we need to strip as moto cannot handle them
    #
    # 17;chunk-signature=6e162122ec4962bea0b18bc624025e6ae4e9322bdc632762d909e87793ac5921
    # <payload data ...>
    # 0;chunk-signature=927ab45acd82fc90a3c210ca7314d59fedc77ce0c914d79095f8cc9563cf2c70

    data_new = re.sub(r'^[0-9a-fA-F]+;chunk-signature=[0-9a-f]{64}', '', data, flags=re.MULTILINE)
    if data_new != data:
        # trim \r (13) or \n (10)
        for i in range(0, 2):
            if ord(data_new[0]) in (10, 13):
                data_new = data_new[1:]
        for i in range(0, 6):
            if ord(data_new[-1]) in (10, 13):
                data_new = data_new[:-1]
    return data_new


def update_s3(method, path, data, headers, response=None, return_forward_info=False):

    if return_forward_info:

        modified_data = None

        # If this request contains streaming v4 authentication signatures, strip them from the message
        # Related isse: https://github.com/atlassian/localstack/issues/98
        # TODO we should evaluate whether to replace moto s3 with scality/S3:
        # https://github.com/scality/S3/issues/237
        if headers.get('x-amz-content-sha256') == 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD':
            modified_data = strip_chunk_signatures(data)

        # persist this API call to disk
        persistence.record('s3', method, path, data, headers)

        parsed = urlparse.urlparse(path)
        query = parsed.query
        path = parsed.path
        bucket = path.split('/')[1]
        query_map = urlparse.parse_qs(query)
        if method == 'PUT' and (query == 'notification' or 'notification' in query_map):
            tree = ET.fromstring(data)
            for dest in ['Queue', 'Topic', 'CloudFunction']:
                config = tree.find('{%s}%sConfiguration' % (XMLNS_S3, dest))
                if config is not None and len(config):
                    S3_NOTIFICATIONS[bucket] = {
                        'Id': get_xml_text(config, 'Id'),
                        'Event': get_xml_text(config, 'Event', ns=XMLNS_S3),
                        dest: get_xml_text(config, dest, ns=XMLNS_S3),
                    }
        if query == 'cors' or 'cors' in query_map:
            if method == 'GET':
                return get_cors(bucket)
            if method == 'PUT':
                return set_cors(bucket, data)
            if method == 'DELETE':
                return delete_cors(bucket)

        if modified_data:
            return Request(data=modified_data, headers=headers, method=method)
        return True

    # get subscribers and send bucket notifications
    if method in ('PUT', 'DELETE') and '/' in path[1:]:
        parts = path[1:].split('/', 1)
        bucket_name = parts[0]
        object_path = '/%s' % parts[1]
        send_notifications(method, bucket_name, object_path)
    # append CORS headers to response
    if response:
        parsed = urlparse.urlparse(path)
        bucket_name = parsed.path.split('/')[0]
        append_cors_headers(bucket_name, request_method=method, request_headers=headers, response=response)
