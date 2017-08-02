import re
import logging
import json
import uuid
import xmltodict
import xml.etree.ElementTree as ET
import six
from six import iteritems
from six.moves.urllib import parse as urlparse
from requests.models import Response, Request
from localstack.constants import *
from localstack.utils import persistence
from localstack.utils.aws import aws_stack
from localstack.utils.common import timestamp, TIMESTAMP_FORMAT_MILLIS, to_str, to_bytes
from localstack.utils.analytics import event_publisher
from localstack.services.generic_proxy import ProxyListener

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


def queue_url_for_arn(queue_arn):
    sqs_client = aws_stack.connect_to_service('sqs')
    parts = queue_arn.split(':')
    return sqs_client.get_queue_url(QueueName=parts[5],
        QueueOwnerAWSAccountId=parts[4])['QueueUrl']


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
                        queue_url = queue_url_for_arn(config['Queue'])
                        sqs_client.send_message(QueueUrl=queue_url, MessageBody=message)
                    except Exception as e:
                        LOGGER.warning('Unable to send notification for S3 bucket "%s" to SQS queue "%s".' %
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


class ProxyListenerS3(ProxyListener):

    def forward_request(self, method, path, data, headers):

        modified_data = None

        # If this request contains streaming v4 authentication signatures, strip them from the message
        # Related isse: https://github.com/localstack/localstack/issues/98
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
        if query == 'notification' or 'notification' in query_map:
            response = Response()
            response.status_code = 200
            if method == 'GET':
                # TODO check if bucket exists
                result = '<NotificationConfiguration xmlns="%s">' % XMLNS_S3
                if bucket in S3_NOTIFICATIONS:
                    notif = S3_NOTIFICATIONS[bucket]
                    for dest in ['Queue', 'Topic', 'CloudFunction']:
                        if dest in notif:
                            result += ('''<{dest}Configuration>
                                        <Id>{uid}</Id>
                                        <{dest}>{endpoint}</{dest}>
                                        <Event>{event}</Event>
                                    </{dest}Configuration>''').format(
                                dest=dest, uid=uuid.uuid4(),
                                endpoint=S3_NOTIFICATIONS[bucket][dest],
                                event=S3_NOTIFICATIONS[bucket]['Event'])
                result += '</NotificationConfiguration>'
                response._content = result

            if method == 'PUT':
                tree = ET.fromstring(data)
                for dest in ['Queue', 'Topic', 'CloudFunction']:
                    config = tree.find('{%s}%sConfiguration' % (XMLNS_S3, dest))
                    if config is not None and len(config):
                        # TODO: what if we have multiple destinations - would we overwrite the config?
                        S3_NOTIFICATIONS[bucket] = {
                            'Id': get_xml_text(config, 'Id'),
                            'Event': get_xml_text(config, 'Event', ns=XMLNS_S3),
                            # TODO extract 'Events' attribute (in addition to 'Event')
                            dest: get_xml_text(config, dest, ns=XMLNS_S3),
                        }

            # return response for ?notification request
            return response

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

    def return_response(self, method, path, data, headers, response):

        parsed = urlparse.urlparse(path)
        # TODO: consider the case of hostname-based (as opposed to path-based) bucket addressing
        bucket_name = parsed.path.split('/')[1]

        # get subscribers and send bucket notifications
        if method in ('PUT', 'DELETE') and '/' in path[1:]:
            parts = parsed.path[1:].split('/', 1)
            object_path = '/%s' % parts[1]
            send_notifications(method, bucket_name, object_path)
        # for creation/deletion of buckets, publish an event:
        if method in ('PUT', 'DELETE') and '/' not in path[1:]:
            event_type = (event_publisher.EVENT_S3_CREATE_BUCKET if method == 'PUT'
                else event_publisher.EVENT_S3_DELETE_BUCKET)
            event_publisher.fire_event(event_type, payload={'n': event_publisher.get_hash(bucket_name)})

        # append CORS headers to response
        if response:
            append_cors_headers(bucket_name, request_method=method, request_headers=headers, response=response)

            # we need to un-pretty-print the XML, otherwise we run into this issue with Spark:
            # https://github.com/jserver/mock-s3/pull/9/files
            # https://github.com/localstack/localstack/issues/183
            response_content_str = None
            try:
                response_content_str = to_str(response._content)
            except Exception as e:
                pass
            if response_content_str and response_content_str.startswith('<'):
                is_bytes = isinstance(response._content, six.binary_type)
                response._content = re.sub(r'>\n\s*<', '><', response_content_str, flags=re.MULTILINE)
                if is_bytes:
                    response._content = to_bytes(response._content)
                response.headers['content-length'] = len(response._content)


# instantiate listener
UPDATE_S3 = ProxyListenerS3()
