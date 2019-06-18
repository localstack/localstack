import re
import logging
import json
import uuid
import base64
import codecs
import xmltodict
import collections
import botocore.config
import six
import datetime
import dateutil.parser
from six import iteritems
from six.moves.urllib import parse as urlparse
from botocore.client import ClientError
from requests.models import Response, Request
from localstack import config
from localstack.constants import DEFAULT_REGION
from localstack.config import HOSTNAME, HOSTNAME_EXTERNAL
from localstack.utils import persistence
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    short_uid, timestamp, TIMESTAMP_FORMAT_MILLIS, to_str, to_bytes, clone, md5, get_service_protocol)
from localstack.utils.analytics import event_publisher
from localstack.services.generic_proxy import ProxyListener
from localstack.services.s3 import multipart_content

# mappings for S3 bucket notifications
S3_NOTIFICATIONS = {}

# mappings for bucket CORS settings
BUCKET_CORS = {}

# mappings for bucket lifecycle settings
BUCKET_LIFECYCLE = {}

# set up logger
LOGGER = logging.getLogger(__name__)

# XML namespace constants
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'

# list of destination types for bucket notifications
NOTIFICATION_DESTINATION_TYPES = ('Queue', 'Topic', 'CloudFunction', 'LambdaFunction')


def event_type_matches(events, action, api_method):
    """ check whether any of the event types in `events` matches the
        given `action` and `api_method`, and return the first match. """
    for event in events:
        regex = event.replace('*', '[^:]*')
        action_string = 's3:%s:%s' % (action, api_method)
        match = re.match(regex, action_string)
        if match:
            return match
    return False


def filter_rules_match(filters, object_path):
    """ check whether the given object path matches all of the given filters """
    filters = filters or {}
    s3_filter = _get_s3_filter(filters)
    for rule in s3_filter.get('FilterRule', []):
        if rule['Name'] == 'prefix':
            if not prefix_with_slash(object_path).startswith(prefix_with_slash(rule['Value'])):
                return False
        elif rule['Name'] == 'suffix':
            if not object_path.endswith(rule['Value']):
                return False
        else:
            LOGGER.warning('Unknown filter name: "%s"' % rule['Name'])
    return True


def _get_s3_filter(filters):
    return filters.get('S3Key', filters.get('Key', {}))


def prefix_with_slash(s):
    return s if s[0] == '/' else '/%s' % s


def get_event_message(event_name, bucket_name, file_name='testfile.txt', version_id=None, file_size=1024):
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
            'requestParameters': {
                'sourceIPAddress': '127.0.0.1'  # TODO determine real source IP
            },
            'responseElements': {
                'x-amz-request-id': short_uid(),
                'x-amz-id-2': 'eftixk72aD6Ap51TnqcoF8eFidJG9Z/2'  # Amazon S3 host that processed the request
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
                    'versionId': version_id,
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


def send_notifications(method, bucket_name, object_path, version_id):
    for bucket, b_cfg in iteritems(S3_NOTIFICATIONS):
        if bucket == bucket_name:
            action = {'PUT': 'ObjectCreated', 'POST': 'ObjectCreated', 'DELETE': 'ObjectRemoved'}[method]
            # TODO: support more detailed methods, e.g., DeleteMarkerCreated
            # http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html
            if action == 'ObjectCreated' and method == 'POST':
                api_method = 'CompleteMultipartUpload'
            else:
                api_method = {'PUT': 'Put', 'POST': 'Post', 'DELETE': 'Delete'}[method]

            event_name = '%s:%s' % (action, api_method)
            if (event_type_matches(b_cfg['Event'], action, api_method) and
                    filter_rules_match(b_cfg.get('Filter'), object_path)):
                # send notification
                message = get_event_message(
                    event_name=event_name, bucket_name=bucket_name,
                    file_name=urlparse.urlparse(object_path[1:]).path,
                    version_id=version_id
                )
                message = json.dumps(message)
                if b_cfg.get('Queue'):
                    sqs_client = aws_stack.connect_to_service('sqs')
                    try:
                        queue_url = queue_url_for_arn(b_cfg['Queue'])
                        sqs_client.send_message(QueueUrl=queue_url, MessageBody=message)
                    except Exception as e:
                        LOGGER.warning('Unable to send notification for S3 bucket "%s" to SQS queue "%s": %s' %
                            (bucket_name, b_cfg['Queue'], e))
                if b_cfg.get('Topic'):
                    sns_client = aws_stack.connect_to_service('sns')
                    try:
                        sns_client.publish(TopicArn=b_cfg['Topic'], Message=message, Subject='Amazon S3 Notification')
                    except Exception:
                        LOGGER.warning('Unable to send notification for S3 bucket "%s" to SNS topic "%s".' %
                            (bucket_name, b_cfg['Topic']))
                # CloudFunction and LambdaFunction are semantically identical
                lambda_function_config = b_cfg.get('CloudFunction') or b_cfg.get('LambdaFunction')
                if lambda_function_config:
                    # make sure we don't run into a socket timeout
                    connection_config = botocore.config.Config(read_timeout=300)
                    lambda_client = aws_stack.connect_to_service('lambda', config=connection_config)
                    try:
                        lambda_client.invoke(FunctionName=lambda_function_config,
                                             InvocationType='Event', Payload=message)
                    except Exception:
                        LOGGER.warning('Unable to send notification for S3 bucket "%s" to Lambda function "%s".' %
                            (bucket_name, lambda_function_config))
                if not filter(lambda x: b_cfg.get(x), NOTIFICATION_DESTINATION_TYPES):
                    LOGGER.warning('Neither of %s defined for S3 notification.' %
                        '/'.join(NOTIFICATION_DESTINATION_TYPES))


def get_cors(bucket_name):
    response = Response()

    exists, code = bucket_exists(bucket_name)
    if not exists:
        response.status_code = code
        return response

    cors = BUCKET_CORS.get(bucket_name)
    if not cors:
        cors = {
            'CORSConfiguration': []
        }
    body = xmltodict.unparse(cors)
    response._content = body
    response.status_code = 200
    return response


def set_cors(bucket_name, cors):
    response = Response()

    exists, code = bucket_exists(bucket_name)
    if not exists:
        response.status_code = code
        return response

    if not isinstance(cors, dict):
        cors = xmltodict.parse(cors)
    BUCKET_CORS[bucket_name] = cors
    response.status_code = 200
    return response


def delete_cors(bucket_name):
    response = Response()

    exists, code = bucket_exists(bucket_name)
    if not exists:
        response.status_code = code
        return response

    BUCKET_CORS.pop(bucket_name, {})
    response.status_code = 200
    return response


def append_cors_headers(bucket_name, request_method, request_headers, response):
    cors = BUCKET_CORS.get(bucket_name)
    if not cors:
        return
    origin = request_headers.get('Origin', '')
    rules = cors['CORSConfiguration']['CORSRule']
    if not isinstance(rules, list):
        rules = [rules]
    for rule in rules:
        # add allow-origin header
        allowed_methods = rule.get('AllowedMethod', [])
        if request_method in allowed_methods:
            allowed_origins = rule.get('AllowedOrigin', [])
            for allowed in allowed_origins:
                if origin in allowed or re.match(allowed.replace('*', '.*'), origin):
                    response.headers['Access-Control-Allow-Origin'] = origin
                    if 'ExposeHeader' in rule:
                        expose_headers = rule['ExposeHeader']
                        response.headers['Access-Control-Expose-Headers'] = \
                            ','.join(expose_headers) if isinstance(expose_headers, list) else expose_headers
                    break


def append_last_modified_headers(response, content=None):
    """Add Last-Modified header with current time
    (if the response content is an XML containing <LastModified>, add that instead)"""

    time_format = '%a, %d %b %Y %H:%M:%S GMT'  # TimeFormat
    try:
        if content:
            last_modified_str = re.findall(r'<LastModified>(.*)</LastModified>', content)[0]
            last_modified_time_format = dateutil.parser.parse(last_modified_str).strftime(time_format)
            response.headers['Last-Modified'] = last_modified_time_format
    except TypeError as err:
        LOGGER.debug('No parsable content: %s' % err)
    except IndexError as err:
        LOGGER.debug('Found no <LastModified>(.*)</LastModified> inside response_content: %s' % err)
    except ValueError as err:
        LOGGER.error('Failed to parse LastModified: %s' % err)
    except Exception as err:
        LOGGER.error('Caught generic exception (parsing LastModified): %s' % err)
    # if cannot parse any LastModified, just continue

    try:
        if response.headers.get('Last-Modified', '') == '':
            response.headers['Last-Modified'] = datetime.datetime.now().strftime(time_format)
    except Exception as err:
        LOGGER.error('Caught generic exception (setting LastModified header): %s' % err)


def get_lifecycle(bucket_name):
    response = Response()
    lifecycle = BUCKET_LIFECYCLE.get(bucket_name)
    if not lifecycle:
        # TODO: check if bucket exists, otherwise return 404-like error
        lifecycle = {
            'LifecycleConfiguration': {}
        }
    body = xmltodict.unparse(lifecycle)
    response._content = body
    response.status_code = 200
    return response


def set_lifecycle(bucket_name, lifecycle):
    # TODO: check if bucket exists, otherwise return 404-like error
    if isinstance(to_str(lifecycle), six.string_types):
        lifecycle = xmltodict.parse(lifecycle)
    BUCKET_LIFECYCLE[bucket_name] = lifecycle
    response = Response()
    response.status_code = 200
    return response


def strip_chunk_signatures(data):
    # For clients that use streaming v4 authentication, the request contains chunk signatures
    # in the HTTP body (see example below) which we need to strip as moto cannot handle them
    #
    # 17;chunk-signature=6e162122ec4962bea0b18bc624025e6ae4e9322bdc632762d909e87793ac5921
    # <payload data ...>
    # 0;chunk-signature=927ab45acd82fc90a3c210ca7314d59fedc77ce0c914d79095f8cc9563cf2c70

    data_new = re.sub(b'(\r\n)?[0-9a-fA-F]+;chunk-signature=[0-9a-f]{64}(\r\n){,2}', b'',
        data, flags=re.MULTILINE | re.DOTALL)
    if data_new != data:
        # trim \r (13) or \n (10)
        for i in range(0, 2):
            if len(data_new) and data_new[0] in (10, 13):
                data_new = data_new[1:]
        for i in range(0, 6):
            if len(data_new) and data_new[-1] in (10, 13):
                data_new = data_new[:-1]
    return data_new


def bucket_exists(bucket_name):
    """Tests for the existence of the specified bucket. Returns the error code
    if the bucket does not exist (200 if the bucket does exist).
    """
    s3_client = aws_stack.connect_to_service('s3')
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as err:
        error_code = err.response.get('Error').get('Code')
        return False, error_code

    return True, 200


def check_content_md5(data, headers):
    actual = md5(strip_chunk_signatures(data))
    expected = headers['Content-MD5']
    try:
        expected = to_str(codecs.encode(base64.b64decode(expected), 'hex'))
    except Exception:
        expected = '__invalid__'
    if actual != expected:
        response = Response()
        result = {
            'Error': {
                'Code': 'InvalidDigest',
                'Message': 'The Content-MD5 you specified was invalid'
            }
        }
        response._content = xmltodict.unparse(result)
        response.status_code = 400
        return response


def expand_redirect_url(starting_url, key, bucket):
    """ Add key and bucket parameters to starting URL query string. """
    parsed = urlparse.urlparse(starting_url)
    query = collections.OrderedDict(urlparse.parse_qsl(parsed.query))
    query.update([('key', key), ('bucket', bucket)])

    redirect_url = urlparse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlparse.urlencode(query), None))

    return redirect_url


def get_bucket_name(path, headers):
    parsed = urlparse.urlparse(path)

    # try pick the bucket_name from the path
    bucket_name = parsed.path.split('/')[1]

    host = headers['host']

    # is the hostname not starting a bucket name?
    if host.startswith(HOSTNAME) or host.startswith(HOSTNAME_EXTERNAL):
        return bucket_name

    # matches the common endpoints like
    #     - '<bucket_name>.s3.<region>.amazonaws.com'
    #     - '<bucket_name>.s3-<region>.amazonaws.com.cn'
    common_pattern = re.compile(r'^(.+)\.s3[.\-][a-z]{2}-[a-z]+-[0-9]{1,}'
                                r'\.amazonaws\.com(\.[a-z]+)?$')
    # matches dualstack endpoints like
    #     - <bucket_name>.s3.dualstack.<region>.amazonaws.com'
    #     - <bucket_name>.s3.dualstack.<region>.amazonaws.com.cn'
    dualstack_pattern = re.compile(r'^(.+)\.s3\.dualstack\.[a-z]{2}-[a-z]+-[0-9]{1,}'
                                   r'\.amazonaws\.com(\.[a-z]+)?$')
    # matches legacy endpoints like
    #     - '<bucket_name>.s3.amazonaws.com'
    #     - '<bucket_name>.s3-external-1.amazonaws.com.cn'
    legacy_patterns = re.compile(r'^(.+)\.s3\.?(-external-1)?\.amazonaws\.com(\.[a-z]+)?$')

    # if any of the above patterns match, the first captured group
    # will be returned as the bucket name
    for pattern in [common_pattern, dualstack_pattern, legacy_patterns]:
        match = pattern.match(host)
        if match:
            bucket_name = match.groups()[0]
            break

    # we're either returning the original bucket_name,
    # or a pattern matched the host and we're returning that name instead
    return bucket_name


def handle_notification_request(bucket, method, data):
    response = Response()
    response.status_code = 200
    response._content = ''
    if method == 'GET':
        # TODO check if bucket exists
        result = '<NotificationConfiguration xmlns="%s">' % XMLNS_S3
        if bucket in S3_NOTIFICATIONS:
            notif = S3_NOTIFICATIONS[bucket]
            for dest in NOTIFICATION_DESTINATION_TYPES:
                if dest in notif:
                    dest_dict = {
                        '%sConfiguration' % dest: {
                            'Id': uuid.uuid4(),
                            dest: notif[dest],
                            'Event': notif['Event'],
                            'Filter': notif['Filter']
                        }
                    }
                    result += xmltodict.unparse(dest_dict, full_document=False)
        result += '</NotificationConfiguration>'
        response._content = result

    if method == 'PUT':
        parsed = xmltodict.parse(data)
        notif_config = parsed.get('NotificationConfiguration')
        S3_NOTIFICATIONS.pop(bucket, None)
        for dest in NOTIFICATION_DESTINATION_TYPES:
            config = notif_config.get('%sConfiguration' % (dest))
            if config:
                events = config.get('Event')
                if isinstance(events, six.string_types):
                    events = [events]
                event_filter = config.get('Filter', {})
                # make sure FilterRule is an array
                s3_filter = _get_s3_filter(event_filter)
                if s3_filter and not isinstance(s3_filter.get('FilterRule', []), list):
                    s3_filter['FilterRule'] = [s3_filter['FilterRule']]
                # create final details dict
                notification_details = {
                    'Id': config.get('Id'),
                    'Event': events,
                    dest: config.get(dest),
                    'Filter': event_filter
                }
                # TODO: what if we have multiple destinations - would we overwrite the config?
                S3_NOTIFICATIONS[bucket] = clone(notification_details)
    return response


class ProxyListenerS3(ProxyListener):

    def forward_request(self, method, path, data, headers):

        # Make sure we use 'localhost' as forward host, to ensure moto uses path style addressing.
        # Note that all S3 clients using LocalStack need to enable path style addressing.
        if 's3.amazonaws.com' not in headers.get('host', ''):
            headers['host'] = 'localhost'

        # check content md5 hash integrity
        if 'Content-MD5' in headers:
            response = check_content_md5(data, headers)
            if response is not None:
                return response

        modified_data = None

        # TODO: For some reason, moto doesn't allow us to put a location constraint on us-east-1
        to_find = to_bytes('<LocationConstraint>us-east-1</LocationConstraint>')
        if data and data.startswith(to_bytes('<')) and to_find in data:
            modified_data = data.replace(to_find, to_bytes(''))

        # If this request contains streaming v4 authentication signatures, strip them from the message
        # Related isse: https://github.com/localstack/localstack/issues/98
        # TODO we should evaluate whether to replace moto s3 with scality/S3:
        # https://github.com/scality/S3/issues/237
        if headers.get('x-amz-content-sha256') == 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD':
            modified_data = strip_chunk_signatures(modified_data or data)
            headers['content-length'] = headers.get('x-amz-decoded-content-length')

        # POST requests to S3 may include a "${filename}" placeholder in the
        # key, which should be replaced with an actual file name before storing.
        if method == 'POST':
            original_data = modified_data or data
            expanded_data = multipart_content.expand_multipart_filename(original_data, headers)
            if expanded_data is not original_data:
                modified_data = expanded_data

        # If no content-type is provided, 'binary/octet-stream' should be used
        # src: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
        if method == 'PUT' and not headers.get('content-type'):
            headers['content-type'] = 'binary/octet-stream'

        # persist this API call to disk
        persistence.record('s3', method, path, data, headers)

        # parse query params
        parsed = urlparse.urlparse(path)
        query = parsed.query
        path = parsed.path
        bucket = path.split('/')[1]
        query_map = urlparse.parse_qs(query, keep_blank_values=True)
        if query == 'notification' or 'notification' in query_map:
            # handle and return response for ?notification request
            response = handle_notification_request(bucket, method, data)
            return response

        if query == 'cors' or 'cors' in query_map:
            if method == 'GET':
                return get_cors(bucket)
            if method == 'PUT':
                return set_cors(bucket, data)
            if method == 'DELETE':
                return delete_cors(bucket)

        if query == 'lifecycle' or 'lifecycle' in query_map:
            if method == 'GET':
                return get_lifecycle(bucket)
            if method == 'PUT':
                return set_lifecycle(bucket, data)

        if modified_data is not None:
            return Request(data=modified_data, headers=headers, method=method)
        return True

    def return_response(self, method, path, data, headers, response):

        path = to_str(path)
        method = to_str(method)
        bucket_name = get_bucket_name(path, headers)

        # No path-name based bucket name? Try host-based
        hostname_parts = headers['host'].split('.')
        if (not bucket_name or len(bucket_name) == 0) and len(hostname_parts) > 1:
            bucket_name = hostname_parts[0]

        # POST requests to S3 may include a success_action_redirect field,
        # which should be used to redirect a client to a new location.
        key = None
        if method == 'POST':
            key, redirect_url = multipart_content.find_multipart_redirect_url(data, headers)

            if key and redirect_url:
                response.status_code = 303
                response.headers['Location'] = expand_redirect_url(redirect_url, key, bucket_name)
                LOGGER.debug('S3 POST {} to {}'.format(response.status_code, response.headers['Location']))

        parsed = urlparse.urlparse(path)
        bucket_name_in_host = headers['host'].startswith(bucket_name)

        should_send_notifications = all([
            method in ('PUT', 'POST', 'DELETE'),
            '/' in path[1:] or bucket_name_in_host,
            # check if this is an actual put object request, because it could also be
            # a put bucket request with a path like this: /bucket_name/
            bucket_name_in_host or (len(path[1:].split('/')) > 1 and len(path[1:].split('/')[1]) > 0),
            self.is_query_allowable(method, parsed.query)
        ])

        # get subscribers and send bucket notifications
        if should_send_notifications:
            # if we already have a good key, use it, otherwise examine the path
            if key:
                object_path = '/' + key
            elif bucket_name_in_host:
                object_path = parsed.path
            else:
                parts = parsed.path[1:].split('/', 1)
                object_path = parts[1] if parts[1][0] == '/' else '/%s' % parts[1]
            version_id = response.headers.get('x-amz-version-id', None)

            send_notifications(method, bucket_name, object_path, version_id)

        # publish event for creation/deletion of buckets:
        if method in ('PUT', 'DELETE') and ('/' not in path[1:] or len(path[1:].split('/')[1]) <= 0):
            event_type = (event_publisher.EVENT_S3_CREATE_BUCKET if method == 'PUT'
                else event_publisher.EVENT_S3_DELETE_BUCKET)
            event_publisher.fire_event(event_type, payload={'n': event_publisher.get_hash(bucket_name)})

        # fix an upstream issue in moto S3 (see https://github.com/localstack/localstack/issues/382)
        if method == 'PUT' and parsed.query == 'policy':
            response._content = ''
            response.status_code = 204
            return response

        if response:
            reset_content_length = False

            # append CORS headers to response
            append_cors_headers(bucket_name, request_method=method, request_headers=headers, response=response)
            append_last_modified_headers(response=response)

            # Remove body from PUT response on presigned URL
            # https://github.com/localstack/localstack/issues/1317
            if method == 'PUT' and ('X-Amz-Security-Token=' in path or 'AWSAccessKeyId=' in path):
                response._content = ''
                reset_content_length = True

            response_content_str = None
            try:
                response_content_str = to_str(response._content)
            except Exception:
                pass

            # We need to un-pretty-print the XML, otherwise we run into this issue with Spark:
            # https://github.com/jserver/mock-s3/pull/9/files
            # https://github.com/localstack/localstack/issues/183
            # Note: yet, we need to make sure we have a newline after the first line: <?xml ...>\n
            if response_content_str and response_content_str.startswith('<'):
                is_bytes = isinstance(response._content, six.binary_type)

                append_last_modified_headers(response=response, content=response_content_str)

                # un-pretty-print the XML
                response._content = re.sub(r'([^\?])>\n\s*<', r'\1><', response_content_str, flags=re.MULTILINE)

                # update Location information in response payload
                response._content = self._update_location(response._content, bucket_name)

                # convert back to bytes
                if is_bytes:
                    response._content = to_bytes(response._content)

                # fix content-type: https://github.com/localstack/localstack/issues/618
                #                   https://github.com/localstack/localstack/issues/549
                if 'text/html' in response.headers.get('Content-Type', ''):
                    response.headers['Content-Type'] = 'application/xml; charset=utf-8'

                reset_content_length = True

            # update content-length headers (fix https://github.com/localstack/localstack/issues/541)
            if method == 'DELETE':
                reset_content_length = True

            if reset_content_length:
                response.headers['content-length'] = len(response._content)

    def _update_location(self, content, bucket_name):
        host = config.HOSTNAME_EXTERNAL
        if ':' not in host:
            host = '%s:%s' % (host, config.PORT_S3)
        return re.sub(r'<Location>\s*([a-zA-Z0-9\-]+)://[^/]+/([^<]+)\s*</Location>',
            r'<Location>%s://%s/%s/\2</Location>' % (get_service_protocol(), host, bucket_name),
            content, flags=re.MULTILINE)

    @staticmethod
    def is_query_allowable(method, query):
        # Generally if there is a query (some/path/with?query) we don't want to send notifications
        if not query:
            return True
        # Except we do want to notify on a multipart upload completion, which does use a query.
        elif method == 'POST' and query.startswith('uploadId'):
            return True


# instantiate listener
UPDATE_S3 = ProxyListenerS3()
