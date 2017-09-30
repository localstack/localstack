import re
import logging
import json
import uuid
import xmltodict
import cgi
import email.parser
import collections
import six
from six import iteritems
from six.moves.urllib import parse as urlparse
from requests.models import Response, Request
from localstack.constants import DEFAULT_REGION
from localstack.utils import persistence
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, timestamp, TIMESTAMP_FORMAT_MILLIS, to_str, to_bytes
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
    key_filter = filters.get('S3Key', {})
    for rule in key_filter.get('FilterRule', []):
        if rule['Name'] == 'prefix':
            if not prefix_with_slash(object_path).startswith(prefix_with_slash(rule['Value'])):
                return False
        elif rule['Name'] == 'suffix':
            if not object_path.endswith(rule['Value']):
                return False
        else:
            LOGGER.warning('Unknown filter name: "%s"' % rule['Name'])
    return True


def prefix_with_slash(s):
    return s if s[0] == '/' else '/%s' % s


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
            if (event_type_matches(config['Event'], action, api_method) and
                    filter_rules_match(config.get('Filter'), object_path)):
                # send notification
                message = get_event_message(
                    event_name=event_name, bucket_name=bucket_name,
                    file_name=urlparse.urlparse(object_path[1:]).path
                )
                message = json.dumps(message)
                if config.get('Queue'):
                    sqs_client = aws_stack.connect_to_service('sqs')
                    try:
                        queue_url = queue_url_for_arn(config['Queue'])
                        sqs_client.send_message(QueueUrl=queue_url, MessageBody=message)
                    except Exception as e:
                        LOGGER.warning('Unable to send notification for S3 bucket "%s" to SQS queue "%s": %s' %
                            (bucket_name, config['Queue'], e))
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


def _iter_multipart_parts(some_bytes, boundary):
    """ Generate a stream of dicts and bytes for each message part.

        Content-Disposition is used as a header for a multipart body:
        https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition
    """
    try:
        parse_data = email.parser.BytesHeaderParser().parsebytes
    except AttributeError:
        # Fall back in case of Python 2.x
        parse_data = email.parser.HeaderParser().parsestr

    while True:
        try:
            part, some_bytes = some_bytes.split(boundary, 1)
        except ValueError:
            # Ran off the end, stop.
            break

        if b'\r\n\r\n' not in part:
            # Real parts have headers and a value separated by '\r\n'.
            continue

        part_head, _ = part.split(b'\r\n\r\n', 1)
        head_parsed = parse_data(part_head.lstrip(b'\r\n'))

        if 'Content-Disposition' in head_parsed:
            _, params = cgi.parse_header(head_parsed['Content-Disposition'])
            yield params, part


def expand_multipart_filename(data, headers):
    """ Replace instance of '${filename}' in key with given file name.

        Data is given as multipart form submission bytes, and file name is
        replace according to Amazon S3 documentation for Post uploads:
        http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html
    """
    _, params = cgi.parse_header(headers.get('Content-Type'))

    if 'boundary' not in params:
        return data

    boundary = params['boundary'].encode('ascii')
    data_bytes = to_bytes(data)

    filename = None

    for (disposition, _) in _iter_multipart_parts(data_bytes, boundary):
        if disposition.get('name') == 'file' and 'filename' in disposition:
            filename = disposition['filename']
            break

    if filename is None:
        # Found nothing, return unaltered
        return data

    for (disposition, part) in _iter_multipart_parts(data_bytes, boundary):
        if disposition.get('name') == 'key' and b'${filename}' in part:
            search = boundary + part
            replace = boundary + part.replace(b'${filename}', filename.encode('utf8'))

            if search in data_bytes:
                return data_bytes.replace(search, replace)

    return data


def find_multipart_redirect_url(data, headers):
    """ Return object key and redirect URL if they can be found.

        Data is given as multipart form submission bytes, and redirect is found
        in the success_action_redirect field according to Amazon S3
        documentation for Post uploads:
        http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html
    """
    _, params = cgi.parse_header(headers.get('Content-Type'))
    boundary = params['boundary'].encode('ascii')
    data_bytes = to_bytes(data)

    key, redirect_url = None, None

    for (disposition, part) in _iter_multipart_parts(data_bytes, boundary):
        if disposition.get('name') == 'key':
            _, value = part.split(b'\r\n\r\n', 1)
            key = value.rstrip(b'\r\n--').decode('utf8')

    if key:
        for (disposition, part) in _iter_multipart_parts(data_bytes, boundary):
            if disposition.get('name') == 'success_action_redirect':
                _, value = part.split(b'\r\n\r\n', 1)
                redirect_url = value.rstrip(b'\r\n--').decode('utf8')

    return key, redirect_url


def expand_redirect_url(starting_url, key, bucket):
    """ Add key and bucket parameters to starting URL query string. """
    parsed = urlparse.urlparse(starting_url)
    query = collections.OrderedDict(urlparse.parse_qsl(parsed.query))
    query.update([('key', key), ('bucket', bucket)])

    redirect_url = urlparse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlparse.urlencode(query), None))

    return redirect_url


class ProxyListenerS3(ProxyListener):

    def forward_request(self, method, path, data, headers):

        modified_data = None

        # If this request contains streaming v4 authentication signatures, strip them from the message
        # Related isse: https://github.com/localstack/localstack/issues/98
        # TODO we should evaluate whether to replace moto s3 with scality/S3:
        # https://github.com/scality/S3/issues/237
        if headers.get('x-amz-content-sha256') == 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD':
            modified_data = strip_chunk_signatures(data)

        # POST requests to S3 may include a "${filename}" placeholder in the
        # key, which should be replaced with an actual file name before storing.
        if method == 'POST':
            original_data = modified_data or data
            expanded_data = expand_multipart_filename(original_data, headers)
            if expanded_data is not original_data:
                modified_data = expanded_data

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
                    events_string = '\n'.join(['<Event>%s</Event>' % e for e in notif['Event']])
                    for dest in ['Queue', 'Topic', 'CloudFunction']:
                        if dest in notif:
                            result += ("""<{dest}Configuration>
                                        <Id>{uid}</Id>
                                        <{dest}>{endpoint}</{dest}>
                                        {events}
                                    </{dest}Configuration>""").format(
                                dest=dest, uid=uuid.uuid4(),
                                endpoint=notif[dest],
                                events=events_string)
                result += '</NotificationConfiguration>'
                response._content = result

            if method == 'PUT':
                parsed = xmltodict.parse(data)
                notif_config = parsed.get('NotificationConfiguration')
                for dest in ['Queue', 'Topic', 'CloudFunction']:
                    config = notif_config.get('%sConfiguration' % (dest))
                    if config:
                        # TODO: what if we have multiple destinations - would we overwrite the config?
                        notification_details = {
                            'Id': config.get('Id'),
                            'Event': config.get('Event'),
                            dest: config.get(dest),
                            'Filter': config.get('Filter')
                        }
                        S3_NOTIFICATIONS[bucket] = json.loads(json.dumps(notification_details))

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

        # POST requests to S3 may include a success_action_redirect field,
        # which should be used to redirect a client to a new location.
        if method == 'POST':
            key, redirect_url = find_multipart_redirect_url(data, headers)
            if key and redirect_url:
                response.status_code = 303
                response.headers['Location'] = expand_redirect_url(redirect_url, key, bucket_name)
                LOGGER.debug('S3 POST {} to {}'.format(response.status_code, response.headers['Location']))

        # get subscribers and send bucket notifications
        if method in ('PUT', 'DELETE') and '/' in path[1:]:
            # check if this is an actual put object request, because it could also be
            # a put bucket request with a path like this: /bucket_name/
            if len(path[1:].split('/')[1]) > 0:
                parts = parsed.path[1:].split('/', 1)
                # ignore bucket notification configuration requests
                if parsed.query != 'notification':
                    object_path = parts[1] if parts[1][0] == '/' else '/%s' % parts[1]
                    send_notifications(method, bucket_name, object_path)
        # publish event for creation/deletion of buckets:
        if method in ('PUT', 'DELETE') and ('/' not in path[1:] or len(path[1:].split('/')[1]) <= 0):
            event_type = (event_publisher.EVENT_S3_CREATE_BUCKET if method == 'PUT'
                else event_publisher.EVENT_S3_DELETE_BUCKET)
            event_publisher.fire_event(event_type, payload={'n': event_publisher.get_hash(bucket_name)})

        # append CORS headers to response
        if response:
            append_cors_headers(bucket_name, request_method=method, request_headers=headers, response=response)

            response_content_str = None
            try:
                response_content_str = to_str(response._content)
            except Exception:
                pass

            # we need to un-pretty-print the XML, otherwise we run into this issue with Spark:
            # https://github.com/jserver/mock-s3/pull/9/files
            # https://github.com/localstack/localstack/issues/183
            if response_content_str and response_content_str.startswith('<'):
                is_bytes = isinstance(response._content, six.binary_type)
                response._content = re.sub(r'>\n\s*<', '><', response_content_str, flags=re.MULTILINE)
                if is_bytes:
                    response._content = to_bytes(response._content)
                response.headers['content-length'] = len(response._content)


# instantiate listener
UPDATE_S3 = ProxyListenerS3()
