import re
import time
import logging
import datetime
from localstack import config
from collections import namedtuple
from botocore.compat import urlsplit
from botocore.credentials import Credentials
from urllib.parse import parse_qs, urlencode
from six.moves.urllib import parse as urlparse
from botocore.awsrequest import create_request_object
from localstack.utils.auth import HmacV1QueryAuth, S3SigV4QueryAuth
from localstack.utils.aws.aws_responses import requests_error_response_xml_signature_calculation
from localstack.constants import (
    S3_VIRTUAL_HOSTNAME, S3_STATIC_WEBSITE_HOSTNAME, TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY)


LOGGER = logging.getLogger(__name__)

REGION_REGEX = r'[a-z]{2}-[a-z]+-[0-9]{1,}'
PORT_REGEX = r'(:[\d]{0,6})?'
S3_STATIC_WEBSITE_HOST_REGEX = r'^([^.]+)\.s3-website\.localhost\.localstack\.cloud(:[\d]{0,6})?$'
S3_VIRTUAL_HOSTNAME_REGEX = (r'^(http(s)?://)?([^\.]+)\.s3((-website)|(-external-1))?[\.-](dualstack\.)?'
                             r'((localhost\.localstack\.cloud)|'
                             r'(({}\.)?amazonaws\.com(.cn)?)){}$'.format(REGION_REGEX, PORT_REGEX))
BUCKET_NAME_REGEX = (r'(?=^.{3,63}$)(?!^(\d+\.)+\d+$)' +
    r'(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)')

# response header overrides the client may request
ALLOWED_HEADER_OVERRIDES = {
    'response-content-type': 'Content-Type',
    'response-content-language': 'Content-Language',
    'response-expires': 'Expires',
    'response-cache-control': 'Cache-Control',
    'response-content-disposition': 'Content-Disposition',
    'response-content-encoding': 'Content-Encoding',
}

# params are required in presigned url
SIGNATURE_V2_PARAMS = ['Signature', 'Expires', 'AWSAccessKeyId']

SIGNATURE_V4_PARAMS = [
    'X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date', 'X-Amz-Expires',
    'X-Amz-SignedHeaders', 'X-Amz-Signature'
]


def is_static_website(headers):
    """
    Determine if the incoming request is for s3 static website hosting
    returns True if the host matches website regex
    returns False if the host does not matches website regex
    """
    return bool(re.match(S3_STATIC_WEBSITE_HOST_REGEX, headers.get('host', '')))


def uses_host_addressing(headers):
    """
    Determines if the bucket is using host based addressing style or path based
    """
    # we can assume that the host header we are receiving here is actually the header we originally received
    # from the client (because the edge service is forwarding the request in memory)
    match = re.match(S3_VIRTUAL_HOSTNAME_REGEX, headers.get('host', ''))
    return True if match and match.group(3) else False


def extract_bucket_name(headers, path):
    """
    Extract the bucket name
    if using host based addressing it's extracted from host header
    if using path based addressing it's extracted form the path
    """
    bucket_name = None
    if uses_host_addressing(headers):
        pattern = re.compile(S3_VIRTUAL_HOSTNAME_REGEX)
        match = pattern.match(headers.get('host', ''))

        if match and match.group(3):
            bucket_name = match.group(3)
    else:
        bucket_name = path.split('/', 2)[1]
    return bucket_name if bucket_name else None


def extract_key_name(headers, path):
    """
    Extract the key name from the path depending on addressing_style
    """
    key_name = None
    path = path.split('?')[0]  # strip off query params from path
    if uses_host_addressing(headers):
        split = path.split('/', 1)
        if len(split) > 1:
            key_name = split[1]
    else:
        split = path.split('/', 2)
        if len(split) > 2:
            key_name = split[2]

    return key_name if key_name else None


def extract_bucket_and_key_name(headers, path):
    return extract_bucket_name(headers, path), extract_key_name(headers, path)


def validate_bucket_name(bucket_name):
    """
    Validate s3 bucket name based on the documentation
    ref. https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    """
    return True if re.match(BUCKET_NAME_REGEX, bucket_name) else False


def get_bucket_hostname(bucket_name):
    """
    Get bucket name for addressing style host
    """
    return '%s.%s:%s' % (bucket_name, S3_VIRTUAL_HOSTNAME, config.EDGE_PORT)


def get_bucket_website_hostname(bucket_name):
    """
    Get bucket name for addressing style host for website hosting
    """
    return '%s.%s:%s' % (bucket_name, S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT)


def get_forwarded_for_host(headers):
    x_forwarded_header = re.split(r',\s?', headers.get('X-Forwarded-For', ''))
    host = x_forwarded_header[len(x_forwarded_header) - 1]
    return host


def authenticate_presign_url(method, path, headers, data=None):

    url = '{}{}'.format(config.get_edge_url(), path)
    parsed = urlparse.urlparse(url)
    query_params = parse_qs(parsed.query)
    forwarded_for = get_forwarded_for_host(headers)
    if forwarded_for:
        url = re.sub('://[^/]+', '://%s' % forwarded_for, url)

    LOGGER.debug('Received presign S3 URL: %s' % url)

    sign_headers = {}
    query_string = {}

    is_v2 = all([p in query_params for p in SIGNATURE_V2_PARAMS])
    is_v4 = all([p in query_params for p in SIGNATURE_V4_PARAMS])

    # Add overrided headers to the query string params
    for param_name, header_name in ALLOWED_HEADER_OVERRIDES.items():
        if param_name in query_params:
            query_string[param_name] = query_params[param_name][0]

    # Request's headers are more essentials than the query parameters in the request.
    # Different values of header in the header of the request and in the query parameter of the
    # request URL will fail the signature calulation. As per the AWS behaviour

    # Add valid headers into the sign_header. Skip the overrided headers
    # and the headers which have been sent in the query string param
    presign_params_lower = \
        [p.lower() for p in SIGNATURE_V4_PARAMS] if is_v4 else [p.lower() for p in SIGNATURE_V2_PARAMS]
    params_header_override = [param_name for param_name, header_name in ALLOWED_HEADER_OVERRIDES.items()]
    if len(query_params) > 2:
        for key in query_params:
            key_lower = key.lower()
            if key_lower not in presign_params_lower:
                if (key_lower not in (header[0].lower() for header in headers) and
                        key_lower not in params_header_override):
                    if key_lower in ['versionid', 'uploadid', 'partnumber']:
                        query_string[key] = query_params[key][0]
                    else:
                        sign_headers[key] = query_params[key][0]

    for header_name, header_value in headers.items():
        header_name_lower = header_name.lower()
        if header_name_lower.startswith('x-amz-') or header_name_lower.startswith('content-'):
            if is_v2 and header_name_lower in query_params:
                sign_headers[header_name] = header_value
            if is_v4 and header_name_lower in query_params['X-Amz-SignedHeaders'][0]:
                sign_headers[header_name] = header_value

    # Preparnig dictionary of request to build AWSRequest's object of the botocore
    request_url = '{}://{}{}'.format(parsed.scheme, parsed.netloc, urlparse.quote(parsed.path))
    request_url = \
        ('%s?%s' % (request_url, urlencode(query_string)) if query_string else request_url)

    if forwarded_for:
        request_url = re.sub('://[^/]+', '://%s' % forwarded_for, request_url)

    bucket_name = extract_bucket_name(headers, parsed.path)

    request_dict = {
        'url_path': urlparse.quote(parsed.path),
        'query_string': query_string,
        'method': method,
        'headers': sign_headers,
        'body': b'',
        'url': request_url,
        'context': {
            'is_presign_request': True,
            'use_global_endpoint': True,
            'signing': {
                'bucket': bucket_name
            }
        }
    }

    # Support for virtual host addressing style in signature version 2
    # We don't need to do this in v4 as we already concerting it to the virtual addressing style.
    # v2 require path base styled request_dict and v4 require virtual styled request_dict

    if uses_host_addressing(headers) and is_v2:
        request_dict['url_path'] = '/{}{}'.format(bucket_name, request_dict['url_path'])
        parsed_url = urlparse.urlparse(request_url)
        request_dict['url'] = '{}://{}:{}{}'.format(
            parsed_url.scheme, S3_VIRTUAL_HOSTNAME, config.EDGE_PORT, request_dict['url_path'])
        request_dict['url'] = \
            ('%s?%s' % (request_dict['url'], urlencode(query_string)) if query_string else request_dict['url'])

    if not is_v2 and any([p in query_params for p in SIGNATURE_V2_PARAMS]):
        response = requests_error_response_xml_signature_calculation(
            code=403,
            message='Query-string authentication requires the Signature, Expires and AWSAccessKeyId parameters',
            code_string='AccessDenied'
        )
    elif is_v2 and not is_v4:
        response = authenticate_presign_url_signv2(method, path, headers, data, url, query_params, request_dict)

    if not is_v4 and any([p in query_params for p in SIGNATURE_V4_PARAMS]):
        response = requests_error_response_xml_signature_calculation(
            code=403,
            message='Query-string authentication requires the X-Amz-Algorithm, \
                X-Amz-Credential, X-Amz-Date, X-Amz-Expires, \
                X-Amz-SignedHeaders and X-Amz-Signature parameters.',
            code_string='AccessDenied'
        )
    elif is_v4 and not is_v2:
        response = authenticate_presign_url_signv4(method, path, headers, data, url, query_params, request_dict)

    if response is not None:
        LOGGER.error('Presign signature calculation failed: %s' % response)
        return response
    LOGGER.debug('Valid presign url.')


def authenticate_presign_url_signv2(method, path, headers, data, url, query_params, request_dict):

    # Calculating Signature
    aws_request = create_request_object(request_dict)
    credentials = Credentials(access_key=TEST_AWS_ACCESS_KEY_ID, secret_key=TEST_AWS_SECRET_ACCESS_KEY)
    auth = HmacV1QueryAuth(credentials=credentials, expires=query_params['Expires'][0])
    split = urlsplit(aws_request.url)
    string_to_sign = auth.get_string_to_sign(method=method, split=split, headers=aws_request.headers)
    signature = auth.get_signature(string_to_sign=string_to_sign)

    # Comparing the signature in url with signature we calculated
    query_sig = urlparse.unquote(query_params['Signature'][0])
    if query_sig != signature:

        return requests_error_response_xml_signature_calculation(
            code=403,
            code_string='SignatureDoesNotMatch',
            aws_access_token=TEST_AWS_ACCESS_KEY_ID,
            string_to_sign=string_to_sign,
            signature=signature,
            message='The request signature we calculated does not match the signature you provided. \
                    Check your key and signing method.')

    # Checking whether the url is expired or not
    if int(query_params['Expires'][0]) < time.time():
        return requests_error_response_xml_signature_calculation(
            code=403,
            code_string='AccessDenied',
            message='Request has expired',
            expires=query_params['Expires'][0]
        )


def authenticate_presign_url_signv4(method, path, headers, data, url, query_params, request_dict):

    # Calculating Signature
    aws_request = create_request_object(request_dict)
    ReadOnlyCredentials = namedtuple('ReadOnlyCredentials',
                                 ['access_key', 'secret_key', 'token'])
    credentials = ReadOnlyCredentials(TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY, None)
    region = query_params['X-Amz-Credential'][0].split('/')[2]
    signer = S3SigV4QueryAuth(credentials, 's3', region, expires=int(query_params['X-Amz-Expires'][0]))
    signature = signer.add_auth(aws_request, query_params['X-Amz-Date'][0])

    expiration_time = datetime.datetime.strptime(query_params['X-Amz-Date'][0], '%Y%m%dT%H%M%SZ') + \
        datetime.timedelta(seconds=int(query_params['X-Amz-Expires'][0]))

    # Comparing the signature in url with signature we calculated
    query_sig = urlparse.unquote(query_params['X-Amz-Signature'][0])
    if query_sig != signature:

        return requests_error_response_xml_signature_calculation(
            code=403,
            code_string='SignatureDoesNotMatch',
            aws_access_token=TEST_AWS_ACCESS_KEY_ID,
            signature=signature,
            message='The request signature we calculated does not match the signature you provided. \
                    Check your key and signing method.')

    # Checking whether the url is expired or not
    if expiration_time < datetime.datetime.utcnow():
        return requests_error_response_xml_signature_calculation(
            code=403,
            code_string='AccessDenied',
            message='Request has expired',
            expires=query_params['X-Amz-Expires'][0]
        )
