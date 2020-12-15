import re
import json
import binascii
import datetime
import xmltodict
from flask import Response
from binascii import crc32
from requests.models import CaseInsensitiveDict
from requests.models import Response as RequestsResponse
from localstack.constants import TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, to_str, to_bytes, json_safe

REGEX_FLAGS = re.MULTILINE | re.DOTALL


class ErrorResponse(Exception):
    def __init__(self, response):
        self.response = response


def flask_error_response_json(msg, code=500, error_type='InternalFailure'):
    result = {
        'Type': 'User' if code < 500 else 'Server',
        'message': msg,
        '__type': error_type
    }
    headers = {'x-amzn-errortype': error_type}
    # Note: don't use flask's make_response(..) or jsonify(..) here as they
    # can lead to "RuntimeError: working outside of application context".
    return Response(json.dumps(result), status=code, headers=headers)


def requests_error_response_json(message, code=500, error_type='InternalFailure'):
    response = flask_error_response_json(message, code=code, error_type=error_type)
    return flask_to_requests_response(response)


def requests_error_response_xml(message, code=400, code_string='InvalidParameter', service=None, xmlns=None):
    response = RequestsResponse()
    xmlns = xmlns or 'http://%s.amazonaws.com/doc/2010-03-31/' % service
    response._content = """<ErrorResponse xmlns="{xmlns}"><Error>
        <Type>Sender</Type>
        <Code>{code_string}</Code>
        <Message>{message}</Message>
        </Error><RequestId>{req_id}</RequestId>
        </ErrorResponse>""".format(xmlns=xmlns, message=message, code_string=code_string, req_id=short_uid())
    response.status_code = code
    return response


def requests_response_xml(action, response, xmlns=None, service=None):
    xmlns = xmlns or 'http://%s.amazonaws.com/doc/2010-03-31/' % service
    response = json_safe(response)
    response = {'{action}Result'.format(action=action): response}
    response = xmltodict.unparse(response)
    if response.startswith('<?xml'):
        response = re.sub(r'<\?xml [^\?]+\?>', '', response)
    result = ("""
        <{action}Response xmlns="{xmlns}">
            {response}
        </{action}Response>
    """).strip()
    result = result.format(action=action, xmlns=xmlns, response=response)
    result = requests_response(result)
    return result


def requests_error_response_xml_signature_calculation(message, string_to_sign=None, signature=None, expires=None,
        code=400, code_string='AccessDenied', aws_access_token='temp'):
    response = RequestsResponse()
    response_template = """<?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>{code_string}</Code>
            <Message>{message}</Message>
            <RequestId>{req_id}</RequestId>
            <HostId>{host_id}</HostId>
        </Error>""".format(message=message, code_string=code_string, req_id=short_uid(), host_id=short_uid())

    parsed_response = xmltodict.parse(response_template)
    response.status_code = code

    if signature and string_to_sign or code_string == 'SignatureDoesNotMatch':

        bytes_signature = binascii.hexlify(bytes(signature, encoding='utf-8'))
        parsed_response['Error']['Code'] = code_string
        parsed_response['Error']['AWSAccessKeyId'] = aws_access_token
        parsed_response['Error']['StringToSign'] = string_to_sign
        parsed_response['Error']['SignatureProvided'] = signature
        parsed_response['Error']['StringToSignBytes'] = '{}'.format(bytes_signature.decode('utf-8'))
        response._content = xmltodict.unparse(parsed_response)
        response.headers['Content-Length'] = str(len(response._content))

    if expires and code_string == 'AccessDenied':

        server_time = datetime.datetime.utcnow().isoformat()[:-4]
        expires_isoformat = datetime.datetime.fromtimestamp(int(expires)).isoformat()[:-4]
        parsed_response['Error']['Code'] = code_string
        parsed_response['Error']['Expires'] = '{}Z'.format(expires_isoformat)
        parsed_response['Error']['ServerTime'] = '{}Z'.format(server_time)
        response._content = xmltodict.unparse(parsed_response)
        response.headers['Content-Length'] = str(len(response._content))

    if not signature and not expires and code_string == 'AccessDenied':

        response._content = xmltodict.unparse(parsed_response)
        response.headers['Content-Length'] = str(len(response._content))

    if response._content:
        return response


def flask_error_response_xml(message, code=500, code_string='InternalFailure', service=None, xmlns=None):
    response = requests_error_response_xml(message, code=code, code_string=code_string, service=service, xmlns=xmlns)
    return requests_to_flask_response(response)


def requests_error_response(req_headers, message, code=500, error_type='InternalFailure', service=None, xmlns=None):
    ctype = req_headers.get('Content-Type', '')
    accept = req_headers.get('Accept', '')
    is_json = 'json' in ctype or 'json' in accept
    if is_json:
        return requests_error_response_json(message=message, code=code, error_type=error_type)
    return requests_error_response_xml(message, code=code, code_string=error_type, service=service, xmlns=xmlns)


def requests_response(content, status_code=200, headers={}):
    resp = RequestsResponse()
    content = json.dumps(content) if isinstance(content, dict) else content
    resp._content = content
    resp.status_code = status_code
    resp.headers = headers
    return resp


def flask_to_requests_response(r):
    return requests_response(r.data, status_code=r.status_code, headers=r.headers)


def requests_to_flask_response(r):
    return Response(r.content, status=r.status_code, headers=dict(r.headers))


def response_regex_replace(response, search, replace):
    content = re.sub(search, replace, to_str(response._content), flags=re.DOTALL | re.MULTILINE)
    set_response_content(response, content)


def set_response_content(response, content):
    if isinstance(content, dict):
        content = json.dumps(content)
    response._content = content or ''
    response.headers['Content-Length'] = str(len(response._content))


def make_requests_error(*args, **kwargs):
    return flask_to_requests_response(flask_error_response_xml(*args, **kwargs))


def make_error(*args, **kwargs):
    return flask_error_response_xml(*args, **kwargs)


def calculate_crc32(content):
    return crc32(to_bytes(content)) & 0xffffffff


class LambdaResponse(object):
    """ Helper class to support multi_value_headers in Lambda responses """

    def __init__(self):
        self._content = False
        self.status_code = None
        self.multi_value_headers = CaseInsensitiveDict()
        self.headers = CaseInsensitiveDict()

    @property
    def content(self):
        return self._content


class MessageConversion(object):

    @staticmethod
    def fix_date_format(response):
        """ Normalize date to format '2019-06-13T18:10:09.1234Z' """

        def _replace(response, pattern, replacement):
            content = to_str(response.content)
            response._content = re.sub(pattern, replacement, content)

        pattern = r'<CreateDate>([^<]+) ([^<+]+)(\+[^<]*)?</CreateDate>'
        replacement = r'<CreateDate>\1T\2Z</CreateDate>'
        _replace(response, pattern, replacement)

    @staticmethod
    def fix_account_id(response):
        return aws_stack.fix_account_id_in_arns(
            response, replace=TEST_AWS_ACCOUNT_ID)

    @staticmethod
    def fix_error_codes(method, data, response):
        regex = r'<Errors>\s*(<Error>(\s|.)*</Error>)\s*</Errors>'
        if method == 'POST' and 'Action=CreateRole' in to_str(data) and response.status_code >= 400:
            content = to_str(response.content)
            # remove the <Errors> wrapper element, as this breaks AWS Java SDKs (issue #2231)
            response._content = re.sub(regex, r'\1', content, flags=REGEX_FLAGS)

    @staticmethod
    def fix_xml_empty_boolean(response, tag_names):
        for tag_name in tag_names:
            regex = r'<{tag}>\s*([Nn]one|null)\s*</{tag}>'.format(tag=tag_name)
            replace = r'<{tag}>false</{tag}>'.format(tag=tag_name)
            response._content = re.sub(regex, replace, to_str(response.content), flags=REGEX_FLAGS)

    @staticmethod
    def _reset_account_id(data):
        """ Fix account ID in request payload. All external-facing responses contain our
            predefined account ID (defaults to 000000000000), whereas the backend endpoint
            from moto expects a different hardcoded account ID (123456789012). """
        return aws_stack.fix_account_id_in_arns(
            data, colon_delimiter='%3A', existing=TEST_AWS_ACCOUNT_ID, replace=MOTO_ACCOUNT_ID)
