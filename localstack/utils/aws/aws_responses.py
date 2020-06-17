import re
import json
from flask import Response
from requests.models import CaseInsensitiveDict
from requests.models import Response as RequestsResponse
from localstack.utils.common import to_str
from localstack.constants import TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


def flask_error_response(msg, code=500, error_type='InternalFailure'):
    result = {
        'Type': 'User' if code < 500 else 'Server',
        'message': msg,
        '__type': error_type
    }
    headers = {'x-amzn-errortype': error_type}
    # Note: don't use flask's make_response(..) or jsonify(..) here as they
    # can lead to "RuntimeError: working outside of application context".
    return Response(json.dumps(result), status=code, headers=headers)


def requests_error_response(msg, code=500, error_type='InternalFailure'):
    response = flask_error_response(msg, code=code, error_type=error_type)
    return flask_to_requests_response(response)


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
    response._content = re.sub(search, replace, to_str(response._content), flags=re.DOTALL | re.MULTILINE)
    response.headers['Content-Length'] = str(len(response._content))


def make_error(message, code=400, code_string='InvalidParameter'):
    response = Response()
    response._content = """<ErrorResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/"><Error>
        <Type>Sender</Type>
        <Code>{code_string}</Code>
        <Message>{message}</Message>
        </Error><RequestId>{req_id}</RequestId>
        </ErrorResponse>""".format(message=message, code_string=code_string, req_id=short_uid())
    response.status_code = code
    return response


class LambdaResponse(object):
    # this object has been created to support multi_value_headers in aws responses.
    def __init__(self):
        self.content = False
        self.status_code = None
        self.multi_value_headers = CaseInsensitiveDict()
        self.headers = CaseInsensitiveDict()


class MessageConversion(object):

    @staticmethod
    def _fix_date_format(response):
        """ Normalize date to format '2019-06-13T18:10:09.1234Z' """

        def _replace(response, pattern, replacement):
            content = to_str(response.content)
            response._content = re.sub(pattern, replacement, content)

        pattern = r'<CreateDate>([^<]+) ([^<+]+)(\+[^<]*)?</CreateDate>'
        replacement = r'<CreateDate>\1T\2Z</CreateDate>'
        _replace(response, pattern, replacement)

    @staticmethod
    def _fix_account_id(response):
        return aws_stack.fix_account_id_in_arns(
            response, existing=MOTO_ACCOUNT_ID, replace=TEST_AWS_ACCOUNT_ID)

    @staticmethod
    def _fix_error_codes(method, data, response):
        if method == 'POST' and 'Action=CreateRole' in to_str(data) and response.status_code >= 400:
            content = to_str(response.content)
            flags = re.MULTILINE | re.DOTALL
            # remove the <Errors> wrapper element, as this breaks AWS Java SDKs (issue #2231)
            response._content = re.sub(r'<Errors>\s*(<Error>(\s|.)*</Error>)\s*</Errors>', r'\1', content, flags)

    @staticmethod
    def _reset_account_id(data):
        """ Fix account ID in request payload. All external-facing responses contain our
            predefined account ID (defaults to 000000000000), whereas the backend endpoint
            from moto expects a different hardcoded account ID (123456789012). """
        return aws_stack.fix_account_id_in_arns(
            data, colon_delimiter='%3A', existing=TEST_AWS_ACCOUNT_ID, replace=MOTO_ACCOUNT_ID)
