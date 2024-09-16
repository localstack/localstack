import binascii
import datetime
import json
import re
from binascii import crc32
from typing import Any, Dict, Optional, Union
from urllib.parse import parse_qs

import xmltodict
from requests.models import CaseInsensitiveDict
from requests.models import Response as RequestsResponse

from localstack.constants import APPLICATION_JSON, HEADER_CONTENT_TYPE
from localstack.utils.json import json_safe
from localstack.utils.strings import short_uid, str_startswith_ignore_case, to_bytes, to_str

REGEX_FLAGS = re.MULTILINE | re.DOTALL

regex_url_start = re.compile("^[a-z]{2,5}://")


class ErrorResponse(Exception):
    def __init__(self, response):
        self.response = response


def requests_error_response_json(message, code=500, error_type="InternalFailure"):
    result = {
        "Type": "User" if code < 500 else "Server",
        "message": message,
        "__type": error_type,
    }
    headers = {"x-amzn-errortype": error_type}
    return requests_response(json.dumps(result), status_code=code, headers=headers)


def requests_error_response_xml(
    message: str,
    code: Optional[int] = 400,
    code_string: Optional[str] = "InvalidParameter",
    service: Optional[str] = None,
    xmlns: Optional[str] = None,
):
    response = RequestsResponse()
    xmlns = xmlns or "http://%s.amazonaws.com/doc/2010-03-31/" % service
    response._content = """<ErrorResponse xmlns="{xmlns}"><Error>
        <Type>Sender</Type>
        <Code>{code_string}</Code>
        <Message>{message}</Message>
        </Error><RequestId>{req_id}</RequestId>
        </ErrorResponse>""".format(
        xmlns=xmlns, message=message, code_string=code_string, req_id=short_uid()
    )
    response.status_code = code
    return response


def requests_error_response_xml_signature_calculation(
    message,
    string_to_sign=None,
    signature=None,
    expires=None,
    code=400,
    code_string="AccessDenied",
    aws_access_token="temp",
):
    response = RequestsResponse()
    response_template = """<?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>{code_string}</Code>
            <Message>{message}</Message>
            <RequestId>{req_id}</RequestId>
            <HostId>{host_id}</HostId>
        </Error>""".format(
        message=message,
        code_string=code_string,
        req_id=short_uid(),
        host_id=short_uid(),
    )

    parsed_response = xmltodict.parse(response_template)
    response.status_code = code

    if signature and string_to_sign or code_string == "SignatureDoesNotMatch":
        bytes_signature = binascii.hexlify(bytes(signature, encoding="utf-8"))
        parsed_response["Error"]["Code"] = code_string
        parsed_response["Error"]["AWSAccessKeyId"] = aws_access_token
        parsed_response["Error"]["StringToSign"] = string_to_sign
        parsed_response["Error"]["SignatureProvided"] = signature
        parsed_response["Error"]["StringToSignBytes"] = "{}".format(bytes_signature.decode("utf-8"))
        set_response_content(response, xmltodict.unparse(parsed_response))

    if expires and code_string == "AccessDenied":
        server_time = datetime.datetime.utcnow().isoformat()[:-4]
        expires_isoformat = datetime.datetime.fromtimestamp(int(expires)).isoformat()[:-4]
        parsed_response["Error"]["Code"] = code_string
        parsed_response["Error"]["Expires"] = "{}Z".format(expires_isoformat)
        parsed_response["Error"]["ServerTime"] = "{}Z".format(server_time)
        set_response_content(response, xmltodict.unparse(parsed_response))

    if not signature and not expires and code_string == "AccessDenied":
        set_response_content(response, xmltodict.unparse(parsed_response))

    if response._content:
        return response


def requests_error_response(
    req_headers: Dict,
    message: Union[str, bytes],
    code: int = 500,
    error_type: str = "InternalFailure",
    service: str = None,
    xmlns: str = None,
):
    is_json = is_json_request(req_headers)
    if is_json:
        return requests_error_response_json(message=message, code=code, error_type=error_type)
    return requests_error_response_xml(
        message, code=code, code_string=error_type, service=service, xmlns=xmlns
    )


def is_json_request(req_headers: Dict) -> bool:
    ctype = req_headers.get("Content-Type", "")
    accept = req_headers.get("Accept", "")
    return "json" in ctype or "json" in accept


def is_invalid_html_response(headers, content) -> bool:
    content_type = headers.get("Content-Type", "")
    return "text/html" in content_type and not str_startswith_ignore_case(content, "<!doctype html")


def is_response_obj(result, include_lambda_response=False):
    types = (RequestsResponse,)
    if include_lambda_response:
        types += (LambdaResponse,)
    return isinstance(result, types)


def get_response_payload(response, as_json=False):
    result = response.content if isinstance(response, RequestsResponse) else None
    result = "" if result is None else result
    if as_json:
        result = result or "{}"
        result = json.loads(to_str(result))
    return result


def requests_response(content, status_code=200, headers=None):
    if headers is None:
        headers = {}
    resp = RequestsResponse()
    headers = CaseInsensitiveDict(dict(headers or {}))
    if isinstance(content, dict):
        content = json.dumps(content)
        if not headers.get(HEADER_CONTENT_TYPE):
            headers[HEADER_CONTENT_TYPE] = APPLICATION_JSON
    resp._content = content
    resp.status_code = int(status_code)
    # Note: update headers (instead of assigning directly), to ensure we're using a case-insensitive dict
    resp.headers.update(headers)
    return resp


def request_response_stream(stream, status_code=200, headers=None):
    if headers is None:
        headers = {}
    resp = RequestsResponse()
    resp.raw = stream
    resp.status_code = int(status_code)
    # Note: update headers (instead of assigning directly), to ensure we're using a case-insensitive dict
    resp.headers.update(headers or {})
    return resp


def set_response_content(response, content, headers=None):
    if isinstance(content, dict):
        content = json.dumps(json_safe(content))
    elif isinstance(content, RequestsResponse):
        response.status_code = content.status_code
        content = content.content
    response._content = content or ""
    response.headers.update(headers or {})
    response.headers["Content-Length"] = str(len(response._content))


def create_sqs_system_attributes(headers: Dict[str, str]) -> Dict[str, Any]:
    system_attributes = {}
    if "X-Amzn-Trace-Id" in headers:
        system_attributes["AWSTraceHeader"] = {
            "DataType": "String",
            "StringValue": str(headers["X-Amzn-Trace-Id"]),
        }
    return system_attributes


def parse_query_string(url_or_qs: str, multi_values=False) -> Dict[str, str]:
    url_or_qs = str(url_or_qs or "").strip()
    # we match if the `url_or_qs` passed is maybe a URL
    if regex_url_start.match(url_or_qs) and "?" not in url_or_qs:
        url_or_qs = f"{url_or_qs}?"
    url_or_qs = url_or_qs.split("?", maxsplit=1)[-1]
    result = parse_qs(url_or_qs, keep_blank_values=True)
    if not multi_values:
        result = {k: v[0] for k, v in result.items()}
    return result


def calculate_crc32(content: Union[str, bytes]) -> int:
    return crc32(to_bytes(content)) & 0xFFFFFFFF


class LambdaResponse:
    """Helper class to support multi_value_headers in Lambda responses"""

    def __init__(self):
        self._content = False
        self.status_code = None
        self.multi_value_headers = CaseInsensitiveDict()
        self.headers = CaseInsensitiveDict()

    @property
    def content(self):
        return self._content
