import binascii
import datetime
import json
import re
import xml.etree.ElementTree as ET
from binascii import crc32
from struct import pack
from typing import Dict, Optional, Union
from urllib.parse import parse_qs

import xmltodict
from flask import Response as FlaskResponse
from requests.models import CaseInsensitiveDict
from requests.models import Response as RequestsResponse

from localstack.config import DEFAULT_ENCODING
from localstack.constants import (
    APPLICATION_JSON,
    HEADER_CONTENT_TYPE,
    MOTO_ACCOUNT_ID,
    TEST_AWS_ACCOUNT_ID,
)
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    json_safe,
    replace_response_content,
    short_uid,
    to_bytes,
    to_str,
    truncate,
)

REGEX_FLAGS = re.MULTILINE | re.DOTALL

AWS_BINARY_DATA_TYPE_STRING = 7


class ErrorResponse(Exception):
    def __init__(self, response):
        self.response = response


def flask_error_response_json(
    msg: str, code: Optional[int] = 500, error_type: Optional[str] = "InternalFailure"
):
    result = {
        "Type": "User" if code < 500 else "Server",
        "message": msg,
        "__type": error_type,
    }
    headers = {"x-amzn-errortype": error_type}
    # Note: don't use flask's make_response(..) or jsonify(..) here as they
    # can lead to "RuntimeError: working outside of application context".
    return FlaskResponse(json.dumps(result), status=code, headers=headers)


def requests_error_response_json(message, code=500, error_type="InternalFailure"):
    response = flask_error_response_json(message, code=code, error_type=error_type)
    return flask_to_requests_response(response)


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


def to_xml(data: dict, memberize: bool = True) -> ET.Element:
    """Generate XML element hierarchy out of dict. Wraps list items in <member> tags by default"""
    if not isinstance(data, dict) or len(data.keys()) != 1:
        raise Exception("Expected data to be a dict with a single root element")

    def _to_xml(parent_el: ET.Element, data_rest) -> None:
        if isinstance(data_rest, list):
            for i in data_rest:
                member_el = ET.SubElement(parent_el, "member") if memberize else parent_el
                _to_xml(member_el, i)
        elif isinstance(data_rest, dict):
            for key in data_rest:
                value = data_rest[key]
                curr_el = ET.SubElement(parent_el, key)
                _to_xml(curr_el, value)
        elif isinstance(data_rest, str):
            parent_el.text = data_rest
        elif any(
            [isinstance(data_rest, i) for i in [bool, str, int, float]]
        ):  # limit types for text serialization
            parent_el.text = str(data_rest)
        else:
            if data_rest is not None:  # None is just ignored and omitted
                raise Exception(f"Unexpected type for value encountered: {type(data_rest)}")

    root_key = list(data.keys())[0]
    root = ET.Element(root_key)
    _to_xml(root, data[root_key])
    return root


def requests_response_xml(action, response, xmlns=None, service=None, memberize=True):
    xmlns = xmlns or "http://%s.amazonaws.com/doc/2010-03-31/" % service
    response = json_safe(response)
    response = {"{action}Result".format(action=action): response}
    response = ET.tostring(to_xml(response, memberize=memberize), short_empty_elements=True)
    response = to_str(response)
    result = (
        """
        <{action}Response xmlns="{xmlns}">
            {response}
        </{action}Response>
        """
    ).strip()
    result = result.format(action=action, xmlns=xmlns, response=response)
    result = requests_response(result)
    return result


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


def flask_error_response_xml(
    message: str,
    code: Optional[int] = 500,
    code_string: Optional[str] = "InternalFailure",
    service: Optional[str] = None,
    xmlns: Optional[str] = None,
):
    response = requests_error_response_xml(
        message, code=code, code_string=code_string, service=service, xmlns=xmlns
    )
    return requests_to_flask_response(response)


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


def raise_exception_if_error_response(response):
    if not is_response_obj(response):
        return
    if response.status_code < 400:
        return
    content = "..."
    try:
        content = truncate(to_str(response.content or ""))
    except Exception:
        pass  # ignore if content has non-printable bytes
    raise Exception("Received error response (code %s): %s" % (response.status_code, content))


def is_response_obj(result):
    return isinstance(result, (RequestsResponse, FlaskResponse))


def get_response_payload(response, as_json=False):
    result = (
        response.content
        if isinstance(response, RequestsResponse)
        else response.data
        if isinstance(response, FlaskResponse)
        else None
    )
    result = "" if result is None else result
    if as_json:
        result = result or "{}"
        result = json.loads(to_str(result))
    return result


def requests_response(content, status_code=200, headers={}):
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


def request_response_stream(stream, status_code=200, headers={}):
    resp = RequestsResponse()
    resp.raw = stream
    resp.status_code = int(status_code)
    # Note: update headers (instead of assigning directly), to ensure we're using a case-insensitive dict
    resp.headers.update(headers or {})
    return resp


def flask_to_requests_response(r):
    return requests_response(r.data, status_code=r.status_code, headers=r.headers)


def requests_to_flask_response(r):
    return FlaskResponse(r.content, status=r.status_code, headers=dict(r.headers))


def flask_not_found_error(msg=None):
    msg = msg or "The specified resource doesnt exist."
    return flask_error_response_json(msg, code=404, error_type="ResourceNotFoundException")


def response_regex_replace(response, search, replace):
    content = re.sub(search, replace, to_str(response._content), flags=re.DOTALL | re.MULTILINE)
    set_response_content(response, content)


def set_response_content(response, content, headers=None):
    if isinstance(content, dict):
        content = json.dumps(json_safe(content))
    elif isinstance(content, RequestsResponse):
        response.status_code = content.status_code
        content = content.content
    response._content = content or ""
    response.headers.update(headers or {})
    response.headers["Content-Length"] = str(len(response._content))


def make_requests_error(*args, **kwargs):
    return flask_to_requests_response(flask_error_response_xml(*args, **kwargs))


def make_error(*args, **kwargs):
    return flask_error_response_xml(*args, **kwargs)


def create_sqs_system_attributes(headers):
    system_attributes = {}
    if "X-Amzn-Trace-Id" in headers:
        system_attributes["AWSTraceHeader"] = {
            "DataType": "String",
            "StringValue": str(headers["X-Amzn-Trace-Id"]),
        }
    return system_attributes


def extract_tags(req_data):
    for param_name in ["Tag", "member"]:
        keys = extract_url_encoded_param_list(req_data, "Tags.{}.%s.Key".format(param_name))
        values = extract_url_encoded_param_list(req_data, "Tags.{}.%s.Value".format(param_name))
        if keys and values:
            break
    entries = zip(keys, values)
    tags = [{"Key": entry[0], "Value": entry[1]} for entry in entries]
    return tags


def extract_url_encoded_param_list(req_data, pattern):
    result = []
    for i in range(1, 200):
        key = pattern % i
        value = req_data.get(key)
        if value is None:
            break
        result.append(value)
    return result


def parse_urlencoded_data(qs_data, top_level_attribute):
    # TODO: potentially find a better way than calling moto here...
    from moto.core.responses import BaseResponse

    if qs_data and isinstance(qs_data, dict):
        # make sure we're using the array form of query string dict here
        qs_data = {k: v if isinstance(v, list) else [v] for k, v in qs_data.items()}
    if isinstance(qs_data, (str, bytes)):
        qs_data = parse_qs(qs_data)
    response = BaseResponse()
    response.querystring = qs_data
    result = response._get_multi_param(top_level_attribute, skip_result_conversion=True)
    return result


def calculate_crc32(content):
    return crc32(to_bytes(content)) & 0xFFFFFFFF


def convert_to_binary_event_payload(result, event_type=None, message_type=None):
    # e.g.: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTSelectObjectAppendix.html
    # e.g.: https://docs.aws.amazon.com/transcribe/latest/dg/event-stream.html

    header_descriptors = {
        ":event-type": event_type or "Records",
        ":message-type": message_type or "event",
    }

    # construct headers
    headers = b""
    for key, value in header_descriptors.items():
        header_name = key.encode(DEFAULT_ENCODING)
        header_value = to_bytes(value)
        headers += pack("!B", len(header_name))
        headers += header_name
        headers += pack("!B", AWS_BINARY_DATA_TYPE_STRING)
        headers += pack("!H", len(header_value))
        headers += header_value

    # construct body
    body = bytes(result, DEFAULT_ENCODING)

    # calculate lengths
    headers_length = len(headers)
    body_length = len(body)

    # construct message
    result = pack("!I", body_length + headers_length + 16)
    result += pack("!I", headers_length)
    prelude_crc = binascii.crc32(result)
    result += pack("!I", prelude_crc)
    result += headers
    result += body
    payload_crc = binascii.crc32(result)
    result += pack("!I", payload_crc)

    return result


class LambdaResponse(object):
    """Helper class to support multi_value_headers in Lambda responses"""

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
        """Normalize date to format '2019-06-13T18:10:09.1234Z'"""
        pattern = r"<CreateDate>([^<]+) ([^<+]+)(\+[^<]*)?</CreateDate>"
        replacement = r"<CreateDate>\1T\2Z</CreateDate>"
        replace_response_content(response, pattern, replacement)

    @staticmethod
    def fix_account_id(response):
        return aws_stack.fix_account_id_in_arns(response, replace=TEST_AWS_ACCOUNT_ID)

    @staticmethod
    def fix_error_codes(method, data, response):
        regex = r"<Errors>\s*(<Error>(\s|.)*</Error>)\s*</Errors>"
        if method == "POST" and "Action=CreateRole" in to_str(data) and response.status_code >= 400:
            content = to_str(response.content)
            # remove the <Errors> wrapper element, as this breaks AWS Java SDKs (issue #2231)
            response._content = re.sub(regex, r"\1", content, flags=REGEX_FLAGS)

    @staticmethod
    def fix_xml_empty_boolean(response, tag_names):
        for tag_name in tag_names:
            regex = r"<{tag}>\s*([Nn]one|null)\s*</{tag}>".format(tag=tag_name)
            replace = r"<{tag}>false</{tag}>".format(tag=tag_name)
            response._content = re.sub(regex, replace, to_str(response.content), flags=REGEX_FLAGS)

    @staticmethod
    def _reset_account_id(data):
        """Fix account ID in request payload. All external-facing responses contain our
        predefined account ID (defaults to 000000000000), whereas the backend endpoint
        from moto expects a different hardcoded account ID (123456789012)."""
        return aws_stack.fix_account_id_in_arns(
            data,
            colon_delimiter="%3A",
            existing=TEST_AWS_ACCOUNT_ID,
            replace=MOTO_ACCOUNT_ID,
        )
