"""
This module has utilities relating to creating/parsing AWS requests.
"""

import logging
import re
from typing import Dict, Optional
from urllib.parse import urlparse

from rolo import Request as RoloRequest

from localstack.aws.accounts import get_account_id_from_access_key_id
from localstack.constants import (
    APPLICATION_AMZ_JSON_1_0,
    APPLICATION_AMZ_JSON_1_1,
    APPLICATION_X_WWW_FORM_URLENCODED,
    AWS_REGION_US_EAST_1,
    DEFAULT_AWS_ACCOUNT_ID,
)
from localstack.utils.aws.aws_responses import (
    requests_error_response,
    requests_to_flask_response,
)
from localstack.utils.coverage_docs import get_coverage_link_for_service
from localstack.utils.patch import patch
from localstack.utils.strings import snake_to_camel_case

LOG = logging.getLogger(__name__)

AWS_REGION_REGEX = r"(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d"


def get_account_id_from_request(request: RoloRequest) -> str:
    access_key_id = (
        extract_access_key_id_from_auth_header(request.headers) or DEFAULT_AWS_ACCOUNT_ID
    )

    return get_account_id_from_access_key_id(access_key_id)


def extract_region_from_auth_header(headers) -> Optional[str]:
    auth = headers.get("Authorization") or ""
    region = re.sub(r".*Credential=[^/]+/[^/]+/([^/]+)/.*", r"\1", auth)
    if region == auth:
        return None
    return region


def extract_account_id_from_auth_header(headers) -> Optional[str]:
    if access_key_id := extract_access_key_id_from_auth_header(headers):
        return get_account_id_from_access_key_id(access_key_id)


def extract_access_key_id_from_auth_header(headers: Dict[str, str]) -> Optional[str]:
    auth = headers.get("Authorization") or ""

    if auth.startswith("AWS4-"):
        # For Signature Version 4
        access_id = re.findall(r".*Credential=([^/]+)/[^/]+/[^/]+/.*", auth)
        if len(access_id):
            return access_id[0]

    elif auth.startswith("AWS "):
        # For Signature Version 2
        access_id = auth.removeprefix("AWS ").split(":")
        if len(access_id):
            return access_id[0]


def extract_account_id_from_headers(headers) -> str:
    return extract_account_id_from_auth_header(headers) or DEFAULT_AWS_ACCOUNT_ID


def extract_region_from_headers(headers) -> str:
    return extract_region_from_auth_header(headers) or AWS_REGION_US_EAST_1


def extract_service_name_from_auth_header(headers: Dict) -> Optional[str]:
    try:
        auth_header = headers.get("authorization", "")
        credential_scope = auth_header.split(",")[0].split()[1]
        _, _, _, service, _ = credential_scope.split("/")
        return service
    except Exception:
        return


def patch_moto_request_handling():
    from importlib.util import find_spec

    if not find_spec("moto"):
        # leave here to avoid import issues
        return

    from flask import request
    from moto.core import utils as moto_utils

    # make sure we properly handle/propagate "not implemented" errors
    @patch(moto_utils.convert_to_flask_response.__call__)
    def convert_to_flask_response_call(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except NotImplementedError as e:
            action = request.headers.get("X-Amz-Target")
            action = action or f"{request.method} {urlparse(request.url).path}"
            if action == "POST /":
                # try to extract action from exception string
                match = re.match(r"The ([a-zA-Z0-9_-]+) action has not been implemented", str(e))
                if match:
                    action = snake_to_camel_case(match.group(1))
            service = extract_service_name_from_auth_header(request.headers)
            exception_message: str | None = e.args[0] if e.args else None
            msg = exception_message or get_coverage_link_for_service(service, action)
            response = requests_error_response(request.headers, msg, code=501)
            LOG.info(msg)
            # TODO: publish analytics event ...
            return requests_to_flask_response(response)


def mock_aws_request_headers(
    service: str, aws_access_key_id: str, region_name: str, internal: bool = False
) -> Dict[str, str]:
    """
    Returns a mock set of headers that resemble SigV4 signing method.
    """
    from localstack.aws.connect import (
        INTERNAL_REQUEST_PARAMS_HEADER,
        InternalRequestParameters,
        dump_dto,
    )

    ctype = APPLICATION_AMZ_JSON_1_0
    if service == "kinesis":
        ctype = APPLICATION_AMZ_JSON_1_1
    elif service in ["sns", "sqs", "sts", "cloudformation"]:
        ctype = APPLICATION_X_WWW_FORM_URLENCODED

    # For S3 presigned URLs, we require that the client and server use the same
    # access key ID to sign requests. So try to use the access key ID for the
    # current request if available
    headers = {
        "Content-Type": ctype,
        "Accept-Encoding": "identity",
        "X-Amz-Date": "20160623T103251Z",  # TODO: Use current date
        "Authorization": (
            "AWS4-HMAC-SHA256 "
            + f"Credential={aws_access_key_id}/20160623/{region_name}/{service}/aws4_request, "
            + "SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=1234"
        ),
    }

    if internal:
        dto = InternalRequestParameters()
        headers[INTERNAL_REQUEST_PARAMS_HEADER] = dump_dto(dto)

    return headers
