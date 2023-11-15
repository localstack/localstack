import logging
import re
import threading
from typing import Dict, Optional
from urllib.parse import urlparse

from flask import request
from requests.models import Request
from requests.structures import CaseInsensitiveDict

from localstack.aws.accounts import get_account_id_from_access_key_id
from localstack.constants import (
    AWS_REGION_US_EAST_1,
    DEFAULT_AWS_ACCOUNT_ID,
)
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import (
    requests_error_response,
    requests_to_flask_response,
)
from localstack.utils.aws.aws_stack import extract_access_key_id_from_auth_header
from localstack.utils.coverage_docs import get_coverage_link_for_service
from localstack.utils.patch import patch
from localstack.utils.strings import snake_to_camel_case
from localstack.utils.threads import FuncThread

LOG = logging.getLogger(__name__)

THREAD_LOCAL = threading.local()

MARKER_APIGW_REQUEST_REGION = "__apigw_request_region__"

AWS_REGION_REGEX = r"(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d"


def get_proxy_request_for_thread():
    try:
        return THREAD_LOCAL.request_context
    except Exception:
        return None


def get_flask_request_for_thread():
    try:
        # Append/cache a converted request (requests.Request) to the the thread-local Flask request.
        #  We use this request object as the invocation context, which may be modified in other places,
        #  e.g., when manually configuring the region in the request context of an incoming API call.
        if not hasattr(request, "_converted_request"):
            request._converted_request = Request(
                url=request.path,
                data=request.data,
                headers=CaseInsensitiveDict(request.headers),
                method=request.method,
            )
        return request._converted_request
    except Exception as e:
        # swallow error: "Working outside of request context."
        if "Working outside" in str(e):
            return None
        raise


def extract_region_from_auth_header(headers) -> Optional[str]:
    auth = headers.get("Authorization") or ""
    region = re.sub(r".*Credential=[^/]+/[^/]+/([^/]+)/.*", r"\1", auth)
    if region == auth:
        return None
    return region


def extract_account_id_from_auth_header(headers) -> Optional[str]:
    if access_key_id := extract_access_key_id_from_auth_header(headers):
        return get_account_id_from_access_key_id(access_key_id)


def extract_account_id_from_headers(headers) -> str:
    return extract_account_id_from_auth_header(headers) or DEFAULT_AWS_ACCOUNT_ID


def extract_region_from_headers(headers) -> str:
    region = headers.get(MARKER_APIGW_REQUEST_REGION)
    # Fix region lookup for certain requests, e.g., API gateway invocations
    #  that do not contain region details in the Authorization header.

    if region:
        return region

    return extract_region_from_auth_header(headers) or AWS_REGION_US_EAST_1


def get_request_context():
    candidates = [get_proxy_request_for_thread, get_flask_request_for_thread]
    for req in candidates:
        context = req()
        if context is not None:
            return context


class RequestContextManager:
    """Context manager which sets the given request context (i.e., region) for the scope of the block."""

    def __init__(self, request_context):
        self.request_context = request_context

    def __enter__(self):
        THREAD_LOCAL.request_context = self.request_context

    def __exit__(self, type, value, traceback):
        THREAD_LOCAL.request_context = None


def get_region_from_request_context():
    """look up region from request context"""

    request_context = get_request_context()
    if not request_context:
        return

    return extract_region_from_headers(request_context.headers)


# TODO: Dead code, to be removed
def configure_region_for_current_request(region_name: str, service_name: str):
    """Manually configure (potentially overwrite) the region in the current request context. This may be
    used by API endpoints that are invoked directly by the user (without specifying AWS Authorization
    headers), to still enable transparent region lookup via aws_stack.get_region() ..."""

    # TODO: leaving import here for now, to avoid circular dependency
    from localstack.utils.aws import aws_stack

    request_context = get_request_context()
    if not request_context:
        LOG.info(
            "Unable to set region '%s' in undefined request context: %s",
            region_name,
            request_context,
        )
        return

    headers = request_context.headers
    auth_header = headers.get("Authorization")
    auth_header = (
        auth_header
        or aws_stack.mock_aws_request_headers(
            service_name, aws_access_key_id=DEFAULT_AWS_ACCOUNT_ID, region_name=AWS_REGION_US_EAST_1
        )["Authorization"]
    )
    auth_header = auth_header.replace("/%s/" % aws_stack.get_region(), "/%s/" % region_name)
    try:
        headers["Authorization"] = auth_header
    except Exception as e:
        if "immutable" not in str(e):
            raise
        _context_to_update = get_proxy_request_for_thread() or request
        _context_to_update.headers = CaseInsensitiveDict({**headers, "Authorization": auth_header})


def mock_request_for_region(service_name: str, account_id: str, region_name: str) -> Request:
    result = Request()
    result.headers["Authorization"] = aws_stack.mock_aws_request_headers(
        service_name, aws_access_key_id=account_id, region_name=region_name
    )["Authorization"]
    return result


def extract_service_name_from_auth_header(headers: Dict) -> Optional[str]:
    try:
        auth_header = headers.get("authorization", "")
        credential_scope = auth_header.split(",")[0].split()[1]
        _, _, _, service, _ = credential_scope.split("/")
        return service
    except Exception:
        return


def patch_moto_request_handling():
    # leave here to avoid import issues
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

    # make sure that we inherit THREAD_LOCAL request contexts to spawned sub-threads
    @patch(FuncThread.__init__)
    def thread_init(fn, self, *args, **kwargs):
        self._req_context = get_request_context()
        return fn(self, *args, **kwargs)

    @patch(FuncThread.run)
    def thread_run(fn, self, *args, **kwargs):
        try:
            if self._req_context:
                THREAD_LOCAL.request_context = self._req_context
        except AttributeError:
            # sometimes there is a race condition where the previous patch has not been applied yet
            pass
        return fn(self, *args, **kwargs)
