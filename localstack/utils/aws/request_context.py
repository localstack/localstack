import logging
import re
import threading

from flask import request
from requests.models import Request
from requests.structures import CaseInsensitiveDict

from localstack import config
from localstack.utils.common import empty_context_manager
from localstack.utils.run import FuncThread

LOG = logging.getLogger(__name__)

THREAD_LOCAL = threading.local()

MARKER_APIGW_REQUEST_REGION = "__apigw_request_region__"


def get_proxy_request_for_thread():
    try:
        return THREAD_LOCAL.request_context
    except Exception:
        return None


def get_flask_request_for_thread():
    try:
        return Request(
            url=request.path,
            data=request.data,
            headers=CaseInsensitiveDict(request.headers),
            method=request.method,
        )
    except Exception as e:
        # swallow error: "Working outside of request context."
        if "Working outside" in str(e):
            return None
        raise


def extract_region_from_auth_header(headers):
    # TODO: use method from aws_stack directly (leaving import here for now, to avoid circular dependency)
    from localstack.utils.aws import aws_stack

    auth = headers.get("Authorization") or ""
    region = re.sub(r".*Credential=[^/]+/[^/]+/([^/]+)/.*", r"\1", auth)
    if region == auth:
        return None
    region = region or aws_stack.get_local_region()
    return region


def get_request_context():
    candidates = [get_proxy_request_for_thread(), get_flask_request_for_thread()]
    for req in candidates:
        if req is not None:
            return req


class RequestContextManager(object):
    """Context manager which sets the given request context (i.e., region) for the scope of the block."""

    def __init__(self, request_context):
        self.request_context = request_context

    def __enter__(self):
        THREAD_LOCAL.request_context = self.request_context

    def __exit__(self, type, value, traceback):
        THREAD_LOCAL.request_context = None


def get_region_from_request_context():
    """look up region from request context"""

    if config.USE_SINGLE_REGION:
        return

    request_context = get_request_context()
    if not request_context:
        return
    region = extract_region_from_auth_header(request_context.headers)

    # Fix region lookup for certain requests, e.g., API gateway invocations
    #  that do not contain region details in the Authorization header.
    region = request_context.headers.get(MARKER_APIGW_REQUEST_REGION) or region

    return region


def patch_request_handling():

    if config.USE_SINGLE_REGION:
        return

    # TODO: move into generic_proxy.py, instead of patching here (leaving import here for now, to avoid circular dependency)
    from localstack.services import generic_proxy

    def modify_and_forward(method=None, path=None, data_bytes=None, headers=None, *args, **kwargs):
        """Patch proxy forward method and store request in thread local."""
        request_context = get_proxy_request_for_thread()
        context_manager = empty_context_manager()
        if not request_context:
            request_context = Request(url=path, data=data_bytes, headers=headers, method=method)
            context_manager = RequestContextManager(request_context)
        with context_manager:
            result = modify_and_forward_orig(
                method, path, data_bytes=data_bytes, headers=headers, *args, **kwargs
            )
        return result

    modify_and_forward_orig = generic_proxy.modify_and_forward
    generic_proxy.modify_and_forward = modify_and_forward

    # make sure that we inherit THREAD_LOCAL request contexts to spawned sub-threads

    def thread_init(self, *args, **kwargs):
        self._req_context = get_request_context()
        return thread_init_orig(self, *args, **kwargs)

    def thread_run(self, *args, **kwargs):
        if self._req_context:
            THREAD_LOCAL.request_context = self._req_context
        return thread_run_orig(self, *args, **kwargs)

    thread_run_orig = FuncThread.run
    FuncThread.run = thread_run
    thread_init_orig = FuncThread.__init__
    FuncThread.__init__ = thread_init
