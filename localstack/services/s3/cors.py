import logging
import re
from typing import Optional, Protocol, Tuple

from werkzeug.datastructures import Headers

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import (
    AccessForbidden,
    BadRequest,
    CORSConfiguration,
    CORSRule,
    CORSRules,
)
from localstack.aws.chain import Handler, HandlerChain

# TODO: refactor those to expose the needed methods
from localstack.aws.handlers.cors import CorsEnforcer, CorsResponseEnricher
from localstack.aws.protocol.op_router import RestServiceOperationRouter
from localstack.aws.protocol.service_router import get_service_catalog
from localstack.config import S3_VIRTUAL_HOSTNAME
from localstack.http import Request, Response
from localstack.services.s3.utils import S3_VIRTUAL_HOSTNAME_REGEX

# TODO: add more logging statements
LOG = logging.getLogger(__name__)

_s3_virtual_host_regex = re.compile(S3_VIRTUAL_HOSTNAME_REGEX)
FAKE_HOST_ID = "9Gjjt1m+cjU4OPvX9O9/8RuvnG41MRb/18Oux2o5H5MY7ISNTlXN+Dz9IG62/ILVxhAGI0qyPfg="

# TODO: refactor those to expose the needed methods maybe in another way that both can import
add_default_headers = CorsResponseEnricher.add_cors_headers
is_origin_allowed_default = CorsEnforcer.is_cors_origin_allowed


class BucketCorsIndex(Protocol):
    @property
    def cors(self) -> dict[str, CORSConfiguration]:
        raise NotImplementedError

    @property
    def buckets(self) -> set[str]:
        raise NotImplementedError

    def invalidate(self):
        raise NotImplementedError


class S3CorsHandler(Handler):
    bucket_cors_index: BucketCorsIndex

    def __init__(self, bucket_cors_index: BucketCorsIndex):
        self.bucket_cors_index = bucket_cors_index
        self._service = get_service_catalog().get("s3")
        self._s3_op_router = RestServiceOperationRouter(self._service)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        self.handle_cors(chain, context, response)

    def pre_parse_s3_request(self, request: Request) -> Tuple[bool, Optional[str]]:
        """
        Parse the request to try to determine if it's directed towards S3. It tries to match on host, then check
        if the targeted bucket exists. If we could not determine it was a s3 request from the host, but the first
        element in the path contains an existing bucket, we can think it's S3.
        :param request: Request from the context
        :return: is_s3, whether we're certain it's a s3 request, and bucket_name if the bucket exists
        """
        is_s3: bool
        bucket_name: str

        path = request.path
        host = request.host

        # first, try to figure out best-effort whether the request is an s3 request
        if host.startswith(S3_VIRTUAL_HOSTNAME):
            is_s3 = True
            bucket_name = path.split("/")[1]
        # try to extract the bucket from the hostname (the "in" check is a minor optimization)
        elif ".s3" in host and (match := _s3_virtual_host_regex.match(host)):
            is_s3 = True
            bucket_name = match.group("bucket")
        # otherwise we're not sure, and whether it's s3 depends on whether the bucket exists. check later
        else:
            is_s3 = False
            bucket_name = path.split("/")[1]

        existing_buckets = self.bucket_cors_index.buckets
        if bucket_name not in existing_buckets:
            return is_s3, None

        return True, bucket_name

    def handle_cors(self, chain: HandlerChain, context: RequestContext, response: Response):
        """
        Handle CORS for S3 requests. S3 CORS rules can be configured.
        https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html
        https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html
        """

        # this is used with the new ASF S3 provider
        # although, we could use it to pre-parse the request and set the context to move the service name parser
        if config.DISABLE_CUSTOM_CORS_S3:
            return

        request = context.request
        is_s3, bucket_name = self.pre_parse_s3_request(context.request)

        if not is_s3:
            # continue the chain, let the default CORS handler take care of the request
            return

        # set the service so that the regular CORS enforcer knows it needs to ignore this request
        context.service = self._service

        is_options_request = request.method == "OPTIONS"

        def stop_options_chain():
            """
            Stops the chain to avoid the OPTIONS request being parsed. The request is ready to be returned to the
            client. We also need to add specific headers normally added by the serializer for regular requests.
            """
            request_id = context.request_id
            response.headers["x-amz-request-id"] = request_id
            response.headers[
                "x-amz-id-2"
            ] = f"MzRISOwyjmnup{request_id}7/JypPGXLh0OVFGcJaaO3KW/hRAqKOpIEEp"

            response.set_response(b"")
            response.headers.pop("Content-Type", None)
            chain.stop()

        # check the presence of the Origin header. If not there, it means the request is not concerned about CORS
        if not (origin := request.headers.get("Origin")):
            if is_options_request:
                context.operation = self._get_op_from_request(request)
                raise BadRequest(
                    "Insufficient information. Origin request header needed.", HostId=FAKE_HOST_ID
                )
            else:
                # If the header is missing, Amazon S3 doesn't treat the request as a cross-origin request,
                # and doesn't send CORS response headers in the response.
                return

        is_origin_allowed_by_default = is_origin_allowed_default(request.headers)

        # The bucket does not exist or does have CORS configured
        # might apply default LS CORS or raise AWS specific errors
        if not bucket_name or bucket_name not in self.bucket_cors_index.cors:
            # if the origin is allowed by localstack per default, adds default LS CORS headers
            if is_origin_allowed_by_default:
                add_default_headers(
                    response_headers=response.headers, request_headers=request.headers
                )
                if is_options_request:
                    stop_options_chain()
                return
            # if the origin is not allowed, raise a specific S3 options in case of OPTIONS
            # if it's a regular request, simply return without adding CORS
            else:
                if is_options_request:
                    if not bucket_name:
                        message = "CORSResponse: Bucket not found"
                    else:
                        message = "CORSResponse: CORS is not enabled for this bucket."

                    context.operation = self._get_op_from_request(request)
                    raise AccessForbidden(
                        message,
                        HostId=FAKE_HOST_ID,
                        Method=request.headers.get("Access-Control-Request-Method", "OPTIONS"),
                        ResourceType="BUCKET",
                    )

                # we return without adding any CORS headers, we could even block the request with 403 here
                return

        rules = self.bucket_cors_index.cors[bucket_name]["CORSRules"]

        if not (rule := self.match_rules(request, rules)):
            if is_options_request:
                context.operation = self._get_op_from_request(request)
                raise AccessForbidden(
                    "CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.",
                    HostId=FAKE_HOST_ID,
                    Method=request.headers.get("Access-Control-Request-Method"),
                    ResourceType="OBJECT",
                )

            if is_options_request:
                stop_options_chain()
            return

        is_wildcard = "*" in rule["AllowedOrigins"]
        # this is contrary to CORS specs. The Access-Control-Allow-Origin should always return the request Origin
        response.headers["Access-Control-Allow-Origin"] = origin if not is_wildcard else "*"
        if not is_wildcard:
            response.headers["Access-Control-Allow-Credentials"] = "true"

        response.headers[
            "Vary"
        ] = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"

        response.headers["Access-Control-Allow-Methods"] = ", ".join(rule["AllowedMethods"])

        if requested_headers := request.headers.get("Access-Control-Request-Headers"):
            # if the rule matched, it means all Requested Headers are allowed
            response.headers["Access-Control-Allow-Headers"] = requested_headers.lower()

        if expose_headers := rule.get("ExposeHeaders"):
            response.headers["Access-Control-Expose-Headers"] = ", ".join(expose_headers)

        if max_age := rule.get("MaxAgeSeconds"):
            response.headers["Access-Control-Max-Age"] = str(max_age)

        if is_options_request:
            stop_options_chain()

    def invalidate_cache(self):
        self.bucket_cors_index.invalidate()

    def match_rules(self, request: Request, rules: CORSRules) -> Optional[CORSRule]:
        """
        Try to match the request to the bucket rules. How to match rules:
          - The request's Origin header must match AllowedOrigin elements.
          - The request method (for example, GET, PUT, HEAD, and so on) or the Access-Control-Request-Method
            header in case of a pre-flight OPTIONS request must be one of the AllowedMethod elements.
          - Every header specified in the Access-Control-Request-Headers request header of a pre-flight request
            must match an AllowedHeader element.
        :param request: RequestContext:
        :param rules: CORSRules: the bucket CORS rules
        :return: return a CORSRule if it finds a match, or None
        """
        headers = request.headers
        method = request.method
        for rule in rules:
            if matched_rule := self._match_rule(rule, method, headers):
                return matched_rule

    @staticmethod
    def _match_rule(rule: CORSRule, method: str, headers: Headers) -> Optional[CORSRule]:
        """
        Check if the request method and headers matches the given CORS rule.
        :param rule: CORSRule: a CORS Rule from the bucket
        :param method: HTTP method of the request
        :param headers: Headers of the request
        :return: CORSRule if the rule match, or None
        """
        # AWS treats any method as an OPTIONS if it has the specific OPTIONS CORS headers
        request_method = headers.get("Access-Control-Request-Method") or method
        origin = headers.get("Origin")
        if request_method not in rule["AllowedMethods"]:
            return

        if "*" not in rule["AllowedOrigins"] and origin not in rule["AllowedOrigins"]:
            return

        if request_headers := headers.get("Access-Control-Request-Headers"):
            if not (allowed_headers := rule.get("AllowedHeaders")):
                return

            lower_case_allowed_headers = {header.lower() for header in allowed_headers}
            if "*" not in allowed_headers and not all(
                header in lower_case_allowed_headers
                for header in request_headers.lower().split(", ")
            ):
                return

        return rule

    def _get_op_from_request(self, request: Request):
        try:
            op, _ = self._s3_op_router.match(request)
            return op
        except Exception:
            # if we can't parse the request, just set GetObject
            return self._service.operation_model("GetObject")


def s3_cors_request_handler(chain: HandlerChain, context: RequestContext, response: Response):
    """
    Handler to add default CORS headers to S3 operations not concerned with CORS configuration
    """
    # if DISABLE_CUSTOM_CORS_S3 is true, the default CORS handling will take place, so we won't need to do it here
    if config.DISABLE_CUSTOM_CORS_S3:
        return

    if not context.service or context.service.service_name != "s3":
        return

    if not context.operation or context.operation.name not in ("ListBuckets", "CreateBucket"):
        return

    if not config.DISABLE_CORS_CHECKS and not is_origin_allowed_default(context.request.headers):
        LOG.info(
            "Blocked CORS request from forbidden origin %s",
            context.request.headers.get("origin") or context.request.headers.get("referer"),
        )
        response.status_code = 403
        chain.terminate()

    add_default_headers(response_headers=response.headers, request_headers=context.request.headers)
