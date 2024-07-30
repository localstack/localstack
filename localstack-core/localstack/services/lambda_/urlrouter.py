"""Routing for Lambda function URLs: https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html"""

import base64
import json
import logging
from datetime import datetime
from http import HTTPStatus

from rolo.request import restore_payload

from localstack.aws.api.lambda_ import InvocationType
from localstack.aws.protocol.serializer import gen_amzn_requestid
from localstack.http import Request, Response, Router
from localstack.http.dispatcher import Handler
from localstack.services.lambda_.api_utils import FULL_FN_ARN_PATTERN
from localstack.services.lambda_.invocation.lambda_models import InvocationResult
from localstack.services.lambda_.invocation.lambda_service import LambdaService
from localstack.services.lambda_.invocation.models import lambda_stores
from localstack.utils.aws.request_context import AWS_REGION_REGEX
from localstack.utils.strings import long_uid, to_bytes, to_str
from localstack.utils.time import TIMESTAMP_READABLE_FORMAT, mktime, timestamp
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)


class FunctionUrlRouter:
    router: Router[Handler]
    lambda_service: LambdaService

    def __init__(self, router: Router[Handler], lambda_service: LambdaService):
        self.router = router
        self.registered = False
        self.lambda_service = lambda_service

    def register_routes(self) -> None:
        if self.registered:
            LOG.debug("Skipped Lambda URL route registration (routes already registered).")
            return
        self.registered = True

        LOG.debug("Registering parameterized Lambda routes.")

        self.router.add(
            "/",
            host=f"<api_id>.lambda-url.<regex('{AWS_REGION_REGEX}'):region>.<regex('.*'):server>",
            endpoint=self.handle_lambda_url_invocation,
            defaults={"path": ""},
        )
        self.router.add(
            "/<path:path>",
            host=f"<api_id>.lambda-url.<regex('{AWS_REGION_REGEX}'):region>.<regex('.*'):server>",
            endpoint=self.handle_lambda_url_invocation,
        )

    def handle_lambda_url_invocation(
        self,
        request: Request,
        api_id: str,
        region: str,
        **url_params: str,
    ) -> Response:
        response = Response()
        response.mimetype = "application/json"

        lambda_url_config = None

        for account_id in lambda_stores.keys():
            store = lambda_stores[account_id][region]
            for fn in store.functions.values():
                for url_config in fn.function_url_configs.values():
                    # AWS tags are case sensitive, but domains are not.
                    # So we normalize them here to maximize both AWS and RFC
                    # conformance
                    if url_config.url_id.lower() == api_id.lower():
                        lambda_url_config = url_config

        # TODO: check if errors are different when the URL has existed previously
        if lambda_url_config is None:
            LOG.info("Lambda URL %s does not exist", request.url)
            response.data = '{"Message":null}'
            response.status = 403
            response.headers["x-amzn-ErrorType"] = "AccessDeniedException"
            # TODO: x-amzn-requestid
            return response

        event = event_for_lambda_url(api_id, request)

        match = FULL_FN_ARN_PATTERN.search(lambda_url_config.function_arn).groupdict()

        result = self.lambda_service.invoke(
            function_name=match.get("function_name"),
            qualifier=match.get("qualifier"),
            account_id=match.get("account_id"),
            region=match.get("region_name"),
            invocation_type=InvocationType.RequestResponse,
            client_context="{}",  # TODO: test
            payload=to_bytes(json.dumps(event)),
            request_id=gen_amzn_requestid(),
        )
        if result.is_error:
            response = Response("Internal Server Error", HTTPStatus.BAD_GATEWAY)
        else:
            response = lambda_result_to_response(result)
        return response


def event_for_lambda_url(api_id: str, request: Request) -> dict:
    partitioned_uri = request.full_path.partition("?")
    raw_path = partitioned_uri[0]
    raw_query_string = partitioned_uri[2]

    query_string_parameters = {k: ",".join(request.args.getlist(k)) for k in request.args.keys()}

    now = datetime.utcnow()
    readable = timestamp(time=now, format=TIMESTAMP_READABLE_FORMAT)
    if not any(char in readable for char in ["+", "-"]):
        readable += "+0000"

    data = restore_payload(request)
    headers = request.headers
    source_ip = headers.get("Remote-Addr", "")
    request_context = {
        "accountId": "anonymous",
        "apiId": api_id,
        "domainName": headers.get("Host", ""),
        "domainPrefix": api_id,
        "http": {
            "method": request.method,
            "path": raw_path,
            "protocol": "HTTP/1.1",
            "sourceIp": source_ip,
            "userAgent": headers.get("User-Agent", ""),
        },
        "requestId": long_uid(),
        "routeKey": "$default",
        "stage": "$default",
        "time": readable,
        "timeEpoch": mktime(ts=now, millis=True),
    }

    content_type = headers.get("Content-Type", "").lower()
    content_type_is_text = any(text_type in content_type for text_type in ["text", "json", "xml"])

    is_base64_encoded = not (data.isascii() and content_type_is_text) if data else False
    body = base64.b64encode(data).decode() if is_base64_encoded else data
    if isinstance(body, bytes):
        body = to_str(body)

    ignored_headers = ["connection", "x-localstack-tgt-api", "x-localstack-request-url"]
    event_headers = {k.lower(): v for k, v in headers.items() if k.lower() not in ignored_headers}

    event_headers.update(
        {
            "x-amzn-tls-cipher-suite": "ECDHE-RSA-AES128-GCM-SHA256",
            "x-amzn-tls-version": "TLSv1.2",
            "x-forwarded-proto": "http",
            "x-forwarded-for": source_ip,
            "x-forwarded-port": str(localstack_host().port),
        }
    )

    event = {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": raw_path,
        "rawQueryString": raw_query_string,
        "headers": event_headers,
        "queryStringParameters": query_string_parameters,
        "requestContext": request_context,
        "body": body,
        "isBase64Encoded": is_base64_encoded,
    }

    if not data:
        event.pop("body")

    return event


def lambda_result_to_response(result: InvocationResult):
    response = Response()

    # Set default headers
    response.headers.update(
        {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "x-amzn-requestid": result.request_id,
            "x-amzn-trace-id": long_uid(),  # TODO: get the proper trace id here
        }
    )

    original_payload = to_str(result.payload)
    parsed_result = json.loads(original_payload)

    # patch to fix whitespaces
    # TODO: check if this is a downstream issue of invocation result serialization
    original_payload = json.dumps(parsed_result, separators=(",", ":"))

    if isinstance(parsed_result, str):
        # a string is a special case here and is returned as-is
        response.data = parsed_result
    elif isinstance(parsed_result, dict):
        # if it's a dict it might be a proper response
        if isinstance(parsed_result.get("headers"), dict):
            response.headers.update(parsed_result.get("headers"))
        if "statusCode" in parsed_result:
            response.status_code = int(parsed_result["statusCode"])
        if "body" not in parsed_result:
            # TODO: test if providing a status code but no body actually works
            response.data = original_payload
        elif isinstance(parsed_result.get("body"), dict):
            response.data = json.dumps(parsed_result.get("body"))
        elif parsed_result.get("isBase64Encoded", False):
            body_bytes = to_bytes(to_str(parsed_result.get("body", "")))
            decoded_body_bytes = base64.b64decode(body_bytes)
            response.data = decoded_body_bytes
        else:
            response.data = parsed_result.get("body")
    else:
        response.data = original_payload

    return response
