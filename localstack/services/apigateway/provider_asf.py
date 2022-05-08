"""A version of the API Gateway provider that uses ASF constructs to dispatch user routes."""
import json
import re
from collections import defaultdict
from typing import Dict, List

from requests.structures import CaseInsensitiveDict
from werkzeug.datastructures import Headers
from werkzeug.exceptions import NotFound
from werkzeug.routing import Rule

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.apigateway import (
    CreateRestApiRequest,
    RestApi,
    String,
    TestInvokeMethodRequest,
    TestInvokeMethodResponse,
)
from localstack.aws.protocol.op_router import RestServiceOperationRouter
from localstack.aws.proxy import AwsApiListener
from localstack.aws.spec import load_service
from localstack.http import Request, Response, Router
from localstack.http.dispatcher import Handler
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import API_REGIONS
from localstack.services.apigateway.invocations import invoke_rest_api_from_request
from localstack.services.apigateway.provider import ApigatewayProvider
from localstack.services.edge import ROUTER
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import LambdaResponse, requests_response
from localstack.utils.json import parse_json_or_yaml
from localstack.utils.strings import to_str


class AsfApigatewayApiListener(AwsApiListener):
    def return_response(self, method, path, data, headers, response):
        # TODO: clean up logic below!

        # fix backend issue (missing support for API documentation)
        if (
            re.match(r"/restapis/[^/]+/documentation/versions", path)
            and response.status_code == 404
        ):
            return requests_response({"position": "1", "items": []})

        # keep track of API regions for faster lookup later on
        # TODO - to be removed - see comment for API_REGIONS variable
        if method == "POST" and path == "/restapis":
            content = json.loads(to_str(response.content))
            api_id = content["id"]
            region = aws_stack.extract_region_from_auth_header(headers)
            API_REGIONS[api_id] = region


def to_invocation_context(request: Request) -> ApiInvocationContext:
    """
    Converts an HTTP Request object into an ApiInvocationContext.

    :param request: the original request
    :return: the ApiInvocationContext
    """
    # FIXME: ApiInvocationContext should be refactored to use werkzeug request object correctly
    method = request.method
    path = request.full_path if request.query_string else request.path
    data = request.get_data(cache=True) or b""
    headers = Headers(request.headers)

    if "X-Forwarded-For" in headers:
        headers["X-Forwarded-For"] = headers["X-Forwarded-For"] + ", " + request.server[0]
    else:
        headers["X-Forwarded-For"] = request.remote_addr + ", " + request.server[0]

    # this is for compatibility with the lower layers of apigw and lambda that make assumptions about header casing
    headers = CaseInsensitiveDict(
        {k.title(): ", ".join(headers.getlist(k)) for k in set(headers.keys())}
    )

    return ApiInvocationContext(
        method,
        path,
        data,
        headers,
    )


class ApigatewayRouter:
    """
    Simple implementation around a Router to manage dynamic restapi routes (routes added by a user through the
    apigateway API).
    """

    router: Router[Handler]

    def __init__(self, router: Router[Handler]):
        self.op_router = RestServiceOperationRouter(load_service("apigateway"))
        self.router_rules: Dict[str, List[Rule]] = defaultdict(list)
        self.router = router

    def add_rest_api(self, rest_api: RestApi) -> None:
        """
        Adds a route for the given RestApi.
        :param rest_api: the RestApi to add
        """
        # TODO: probably it is better to have a parameterized handler and only one rule, rather than creating a new
        #  rule for every rest API. the more rules there are, the slower the routing will be. on the other hand,
        #  regex matching could be just as slow. need to check!
        api_id = rest_api["id"]

        # add the canonical execute-api handler
        self.router_rules[api_id].append(
            self.router.add(
                "/",
                host=f"{api_id}.execute-api.<regex('.*'):server>",
                endpoint=self._restapis_host_handler,
            )
        )
        self.router_rules[api_id].append(
            self.router.add(
                "/<path:path>",
                host=f"{api_id}.execute-api.<regex('.*'):server>",
                endpoint=self._restapis_host_handler,
            )
        )

        # add the localstack-specific _user_request_ handler
        self.router_rules[api_id].append(
            self.router.add(
                f"/restapis/{api_id}/<stage>/_user_request_",
                endpoint=self._restapis_user_request_handler,
            )
        )
        self.router_rules[api_id].append(
            self.router.add(
                f"/restapis/{api_id}/<stage>/_user_request_/<path:path>",
                endpoint=self._restapis_user_request_handler,
            )
        )

    def remove_rest_api(self, rest_api_id: str) -> None:
        """
        Removes the given rest api.
        :param rest_api_id: the rest api to remove
        """
        rules = self.router_rules.pop(rest_api_id, [])
        for rule in rules:
            self.router.remove_rule(rule)

    def _restapis_handler(self, request: Request, path=None) -> Response:
        invocation_context = to_invocation_context(request)

        result = invoke_rest_api_from_request(invocation_context)
        if result is not None:
            if isinstance(result, LambdaResponse):
                headers = Headers(dict(result.headers))
                for k, values in result.multi_value_headers.items():
                    for value in values:
                        headers.add(k, value)
            else:
                headers = dict(result.headers)
            return Response(
                response=result.content,
                status=result.status_code,
                headers=headers,
            )

        raise NotFound()

    def _restapis_user_request_handler(self, request: Request, stage=None, path=None):
        return self._restapis_handler(request, path)

    def _restapis_host_handler(self, request: Request, path=None, server=None) -> Response:
        return self._restapis_handler(request)


class AsfApigatewayProvider(ApigatewayProvider):
    """Modern ASF provider that uses an ApigatewayRouter to dispatch requests to user routes."""

    router: ApigatewayRouter

    def __init__(self, router: ApigatewayRouter = None):
        self.router = router or ApigatewayRouter(router=ROUTER)

    def create_rest_api(self, context: RequestContext, request: CreateRestApiRequest) -> RestApi:
        result = super().create_rest_api(context, request)
        self.router.add_rest_api(result)
        return result

    def delete_rest_api(self, context: RequestContext, rest_api_id: String) -> None:
        super().delete_rest_api(context, rest_api_id)
        self.router.remove_rest_api(rest_api_id)

    @handler("TestInvokeMethod", expand=False)
    def test_invoke_method(
        self, context: RequestContext, request: TestInvokeMethodRequest
    ) -> TestInvokeMethodResponse:

        invocation_context = to_invocation_context(context.request)
        invocation_context.method = request["httpMethod"]

        if data := parse_json_or_yaml(to_str(invocation_context.data or b"")):
            orig_data = data
            path_with_query_string = orig_data.get("pathWithQueryString", None)
            if path_with_query_string:
                invocation_context.path_with_query_string = path_with_query_string
            invocation_context.data = data.get("body")
            invocation_context.headers = orig_data.get("headers", {})

        result = invoke_rest_api_from_request(invocation_context)

        # FIXME: there are also multi-value-headers, log, and latency
        return TestInvokeMethodResponse(
            status=result.status_code,
            headers=dict(result.headers),
            body=to_str(result.content),
        )
