"""A version of the API Gateway provider that uses ASF constructs to dispatch user routes."""
from collections import defaultdict
from typing import Any, Dict, List

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
from localstack.http import Request, Response, Router
from localstack.http.dispatcher import Handler
from localstack.http.request import restore_payload
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import API_REGIONS
from localstack.services.apigateway.invocations import invoke_rest_api_from_request
from localstack.services.apigateway.provider import ApigatewayProvider
from localstack.services.edge import ROUTER
from localstack.utils.aws.aws_responses import LambdaResponse
from localstack.utils.json import parse_json_or_yaml
from localstack.utils.strings import to_str


def to_invocation_context(
    request: Request, url_params: Dict[str, Any] = None
) -> ApiInvocationContext:
    """
    Converts an HTTP Request object into an ApiInvocationContext.

    :param request: the original request
    :param url_params: the parameters extracted from the URL matching rules
    :return: the ApiInvocationContext
    """
    # FIXME: ApiInvocationContext should be refactored to use werkzeug request object correctly
    method = request.method
    path = request.full_path if request.query_string else request.path
    data = restore_payload(request)
    headers = Headers(request.headers)

    if url_params is None:
        url_params = {}

    # adjust the X-Forwarded-For header
    x_forwarded_for = headers.getlist("X-Forwarded-For")
    x_forwarded_for.append(request.remote_addr)
    x_forwarded_for.append(request.host)
    headers["X-Forwarded-For"] = ", ".join(x_forwarded_for)

    # this is for compatibility with the lower layers of apigw and lambda that make assumptions about header casing
    headers = CaseInsensitiveDict(
        {k.title(): ", ".join(headers.getlist(k)) for k in headers.keys()}
    )

    return ApiInvocationContext(
        method,
        path,
        data,
        headers,
        stage=url_params.get("stage"),
    )


class ApigatewayRouter:
    """
    Simple implementation around a Router to manage dynamic restapi routes (routes added by a user through the
    apigateway API).
    """

    router: Router[Handler]

    def __init__(self, router: Router[Handler]):
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

    def _invoke_rest_api(self, request: Request, url_params: Dict[str, Any]) -> Response:
        invocation_context = to_invocation_context(request, url_params)

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

    def _restapis_user_request_handler(self, request: Request, **url_params):
        return self._invoke_rest_api(request, url_params)

    def _restapis_host_handler(self, request: Request, **url_params) -> Response:
        return self._invoke_rest_api(request, url_params)


class AsfApigatewayProvider(ApigatewayProvider):
    """Modern ASF provider that uses an ApigatewayRouter to dispatch requests to user routes."""

    router: ApigatewayRouter

    def __init__(self, router: ApigatewayRouter = None):
        self.router = router or ApigatewayRouter(router=ROUTER)

    def create_rest_api(self, context: RequestContext, request: CreateRestApiRequest) -> RestApi:
        result: RestApi = super().create_rest_api(context, request)
        API_REGIONS[result["id"]] = context.region
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
            if path_with_query_string := orig_data.get("pathWithQueryString"):
                invocation_context.path_with_query_string = path_with_query_string
            invocation_context.data = data.get("body")
            invocation_context.headers = orig_data.get("headers", {})

        result = invoke_rest_api_from_request(invocation_context)

        # TODO: implement the other TestInvokeMethodResponse parameters
        #   * multiValueHeaders: Optional[MapOfStringToList]
        #   * log: Optional[String]
        #   * latency: Optional[Long]

        return TestInvokeMethodResponse(
            status=result.status_code,
            headers=dict(result.headers),
            body=to_str(result.content),
        )
