"""A version of the API Gateway provider that uses ASF constructs to dispatch user routes."""
import logging
from typing import Any, Dict

from requests.structures import CaseInsensitiveDict
from werkzeug.datastructures import Headers
from werkzeug.exceptions import NotFound

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.apigateway import (
    CreateRestApiRequest,
    RestApi,
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

LOG = logging.getLogger(__name__)


def to_invocation_context(
    request: Request, url_params: Dict[str, Any] = None
) -> ApiInvocationContext:
    """
    Converts an HTTP Request object into an ApiInvocationContext.

    :param request: the original request
    :param url_params: the parameters extracted from the URL matching rules
    :return: the ApiInvocationContext
    """
    method = request.method
    path = request.full_path if request.query_string else request.path
    data = restore_payload(request)
    headers = Headers(request.headers)

    # adjust the X-Forwarded-For header
    x_forwarded_for = headers.getlist("X-Forwarded-For")
    x_forwarded_for.append(request.remote_addr)
    x_forwarded_for.append(request.host)
    headers["X-Forwarded-For"] = ", ".join(x_forwarded_for)

    # this is for compatibility with the lower layers of apigw and lambda that make assumptions about header casing
    headers = CaseInsensitiveDict(
        {k.title(): ", ".join(headers.getlist(k)) for k in headers.keys()}
    )

    # FIXME: Use the already parsed url params instead of parsing them into the ApiInvocationContext part-by-part.
    #   We already would have all params at hand to avoid _all_ the parsing, but the parsing
    #   has side-effects (f.e. setting the region in a thread local)!
    #   It would be best to use a small (immutable) context for the already parsed params and the Request object
    #   and use it everywhere.
    return ApiInvocationContext(method, path, data, headers, stage=url_params.get("stage"))


class AsfApigatewayProvider(ApigatewayProvider):
    """Modern ASF provider that uses the router handler to dispatch requests to user routes."""

    router: Router[Handler]

    def __init__(self, router: Router[Handler] = None):
        self.router = router or ROUTER

    def on_after_init(self):
        super(AsfApigatewayProvider, self).on_after_init()
        self.register_routes()

    def create_rest_api(self, context: RequestContext, request: CreateRestApiRequest) -> RestApi:
        result: RestApi = super().create_rest_api(context, request)
        API_REGIONS[result["id"]] = context.region
        return result

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

    def register_routes(self) -> None:
        """Registers all API Gateway user invocation routes as parameterized routes."""
        # add the canonical execute-api handler
        self.router.add(
            "/",
            host="<api_id>.execute-api.<regex('.*'):server>",
            endpoint=self.invoke_rest_api,
            defaults={"path": "", "stage": None},
        )
        self.router.add(
            "/<stage>/",
            host="<api_id>.execute-api.<regex('.*'):server>",
            endpoint=self.invoke_rest_api,
            defaults={"path": ""},
        )
        self.router.add(
            "/<stage>/<path:path>",
            host="<api_id>.execute-api.<regex('.*'):server>",
            endpoint=self.invoke_rest_api,
        )

        # add the localstack-specific _user_request_ routes
        self.router.add(
            "/restapis/<api_id>/<stage>/_user_request_",
            endpoint=self.invoke_rest_api,
            defaults={"path": ""},
        )
        self.router.add(
            "/restapis/<api_id>/<stage>/_user_request_/<path:path>",
            endpoint=self.invoke_rest_api,
        )

    @staticmethod
    def invoke_rest_api(request: Request, **url_params: Dict[str, Any]) -> Response:
        if not url_params["api_id"] in API_REGIONS:
            return Response(status=404)
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
