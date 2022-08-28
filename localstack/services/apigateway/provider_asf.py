"""A version of the API Gateway provider that uses ASF constructs to dispatch user routes."""
import logging

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.apigateway import TestInvokeMethodRequest, TestInvokeMethodResponse
from localstack.http import Request
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.invocations import invoke_rest_api_from_request
from localstack.services.apigateway.provider import ApigatewayProvider
from localstack.services.apigateway.router_asf import ApigatewayRouter
from localstack.services.edge import ROUTER
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)


class AsfApigatewayProvider(ApigatewayProvider):
    """
    Modern ASF provider that uses the ApigatwayRouter (based on the router handler)
    to dispatch requests to user routes.
    """

    router: ApigatewayRouter

    def __init__(self, router: ApigatewayRouter = None):
        self.router = router or ApigatewayRouter(ROUTER)

    def on_after_init(self):
        super(AsfApigatewayProvider, self).on_after_init()
        self.router.register_routes()

    @handler("TestInvokeMethod", expand=False)
    def test_invoke_method(
        self, context: RequestContext, request: TestInvokeMethodRequest
    ) -> TestInvokeMethodResponse:
        method = request.get("httpMethod")
        path_query_string = request.get("pathWithQueryString")
        api_id = request.get("restApiId")

        path = "/"
        query_string = ""
        headers = request.get("headers")
        body = request.get("body")

        url_params = {"api_id": api_id}
        if path_query_string:
            path, query_string = path_query_string.split("?", 1)
            url_params |= {"path": path}

        http_request = Request(
            method=method, path=path, query_string=query_string, body=body, headers=headers
        )
        invocation_context = ApiInvocationContext(http_request, url_params=url_params)

        result = invoke_rest_api_from_request(invocation_context)

        # TODO: implement the other TestInvokeMethodResponse parameters
        #   * multiValueHeaders: Optional[MapOfStringToList]
        #   * log: Optional[String]
        #   * latency: Optional[Long]

        return TestInvokeMethodResponse(
            status=result.status_code,
            headers=dict(result.headers),
            body=to_str(result.get_data()),
        )
