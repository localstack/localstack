"""A version of the API Gateway provider that uses ASF constructs to dispatch user routes."""
import logging

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.apigateway import TestInvokeMethodRequest, TestInvokeMethodResponse
from localstack.services.apigateway.invocations import invoke_rest_api_from_request
from localstack.services.apigateway.provider import ApigatewayProvider
from localstack.services.apigateway.router_asf import ApigatewayRouter, to_invocation_context
from localstack.services.edge import ROUTER
from localstack.utils.json import parse_json_or_yaml
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
