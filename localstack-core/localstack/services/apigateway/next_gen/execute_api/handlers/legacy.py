from rolo import Request
from werkzeug.exceptions import NotFound

from localstack.http import Response
from localstack.services.apigateway.helpers import get_api_account_id_and_region
from localstack.services.apigateway.invocations import invoke_rest_api_from_request
from localstack.services.apigateway.router_asf import convert_response, to_invocation_context

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext


# Copy-pasted from `router_asf.py`, to migrate parts slowly away
# TODO: first thing would be to refactor `to_invocation_context` in order to simplify it
# when we continue, every new handler should not rely on this invocation context but on the passed `InvocationContext`
# in the handler
def invoke_rest_api(request: Request, api_id: str, stage: str) -> Response:
    url_params = {
        "api_id": api_id,
        "stage": stage,
        "path": "",  # TODO: seems for now nothing using the path from the router, manually parsed from RAW_URI
    }

    account_id, region_name = get_api_account_id_and_region(api_id)
    if not region_name:
        return Response(status=404)
    invocation_context = to_invocation_context(request, url_params)
    invocation_context.region_name = region_name
    invocation_context.account_id = account_id
    # TODO: copy paste `invoke_rest_api_from_request` in order to remove the parts we will migrate
    result = invoke_rest_api_from_request(invocation_context)
    if result is not None:
        return convert_response(result)
    raise NotFound()


class LegacyHandler(RestApiGatewayHandler):
    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        invocation_response = invoke_rest_api(
            context.request, api_id=context.api_id, stage=context.stage
        )
        response.update_from(invocation_response)
