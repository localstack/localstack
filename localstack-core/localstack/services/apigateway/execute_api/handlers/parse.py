from localstack.http import Response

from ...models import RestApiDeployment
from ..api import ApiGatewayHandler, ApiGatewayHandlerChain
from ..context import InvocationContext


class InvocationRequestParser(ApiGatewayHandler):
    def __init__(self, deployment: RestApiDeployment, stage: str):
        self.deployment = deployment
        self.stage = stage

    def __call__(
        self, chain: ApiGatewayHandlerChain, context: InvocationContext, response: Response
    ):
        self.context.deployment = self.deployment
        self.context.api_id = self.deployment.localstack_rest_api.rest_api["id"]
        self.context.stage = self.stage
