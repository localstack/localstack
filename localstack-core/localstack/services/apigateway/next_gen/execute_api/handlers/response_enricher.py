from localstack.aws.api.apigateway import IntegrationType
from localstack.http import Response
from localstack.services.apigateway.next_gen.execute_api.api import (
    RestApiGatewayHandler,
    RestApiGatewayHandlerChain,
)
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.utils.strings import short_uid


class InvocationResponseEnricher(RestApiGatewayHandler):
    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        headers = response.headers

        headers.set("x-amzn-RequestId", context.context_variables["requestId"])

        # Todo, as we go into monitoring, we will want to have these values come from the context?
        headers.set("x-amz-apigw-id", short_uid() + "=")
        if (
            context.integration
            and context.integration["type"] != IntegrationType.HTTP_PROXY
            and not context.context_variables.get("error")
        ):
            headers.set("X-Amzn-Trace-Id", short_uid())  # TODO
