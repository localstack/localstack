import json

from rolo import Response

from localstack.aws.api.apigateway import GatewayResponse
from localstack.services.apigateway.next_gen.execute_api.api import (
    RestApiGatewayExceptionHandler,
    RestApiGatewayHandlerChain,
)
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    BaseGatewayException,
)


class GatewayExceptionHandler(RestApiGatewayExceptionHandler):
    """
    Exception handler that serializes the Gateway Responses
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        exception: Exception,
        context: RestApiInvocationContext,
        response: Response,
    ):
        # We only handle Gateway Responses here. We let other Exceptions bubble up.
        if not isinstance(exception, BaseGatewayException):
            return

        error = self.create_exception_response(exception, context)
        if error:
            response.update_from(error)

    def create_exception_response(
        self, exception: BaseGatewayException, context: RestApiInvocationContext
    ):
        gateway_response = self._get_gateway_response(exception, context)

        # TODO apply responseTemplates to the content. We should also handle the default simply by managing the default
        #  template body `{"message":$context.error.messageString}`
        content = {"message": exception.message}

        # TODO apply responseParameters to the headers and get content-type from the gateway_response
        headers = {"content-type": "application/json"}

        status_code = gateway_response.get("statusCode", exception.status_code)

        return Response(response=json.dumps(content), headers=headers, status=status_code)

    def _get_gateway_response(
        self, exception: BaseGatewayException, context: RestApiInvocationContext
    ) -> GatewayResponse:
        """Returns the user configured GatewayResponse dict. If no"""
        responses = context.deployment.localstack_rest_api.gateway_responses
        if response := responses.get(exception.type):
            return response
        if response := responses.get(exception.default_type):
            return response
        return {}
