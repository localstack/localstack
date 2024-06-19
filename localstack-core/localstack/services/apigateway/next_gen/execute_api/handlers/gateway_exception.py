import json
import logging

from rolo import Response

from localstack.aws.api.apigateway import GatewayResponse, GatewayResponseType
from localstack.services.apigateway.next_gen.execute_api.api import (
    RestApiGatewayExceptionHandler,
    RestApiGatewayHandlerChain,
)
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    BaseGatewayException,
    Default5xxError,
    build_default_response,
)

LOG = logging.getLogger(__name__)


class GatewayExceptionHandler(RestApiGatewayExceptionHandler):
    """
    Exception handler that serializes the Gateway Exceptions into Gateway Responses
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        exception: Exception,
        context: RestApiInvocationContext,
        response: Response,
    ):
        if not isinstance(exception, BaseGatewayException):
            (
                LOG.warning(
                    "Non Gateway Exception raised: %s",
                    exception,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                ),
            )
            exception = Default5xxError(message=f"LocalStack Error: {exception}", status_code="500")

        error = self.create_exception_response(exception, context)
        if error:
            response.update_from(error)

    def create_exception_response(
        self, exception: BaseGatewayException, context: RestApiInvocationContext
    ):
        gateway_response = self._get_gateway_response(exception, context)

        content = self._build_response_content(exception)

        headers = self._build_response_headers()

        status_code = gateway_response.get("statusCode", exception.status_code)

        return Response(response=content, headers=headers, status=status_code)

    def _get_gateway_response(
        self, exception: BaseGatewayException, context: RestApiInvocationContext
    ) -> GatewayResponse:
        """Returns the user configured GatewayResponse dict. If no responses were found we the default response."""
        try:
            responses = context.deployment.localstack_rest_api.gateway_responses
            if response := responses.get(exception.type):
                return response
            if response := responses.get(exception.default_type):
                return response
            return build_default_response(exception.type)
        except Exception as e:
            LOG.warning(
                "Failed to load responses for response %s: %s",
                exception.type,
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            return build_default_response(GatewayResponseType.DEFAULT_5XX)

    def _build_response_content(self, exception: BaseGatewayException) -> str:
        # TODO apply responseTemplates to the content. We should also handle the default simply by managing the default
        #  template body `{"message":$context.error.messageString}`
        return json.dumps({"message": exception.message})

    def _build_response_headers(self) -> dict:
        # TODO apply responseParameters to the headers and get content-type from the gateway_response
        return {"content-type": "application/json"}
