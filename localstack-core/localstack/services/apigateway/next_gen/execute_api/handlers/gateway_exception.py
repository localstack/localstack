import json
import logging

from rolo import Response

from localstack.services.apigateway.next_gen.execute_api.api import (
    RestApiGatewayExceptionHandler,
    RestApiGatewayHandlerChain,
)
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    BaseGatewayException,
    get_gateway_response_or_default,
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
            LOG.warning(
                "Non Gateway Exception raised: %s",
                exception,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            response.update_from(
                Response(response=f"Error in apigateway invocation: {exception}", status="500")
            )
            return

        error = self.create_exception_response(exception, context)
        if error:
            response.update_from(error)

    def create_exception_response(
        self, exception: BaseGatewayException, context: RestApiInvocationContext
    ):
        gateway_response = get_gateway_response_or_default(
            exception.type, context.deployment.rest_api.gateway_responses
        )

        content = self._build_response_content(exception)

        headers = self._build_response_headers(exception)

        status_code = gateway_response.get("statusCode")
        if not status_code:
            status_code = exception.status_code or 500

        return Response(response=content, headers=headers, status=status_code)

    def _build_response_content(self, exception: BaseGatewayException) -> str:
        # TODO apply responseTemplates to the content. We should also handle the default simply by managing the default
        #  template body `{"message":$context.error.messageString}`
        return json.dumps({"message": exception.message})

    def _build_response_headers(self, exception: BaseGatewayException) -> dict:
        # TODO apply responseParameters to the headers and get content-type from the gateway_response
        return {"content-type": "application/json", "x-amzn-ErrorType": exception.code}
