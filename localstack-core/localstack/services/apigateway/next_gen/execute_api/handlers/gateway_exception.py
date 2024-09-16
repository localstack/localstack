import json
import logging

from rolo import Response
from werkzeug.datastructures import Headers

from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway.next_gen.execute_api.api import (
    RestApiGatewayExceptionHandler,
    RestApiGatewayHandlerChain,
)
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    AccessDeniedError,
    BaseGatewayException,
    get_gateway_response_or_default,
)
from localstack.services.apigateway.next_gen.execute_api.variables import (
    GatewayResponseContextVarsError,
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

        LOG.info("Error raised during invocation: %s", exception.type)
        self.set_error_context(exception, context)
        error = self.create_exception_response(exception, context)
        if error:
            response.update_from(error)

    @staticmethod
    def set_error_context(exception: BaseGatewayException, context: RestApiInvocationContext):
        context.context_variables["error"] = GatewayResponseContextVarsError(
            message=exception.message,
            messageString=exception.message,
            responseType=exception.type,
            validationErrorString="",  # TODO
        )

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

        response = Response(response=content, headers=headers, status=status_code)
        return response

    @staticmethod
    def _build_response_content(exception: BaseGatewayException) -> str:
        # TODO apply responseTemplates to the content. We should also handle the default simply by managing the default
        #  template body `{"message":$context.error.messageString}`

        # TODO: remove this workaround by properly managing the responseTemplate for UnauthorizedError
        #  on the CRUD level, it returns the same template as all other errors but in reality the message field is
        #  capitalized
        if isinstance(exception, AccessDeniedError):
            return json.dumps({"Message": exception.message}, separators=(",", ":"))

        return json.dumps({"message": exception.message})

    @staticmethod
    def _build_response_headers(exception: BaseGatewayException) -> dict:
        # TODO apply responseParameters to the headers and get content-type from the gateway_response
        headers = Headers({"Content-Type": APPLICATION_JSON, "x-amzn-ErrorType": exception.code})
        return headers
