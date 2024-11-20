import logging
from http import HTTPMethod

from localstack import config
from localstack.aws.handlers.cors import CorsEnforcer
from localstack.aws.handlers.cors import CorsResponseEnricher as GlobalCorsResponseEnricher
from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext
from ..gateway_response import MissingAuthTokenError

LOG = logging.getLogger(__name__)


class CorsResponseEnricher(RestApiGatewayHandler):
    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        """
        This is a LocalStack only handler, to allow users to override API Gateway CORS configuration and just use the
        default LocalStack configuration instead, to ease the usage and reduce production code changes.
        """
        if not config.DISABLE_CUSTOM_CORS_APIGATEWAY:
            return

        if not context.invocation_request:
            return

        headers = context.invocation_request["headers"]

        if "Origin" not in headers:
            return

        if context.request.method == HTTPMethod.OPTIONS:
            # If the user did not configure an OPTIONS route, we still want LocalStack to properly respond to CORS
            # requests
            if context.invocation_exception:
                if isinstance(context.invocation_exception, MissingAuthTokenError):
                    response.data = b""
                    response.status_code = 204
                else:
                    return

        if CorsEnforcer.is_cors_origin_allowed(headers):
            GlobalCorsResponseEnricher.add_cors_headers(headers, response.headers)
