import json
import logging
from json import JSONDecodeError

from werkzeug.datastructures import Headers

from localstack.utils.strings import to_str

from ..context import EndpointResponse, IntegrationRequest, RestApiInvocationContext
from ..gateway_response import InternalServerError
from .core import RestApiIntegration

LOG = logging.getLogger(__name__)


class RestApiMockIntegration(RestApiIntegration):
    """
    This is a simple REST API integration but quite limited, allowing you to quickly test your APIs or return
    hardcoded responses to the client.
    This integration can never return a proper response, and all the work is done with integration request and response
    mappings.
    This can be used to set up CORS response for `OPTIONS` requests.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-mock-integration.html
    """

    name = "MOCK"

    def invoke(self, context: RestApiInvocationContext) -> EndpointResponse:
        integration_req: IntegrationRequest = context.integration_request

        status_code = self.get_status_code(integration_req)

        if status_code is None:
            LOG.debug(
                "Execution failed due to configuration error: Unable to parse statusCode. "
                "It should be an integer that is defined in the request template."
            )
            raise InternalServerError("Internal server error")

        return EndpointResponse(status_code=status_code, body=b"", headers=Headers())

    @staticmethod
    def get_status_code(integration_req: IntegrationRequest) -> int | None:
        try:
            body = json.loads(to_str(integration_req["body"]))
        except JSONDecodeError as e:
            LOG.debug(
                "Exception while parsing integration request body: %s",
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            return

        status_code = body.get("statusCode")
        if not isinstance(status_code, int):
            return

        return status_code
