from abc import abstractmethod

from ..api import RestApiInvocationContext
from ..context import EndpointResponse


class RestApiIntegration:
    """
    This REST API Integration exposes an API to invoke the specific Integration with a common interface.

    https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-integration-settings.html
    TODO: Add more abstractmethods when starting to work on the Integration handler
    """

    name: str

    @abstractmethod
    def invoke(self, context: RestApiInvocationContext) -> EndpointResponse:
        pass
