import json
import logging
import re
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

    def get_status_code(self, integration_req: IntegrationRequest) -> int | None:
        try:
            body = json.loads(integration_req["body"])
        except JSONDecodeError as e:
            LOG.debug(
                "Exception while JSON parsing integration request body: %s"
                "Falling back to custom parser",
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            body = self.parse_invalid_json(to_str(integration_req["body"]))

        status_code = body.get("statusCode")
        if not isinstance(status_code, int):
            return

        return status_code

    def parse_invalid_json(self, body: str) -> dict:
        """This is a quick fix to unblock cdk users setting cors policy for rest apis.
        CDK creates a MOCK OPTIONS route with in valid json. `{statusCode: 200}`
        Aws probably has a custom token parser. We can implement one
        at some point if we have user requests for it"""

        def convert_null_value(value) -> str:
            if (value := value.strip()) in ("null", ""):
                return '""'
            return value

        try:
            statuscode = ""
            matched = re.match(r"^\s*{(.+)}\s*$", body).group(1)
            pairs = [m.strip() for m in matched.split(",")]
            # TODO this is not right, but nested object would otherwise break the parsing
            key_values = [s.split(":", maxsplit=1) for s in pairs if s]
            for key_value in key_values:
                assert len(key_value) == 2
                key, value = [convert_null_value(el) for el in key_value]

                if key in ("statusCode", "'statusCode'", '"statusCode"'):
                    statuscode = int(value)
                    continue

                assert (leading_key_char := key[0]) not in "[{"
                if leading_key_char in "'\"":
                    assert len(key) >= 2
                    assert key[-1] == leading_key_char

                if (leading_value_char := value[0]) in "[{'\"":
                    assert len(value) >= 2
                    if leading_value_char == "{":
                        # TODO reparse objects
                        assert value[-1] == "}"
                    elif leading_value_char == "[":
                        # TODO validate arrays
                        assert value[-1] == "]"
                    else:
                        assert value[-1] == leading_value_char

            return {"statusCode": statuscode}

        except Exception as e:
            LOG.debug(
                "Error Parsing an invalid json, %s", e, exc_info=LOG.isEnabledFor(logging.DEBUG)
            )
            return {"statusCode": ""}
