import pytest

from localstack.aws.api.apigateway import IntegrationResponse
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    ApiConfigurationError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import IntegrationResponseHandler


class TestSelectionPattern:
    def test_selection_pattern_status_code(self):
        integration_responses = {
            "2OO": IntegrationResponse(
                statusCode="200",
            ),
            "400": IntegrationResponse(
                statusCode="400",
                selectionPattern="400",
            ),
            "500": IntegrationResponse(
                statusCode="500",
                selectionPattern=r"5\d{2}",
            ),
        }

        def select_int_response(selection_value: str) -> IntegrationResponse:
            return IntegrationResponseHandler.select_integration_response(
                selection_value=selection_value,
                integration_responses=integration_responses,
            )

        int_response = select_int_response("200")
        assert int_response["statusCode"] == "200"

        int_response = select_int_response("400")
        assert int_response["statusCode"] == "400"

        int_response = select_int_response("404")
        # fallback to default
        assert int_response["statusCode"] == "200"

        int_response = select_int_response("500")
        assert int_response["statusCode"] == "500"

        int_response = select_int_response("501")
        assert int_response["statusCode"] == "500"

    def test_selection_pattern_no_default(self):
        integration_responses = {
            "2OO": IntegrationResponse(
                statusCode="200",
                selectionPattern="200",
            ),
        }

        with pytest.raises(ApiConfigurationError) as e:
            IntegrationResponseHandler.select_integration_response(
                selection_value="404",
                integration_responses=integration_responses,
            )
        assert e.value.message == "Internal server error"

    def test_selection_pattern_string(self):
        integration_responses = {
            "2OO": IntegrationResponse(
                statusCode="200",
            ),
            "400": IntegrationResponse(
                statusCode="400",
                selectionPattern="Malformed.*",
            ),
            "500": IntegrationResponse(
                statusCode="500",
                selectionPattern="Internal.*",
            ),
        }

        def select_int_response(selection_value: str) -> IntegrationResponse:
            return IntegrationResponseHandler.select_integration_response(
                selection_value=selection_value,
                integration_responses=integration_responses,
            )

        # this would basically no error message from AWS lambda
        int_response = select_int_response("")
        assert int_response["statusCode"] == "200"

        int_response = select_int_response("Malformed request")
        assert int_response["statusCode"] == "400"

        int_response = select_int_response("Internal server error")
        assert int_response["statusCode"] == "500"

        int_response = select_int_response("Random error")
        assert int_response["statusCode"] == "200"
