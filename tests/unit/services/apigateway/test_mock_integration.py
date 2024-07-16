import pytest

from localstack.http import Request
from localstack.services.apigateway.next_gen.execute_api.context import (
    IntegrationRequest,
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.gateway_response import InternalServerError
from localstack.services.apigateway.next_gen.execute_api.integrations.mock import (
    RestApiMockIntegration,
)
from localstack.utils.strings import to_bytes


@pytest.fixture
def create_default_context():
    def _create_context(body: str) -> RestApiInvocationContext:
        context = RestApiInvocationContext(request=Request())
        context.integration_request = IntegrationRequest(body=to_bytes(body))
        return context

    return _create_context


class TestMockIntegration:
    def test_mock_integration(self, create_default_context):
        mock_integration = RestApiMockIntegration()

        ctx = create_default_context(body='{"statusCode": 200}')
        response = mock_integration.invoke(ctx)
        assert response["status_code"] == 200

        # It needs to be an integer
        ctx = create_default_context(body='{"statusCode": "200"}')
        with pytest.raises(InternalServerError) as exc_info:
            mock_integration.invoke(ctx)
        assert exc_info.match("Internal server error")

        # Any integer will do
        ctx = create_default_context(body='{"statusCode": 0}')
        response = mock_integration.invoke(ctx)
        assert response["status_code"] == 0

        # Literally any
        ctx = create_default_context(body='{"statusCode": -1000}')
        response = mock_integration.invoke(ctx)
        assert response["status_code"] == -1000

        # Malformed Json
        ctx = create_default_context(body='{"statusCode": 200')
        with pytest.raises(InternalServerError) as exc_info:
            mock_integration.invoke(ctx)
        assert exc_info.match("Internal server error")
