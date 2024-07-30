from localstack.http import Request
from localstack.services.apigateway.next_gen.execute_api.router import ApiGatewayEndpoint


class TestApiGatewayEndpoint:
    def test_create_response_connection(self):
        no_connection_header = ApiGatewayEndpoint.create_response(Request())
        assert no_connection_header.headers.get("Connection") == "keep-alive"

        close_header = ApiGatewayEndpoint.create_response(Request(headers={"Connection": "close"}))
        assert close_header.headers.get("Connection") is None

        keep_alive_header = ApiGatewayEndpoint.create_response(
            Request(headers={"Connection": "keep-alive"})
        )
        assert keep_alive_header.headers.get("Connection") == "keep-alive"

        unknown_header = ApiGatewayEndpoint.create_response(Request(headers={"Connection": "foo"}))
        assert unknown_header.headers.get("Connection") == "keep-alive"
