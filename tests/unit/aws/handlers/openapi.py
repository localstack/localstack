import json

from rolo import Request, Response
from rolo.gateway import RequestContext
from rolo.gateway.handlers import EmptyResponseHandler

from localstack.aws.chain import HandlerChain
from localstack.aws.handlers.openapi import OpenAPIRequestValidator


class TestOpenAPIRequestValidator:
    def test_valid_request(self):
        chain = HandlerChain([OpenAPIRequestValidator()])
        context = RequestContext(
            Request(
                path="/_localstack/diagnose",
                method="GET",
                scheme="http",
                headers={"Host": "localhost.localstack.cloud:4566"},
            )
        )
        response = Response()
        chain.handle(context=context, response=response)
        assert response.status_code == 200

    def test_path_not_found(self):
        chain = HandlerChain(
            [
                OpenAPIRequestValidator(),
                EmptyResponseHandler(404, b'{"message": "Not Found"}'),
            ]
        )
        context = RequestContext(
            Request(
                path="/_localstack/not_existing_endpoint",
                method="GET",
                scheme="http",
                headers={"Host": "localhost.localstack.cloud:4566"},
            )
        )
        response = Response(status=0)
        chain.handle(context=context, response=response)
        # We leave this case to the last handler in the request handler chain.
        assert response.status_code == 404
        assert response.data == b'{"message": "Not Found"}'

    def test_body_validation_errors(self):
        body = {"variable": "FOO", "value": "BAZ"}
        chain = HandlerChain([OpenAPIRequestValidator()])
        request = Request(
            path="/_localstack/config",
            method="POST",
            body=json.dumps(body),
            scheme="http",
            headers={"Host": "localhost.localstack.cloud:4566", "Content-Type": "application/json"},
        )
        context = RequestContext(request)
        response = Response()
        chain.handle(context=context, response=response)
        assert response.status_code == 200

        # Request without the content type
        request.headers = {"Host": "localhost.localstack.cloud:4566"}
        context = RequestContext(request)
        response = Response()
        chain.handle(context=context, response=response)
        assert response.status_code == 400
        assert response.json["error"] == "Bad Request"
        assert response.json["message"] == "Request body validation error"

        # Request with invalid body
        context = RequestContext(
            Request(
                path="/_localstack/config",
                method="POST",
                body=json.dumps({"variable": "", "value": "BAZ"}),
                scheme="http",
                headers={
                    "Host": "localhost.localstack.cloud:4566",
                    "Content-Type": "application/json",
                },
            )
        )
        response = Response()
        chain.handle(context=context, response=response)
        assert response.status_code == 400
        assert response.json["error"] == "Bad Request"
        assert response.json["message"] == "Request body validation error"
