from collections.abc import Iterable

import pytest
from moto.core.exceptions import RESTError, ServiceException
from moto.ec2.exceptions import EC2_ERROR_RESPONSE

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.forwarder import create_aws_request_context
from localstack.aws.handlers.service import ServiceExceptionSerializer, ServiceResponseParser
from localstack.aws.protocol.serializer import create_serializer
from localstack.http import Request, Response


@pytest.fixture
def service_response_handler_chain() -> HandlerChain:
    """Returns a dummy chain for testing."""
    return HandlerChain(response_handlers=[ServiceResponseParser()])


class TestServiceResponseHandler:
    def test_use_set_response(self, service_response_handler_chain):
        context = create_aws_request_context(
            "opensearch", "CreateDomain", "rest-json", {"DomainName": "foobar"}
        )
        context.service_response = {"sure": "why not"}

        service_response_handler_chain.handle(context, Response(status=200))
        assert context.service_response == {"sure": "why not"}

    def test_parse_response(self, service_response_handler_chain):
        context = create_aws_request_context("sqs", "CreateQueue", "json", {"QueueName": "foobar"})
        backend_response = {"QueueUrl": "http://localhost:4566/000000000000/foobar"}
        http_response = create_serializer(context.service).serialize_to_response(
            backend_response, context.operation, context.request.headers, context.request_id
        )

        service_response_handler_chain.handle(context, http_response)
        assert context.service_response == backend_response

    def test_parse_response_with_streaming_response(self, service_response_handler_chain):
        context = create_aws_request_context(
            "s3", "GetObject", "rest-xml", {"Bucket": "foo", "Key": "bar.bin"}
        )
        backend_response = {"Body": b"\x00\x01foo", "ContentType": "application/octet-stream"}
        http_response = create_serializer(context.service).serialize_to_response(
            backend_response, context.operation, context.request.headers, context.request_id
        )

        service_response_handler_chain.handle(context, http_response)
        assert context.service_response["ContentLength"] == 5
        assert context.service_response["ContentType"] == "application/octet-stream"
        assert context.service_response["Body"].read() == b"\x00\x01foo"

    def test_common_service_exception(self, service_response_handler_chain):
        context = create_aws_request_context(
            "opensearch", "CreateDomain", "rest-json", {"DomainName": "foobar"}
        )
        context.service_exception = CommonServiceException(
            "MyCommonException", "oh noes", status_code=409, sender_fault=True
        )

        service_response_handler_chain.handle(context, Response(status=409))
        assert context.service_exception.message == "oh noes"
        assert context.service_exception.code == "MyCommonException"
        assert context.service_exception.sender_fault
        assert context.service_exception.status_code == 409

    def test_service_exception(self, service_response_handler_chain):
        from localstack.aws.api.opensearch import ResourceAlreadyExistsException

        context = create_aws_request_context(
            "opensearch", "CreateDomain", "rest-json", {"DomainName": "foobar"}
        )
        context.service_exception = ResourceAlreadyExistsException("oh noes")

        response = create_serializer(context.service).serialize_error_to_response(
            context.service_exception,
            context.operation,
            context.request.headers,
            context.request_id,
        )

        service_response_handler_chain.handle(context, response)
        assert context.service_exception.message == "oh noes"
        assert context.service_exception.code == "ResourceAlreadyExistsException"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 409

    def test_service_exception_with_code_from_spec(self, service_response_handler_chain):
        from localstack.aws.api.sqs import QueueDoesNotExist

        context = create_aws_request_context(
            "sqs",
            "SendMessage",
            "json",
            {"QueueUrl": "http://localhost:4566/000000000000/foobared", "MessageBody": "foo"},
        )
        context.service_exception = QueueDoesNotExist()

        response = create_serializer(context.service).serialize_error_to_response(
            context.service_exception,
            context.operation,
            context.request.headers,
            context.request_id,
        )

        service_response_handler_chain.handle(context, response)

        assert context.service_exception.message == ""
        assert context.service_exception.code == "QueueDoesNotExist"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 400

    def test_sets_exception_from_error_response(self, service_response_handler_chain):
        context = create_aws_request_context(
            "opensearch", "DescribeDomain", "rest-json", {"DomainName": "foobar"}
        )
        response = Response(
            b'{"__type": "ResourceNotFoundException", "message": "Domain not found: foobar"}',
            409,
        )
        service_response_handler_chain.handle(context, response)

        assert context.service_exception.message == "Domain not found: foobar"
        assert context.service_exception.code == "ResourceNotFoundException"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 409

        assert context.service_response is None

    def test_nothing_set_does_nothing(self, service_response_handler_chain):
        context = RequestContext(request=Request("GET", "/_localstack/health"))

        service_response_handler_chain.handle(context, Response("ok", 200))

        assert context.service_exception is None
        assert context.service_response is None

    def test_invalid_exception_does_nothing(self, service_response_handler_chain):
        context = create_aws_request_context(
            "opensearch", "DescribeDomain", "rest-json", {"DomainName": "foobar"}
        )
        context.service_exception = ValueError()
        service_response_handler_chain.handle(context, Response(status=500))

        assert context.service_response is None
        assert isinstance(context.service_exception, ValueError)


class TestServiceExceptionSerializer:
    @pytest.mark.parametrize(
        "message, output",
        [
            ("", "not available in your current license plan or has not yet been emulated"),
            ("Ups!", "Ups!"),
        ],
    )
    def test_not_implemented_error(self, message, output):
        context = create_aws_request_context(
            "opensearch", "DescribeDomain", "rest-json", {"DomainName": "foobar"}
        )
        not_implemented_exception = NotImplementedError(message)

        ServiceExceptionSerializer().create_exception_response(not_implemented_exception, context)

        assert output in context.service_exception.message
        assert context.service_exception.code == "InternalFailure"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 501

    def test_internal_error_propagate_traceback(self, service_response_handler_chain):
        raised_exception: Exception | None = None

        def raise_internal_error_handler(*args, **kwargs):
            raise ValueError("error")

        def capture_original_exception_handler(
            chain: HandlerChain,
            exception: Exception,
            context: RequestContext,
            response: Response,
        ):
            nonlocal raised_exception
            raised_exception = exception
            return

        err_chain = HandlerChain(
            request_handlers=[raise_internal_error_handler],
            exception_handlers=[
                capture_original_exception_handler,
                ServiceExceptionSerializer(),
            ],
        )

        err_context = create_aws_request_context(
            "opensearch", "DescribeDomain", "rest-json", {"DomainName": "foobar"}
        )
        err_chain.handle(err_context, Response())

        assert err_context.service_exception.code == "InternalError"
        assert err_context.service_exception.__traceback__
        assert err_context.service_exception.__traceback__ == raised_exception.__traceback__
        assert err_context.service_exception.status_code == 500

    def test_moto_service_exception_is_translated(self, service_response_handler_chain):
        # Redefine exception here but use the right base exc. This is to improve tolerance against Moto refactors.
        class MessageRejectedError(ServiceException):
            code = "MessageRejected"

        # Ensure ServiceExceptions are translated
        context = create_aws_request_context(
            "ses",
            "SendRawEmail",
            "query",
            {
                "Destinations": ["invalid@example.com"],
                "RawMessage": {
                    "Data": b"From: origin@example.com\nTo: destination@example.com\nSubject: sub\n\nbody\n\n"
                },
            },
        )
        msg = "Did not have authority to send email"
        moto_exception = MessageRejectedError(msg)

        ServiceExceptionSerializer().create_exception_response(moto_exception, context)

        assert msg in context.service_exception.message
        assert context.service_exception.code == "MessageRejected"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 400

    def test_moto_rest_error_is_translated(self, service_response_handler_chain):
        # Redefine exception here but use the right base exc. This is to improve tolerance against Moto refactors.
        class InvalidKeyPairNameError(RESTError):
            code = 400
            request_id_tag_name = "RequestID"
            extended_templates = {"custom_response": EC2_ERROR_RESPONSE}
            env = RESTError.extended_environment(extended_templates)

            def __init__(self, key: Iterable[str]):
                super().__init__(
                    "InvalidKeyPair.NotFound",
                    f"The keypair '{key}' does not exist.",
                    template="custom_response",
                )

        # Ensure RESTErrors are translated
        context = create_aws_request_context(
            "ec2",
            "RunInstances",
            "ec2",
            {
                "ImageId": "ami-deadc0de",
                "InstanceType": "t3.nano",
                "KeyName": "some-key-pair",
                "MaxCount": 1,
                "MinCount": 1,
            },
        )
        moto_exception = InvalidKeyPairNameError({"some-key-pair"})

        ServiceExceptionSerializer().create_exception_response(moto_exception, context)

        assert (
            "The keypair '{'some-key-pair'}' does not exist." in context.service_exception.message
        )
        assert context.service_exception.code == "InvalidKeyPair.NotFound"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 400
