import os
from contextlib import contextmanager
from unittest.mock import ANY, MagicMock, patch

import botocore.config
import pytest

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.connect import (
    ExternalClientFactory,
    InternalClientFactory,
    attribute_name_to_service_name,
)
from localstack.aws.gateway import Gateway
from localstack.aws.handlers import add_internal_request_params
from localstack.http import Response
from localstack.http.hypercorn import GatewayServer
from localstack.utils.net import get_free_tcp_port
from localstack.utils.serving import Server


@contextmanager
def server_context(server: Server):
    server.start()
    server.wait_is_up(timeout=10)
    try:
        yield server
    finally:
        server.shutdown()


class TestClientFactory:
    def test_internal_client_dto_is_registered(self):
        factory = InternalClientFactory()
        factory._session = MagicMock()

        mock = factory.get_client("sns", "eu-central-1")
        mock.meta.events.register.assert_called_with("before-call.*.*", handler=ANY)

    def test_external_client_dto_is_not_registered(self):
        factory = ExternalClientFactory()
        factory._session = MagicMock()

        mock = factory.get_client(
            "sqs", "eu-central-1", aws_access_key_id="foo", aws_secret_access_key="bar"
        )
        mock.meta.events.register.assert_not_called()

    @patch.object(ExternalClientFactory, "_get_client")
    def test_external_client_credentials_loaded_from_env_if_set_to_none(self, mock, monkeypatch):
        connect_to = ExternalClientFactory(use_ssl=True)
        connect_to.get_client(
            "abc", region_name="xx-south-1", aws_access_key_id="foo", aws_secret_access_key="bar"
        )
        mock.assert_called_once_with(
            service_name="abc",
            region_name="xx-south-1",
            use_ssl=True,
            verify=False,
            endpoint_url="http://localhost:4566",
            aws_access_key_id="foo",
            aws_secret_access_key="bar",
            aws_session_token=None,
            config=connect_to._config,
        )

        mock.reset_mock()
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "lorem")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ipsum")

        connect_to.get_client(
            "def", region_name=None, aws_secret_access_key=None, aws_access_key_id=None
        )
        mock.assert_called_once_with(
            service_name="def",
            region_name="us-east-1",
            use_ssl=True,
            verify=False,
            endpoint_url="http://localhost:4566",
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
            config=connect_to._config,
        )

    @pytest.mark.parametrize(
        "service",
        [
            "acm",
            "apigateway",
            "awslambda",
            "cloudformation",
            "cloudwatch",
            "cognito_idp",
            "dynamodb",
            "dynamodbstreams",
            "ec2",
            "ecr",
            "es",
            "events",
            "firehose",
            "iam",
            "kinesis",
            "kms",
            "logs",
            "opensearch",
            "redshift",
            "resource_groups",
            "resourcegroupstaggingapi",
            "route53",
            "route53resolver",
            "s3",
            "s3control",
            "secretsmanager",
            "ses",
            "sns",
            "sqs",
            "ssm",
            "stepfunctions",
            "sts",
            "transcribe",
        ],
    )
    def test_typed_client_creation(self, service):
        """Test the created client actually matching the requested service"""
        factory = InternalClientFactory()
        client = getattr(factory(), service)
        assert client.meta.service_model.service_name == attribute_name_to_service_name(service)

    def test_client_caching(self):
        """Test client caching. Same factory for the same service should result in the same client.
        Different factories should result in different (identity wise) clients"""
        # This test might get flaky if some internal boto3 caching is introduced at some point
        # TODO does it really make sense to test the caching?
        factory = InternalClientFactory()
        assert factory().s3 == factory().s3
        factory_2 = InternalClientFactory()
        assert factory().s3 != factory_2().s3

    def test_internal_request_parameters(self):
        internal_dto = None

        def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
            nonlocal internal_dto
            internal_dto = context.internal_request_params
            response.status_code = 200
            response.headers = context.request.headers

        # setup gateway
        gateway = Gateway()
        gateway.request_handlers.append(add_internal_request_params)
        gateway.request_handlers.append(echo_request_handler)
        port = get_free_tcp_port()
        server = GatewayServer(gateway, port, "127.0.0.1", use_ssl=True)

        # create client
        with server_context(server):
            sent_dto = {
                "service_principal": "apigateway",
                "source_arn": "arn:aws:apigateway:us-east-1::/apis/api-id",
            }
            internal_factory = InternalClientFactory()
            internal_lambda_client = internal_factory(
                endpoint_url=f"http://localhost:{port}"
            ).awslambda
            internal_lambda_client.list_functions(
                _ServicePrincipal=sent_dto["service_principal"], _SourceArn=sent_dto["source_arn"]
            )
            assert internal_dto == sent_dto
            external_factory = ExternalClientFactory()
            external_lambda_client = external_factory(
                endpoint_url=f"http://localhost:{port}"
            ).awslambda
            external_lambda_client.list_functions()
            assert internal_dto is None

    def test_internal_call(self):
        """Test the creation of a strictly internal client"""
        pass

    def test_internal_call_from_principal(self):
        """Test the creation of a client based on some principal credentials"""
        pass

    def test_internal_call_from_role(self):
        """Test the creation of a client assuming a role"""
        pass

    def test_internal_call_from_service(self):
        """Test the creation of a client from a service on behalf of some resource"""
        pass

    def test_external_call_to_provider(self):
        """Test the creation of a client to be used to connect to a downstream provider implementation"""
        pass

    def test_external_call_from_test(self):
        """Test the creation of a client to be used to connect in a test"""
        pass


class TestFactoryTestUsage:
    @pytest.fixture(scope="module")
    def test_client_factory(self):
        return ExternalClientFactory()

    @pytest.fixture(scope="class")
    def clients(self, test_client_factory):
        """Clients fixture which will allow all kind of clients to be initialized"""
        botocore_config = botocore.config.Config()

        # can't set the timeouts to 0 like in the AWS CLI because the underlying http client requires values > 0
        if os.environ.get("TEST_DISABLE_RETRIES_AND_TIMEOUTS"):
            botocore_config = botocore_config.merge(
                botocore.config.Config(
                    connect_timeout=1_000, read_timeout=1_000, retries={"total_max_attempts": 1}
                )
            )

        if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
            return test_client_factory(config=botocore_config)

        return test_client_factory(
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
            endpoint_url=config.get_edge_url(),
        )

    def test_something_with_boto_clients(self, clients):
        functions = clients.awslambda.list_functions()
        print(functions)
