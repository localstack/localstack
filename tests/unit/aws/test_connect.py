from unittest.mock import ANY, MagicMock, patch

import boto3
import botocore
import pytest
from botocore.config import Config

from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.aws.connect import (
    ExternalAwsClientFactory,
    ExternalClientFactory,
    InternalClientFactory,
    attribute_name_to_service_name,
)
from localstack.aws.gateway import Gateway
from localstack.aws.handlers import add_internal_request_params, add_region_from_header
from localstack.config import HostAndPort
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.http import Response
from localstack.http.duplex_socket import enable_duplex_socket
from localstack.http.hypercorn import GatewayServer
from localstack.testing.config import TEST_AWS_ACCESS_KEY_ID
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.aws.request_context import extract_access_key_id_from_auth_header
from localstack.utils.net import get_free_tcp_port


class TestClientFactory:
    @pytest.fixture
    def create_dummy_request_parameter_gateway(self):
        server = None

        def _create(request_handlers: list[Handler]) -> str:
            nonlocal server

            # explicitly enable the duplex socket support here
            enable_duplex_socket()

            gateway = Gateway()
            gateway.request_handlers.append(add_internal_request_params)
            for handler in request_handlers:
                gateway.request_handlers.append(handler)
            port = get_free_tcp_port()
            gateway_listen = HostAndPort(host="127.0.0.1", port=port)
            server = GatewayServer(gateway, gateway_listen, use_ssl=True)
            server.start()
            server.wait_is_up(timeout=10)
            return f"http://localhost:{port}"

        yield _create
        if server:
            server.shutdown()

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
    def test_external_client_credentials_origin(self, mock, region_name, monkeypatch):
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

        connect_to.get_client(
            "def", region_name=None, aws_secret_access_key=None, aws_access_key_id=None
        )
        mock.assert_called_once_with(
            service_name="def",
            region_name=region_name,
            use_ssl=True,
            verify=False,
            endpoint_url="http://localhost:4566",
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
            config=connect_to._config,
        )

        mock.reset_mock()

        connect_to.get_client("def", region_name=None, aws_access_key_id=TEST_AWS_ACCESS_KEY_ID)
        mock.assert_called_once_with(
            service_name="def",
            region_name=region_name,
            use_ssl=True,
            verify=False,
            endpoint_url="http://localhost:4566",
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
            aws_session_token=None,
            config=connect_to._config,
        )

    @patch.object(ExternalAwsClientFactory, "_get_client")
    def test_external_aws_client_credentials_loaded_from_env_if_set_to_none(
        self, mock, region_name, monkeypatch
    ):
        session = boto3.Session()
        connect_to = ExternalAwsClientFactory(use_ssl=True, session=session)
        connect_to.get_client(
            "abc", region_name="xx-south-1", aws_access_key_id="foo", aws_secret_access_key="bar"
        )
        mock.assert_called_once_with(
            service_name="abc",
            region_name="xx-south-1",
            use_ssl=True,
            verify=True,
            endpoint_url=None,
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
            region_name=region_name,
            use_ssl=True,
            verify=True,
            endpoint_url=None,
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
            config=connect_to._config,
        )

    @pytest.mark.parametrize(
        "service",
        [
            "acm",
            "amplify",
            "apigateway",
            "apigatewayv2",
            "appconfig",
            "appsync",
            "athena",
            "autoscaling",
            "lambda_",
            "backup",
            "batch",
            "ce",
            "cloudformation",
            "cloudfront",
            "cloudtrail",
            "cloudwatch",
            "codecommit",
            "cognito_identity",
            "cognito_idp",
            "docdb",
            "dynamodb",
            "dynamodbstreams",
            "ec2",
            "ecr",
            "ecs",
            "eks",
            "elasticbeanstalk",
            "elbv2",
            "emr",
            "es",
            "events",
            "firehose",
            "glacier",
            "glue",
            "iam",
            "iot",
            "iot_data",
            "iotanalytics",
            "iotwireless",
            "kafka",
            "kinesis",
            "kms",
            "lakeformation",
            "logs",
            "mediastore",
            "mq",
            "mwaa",
            "neptune",
            "opensearch",
            "organizations",
            "pi",
            "qldb",
            "qldb_session",
            "rds",
            "rds_data",
            "redshift",
            "redshift_data",
            "resource_groups",
            "resourcegroupstaggingapi",
            "route53",
            "route53resolver",
            "s3",
            "s3control",
            "sagemaker",
            "sagemaker_runtime",
            "secretsmanager",
            "serverlessrepo",
            "servicediscovery",
            "ses",
            "sesv2",
            "sns",
            "sqs",
            "ssm",
            "stepfunctions",
            "sts",
            "timestream_query",
            "timestream_write",
            "transcribe",
            "xray",
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
        # TODO pretty ugly way of accessing the internal client
        factory = InternalClientFactory()
        assert factory().s3._client is factory().s3._client
        factory_2 = InternalClientFactory()
        assert factory().s3._client != factory_2().s3._client

    def test_client_caching_with_config(self):
        """Test client caching. Same factory for the same service should result in the same client.
        Different factories should result in different (identity wise) clients"""
        # This test might get flaky if some internal boto3 caching is introduced at some point
        config = Config(read_timeout=2, signature_version=botocore.UNSIGNED)
        second_config = Config(read_timeout=2, signature_version=botocore.UNSIGNED)
        third_config = Config(read_timeout=3, signature_version=botocore.UNSIGNED)
        factory = InternalClientFactory()
        client_1 = factory(config=config).s3._client
        client_2 = factory(config=config).s3._client
        client_3 = factory(config=second_config).s3._client
        client_4 = factory(config=third_config).s3._client
        assert client_1 is client_2
        assert client_2 is client_3
        assert client_3 is not client_4

    def test_client_caching_with_merged_configs(self):
        """Test client caching. Same factory for the same service should result in the same client.
        Different factories should result in different (identity wise) clients"""
        # This test might get flaky if some internal boto3 caching is introduced at some point
        config_1 = Config(read_timeout=2)
        config_2 = Config(signature_version=botocore.UNSIGNED)
        config_3 = config_1.merge(config_2)
        config_4 = config_1.merge(config_2)
        factory = InternalClientFactory()
        client_1 = factory(config=config_1).s3._client
        client_2 = factory(config=config_2).s3._client
        client_3 = factory(config=config_3).s3._client
        client_4 = factory(config=config_4).s3._client
        assert client_1 is not client_2
        assert client_2 is not client_3
        assert client_1 is not client_3
        assert client_3 is client_4

    def test_internal_request_parameters(self, create_dummy_request_parameter_gateway):
        internal_dto = None

        def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
            nonlocal internal_dto
            internal_dto = context.internal_request_params
            response.status_code = 200
            response.headers = context.request.headers

        endpoint_url = create_dummy_request_parameter_gateway([echo_request_handler])

        sent_dto = {
            "service_principal": "apigateway",
            "source_arn": "arn:aws:apigateway:us-east-1::/apis/api-id",
        }
        internal_factory = InternalClientFactory()
        internal_lambda_client = internal_factory(endpoint_url=endpoint_url).lambda_
        internal_lambda_client.request_metadata(
            service_principal=sent_dto["service_principal"], source_arn=sent_dto["source_arn"]
        ).list_functions()
        assert internal_dto == sent_dto
        external_factory = ExternalClientFactory()
        external_lambda_client = external_factory(endpoint_url=endpoint_url).lambda_
        external_lambda_client.list_functions()
        assert internal_dto is None

    def test_internal_call(self, create_dummy_request_parameter_gateway):
        """Test the creation of a strictly internal client"""
        # TODO add utility to simplify (second iteration)
        factory = InternalClientFactory()
        test_params = {}

        def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
            test_params["is_internal"] = context.is_internal_call
            if context.internal_request_params:
                test_params.update(context.internal_request_params)
            response.status_code = 200

        endpoint_url = create_dummy_request_parameter_gateway([echo_request_handler])

        factory(endpoint_url=endpoint_url).lambda_.list_functions()

        assert test_params == {"is_internal": True}

    def test_internal_call_from_principal(self, create_dummy_request_parameter_gateway):
        """Test the creation of a client based on some principal credentials"""

        factory = InternalClientFactory()
        test_params = {}

        def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
            test_params["is_internal"] = context.is_internal_call
            if context.internal_request_params:
                test_params.update(context.internal_request_params)
            test_params["access_key_id"] = extract_access_key_id_from_auth_header(
                context.request.headers
            )
            response.status_code = 200

        endpoint_url = create_dummy_request_parameter_gateway([echo_request_handler])

        factory(
            endpoint_url=endpoint_url,
            aws_access_key_id="AKIAQAAAAAAALX6GRE2E",
            aws_secret_access_key="something",
        ).lambda_.list_functions()

        assert test_params == {"is_internal": True, "access_key_id": "AKIAQAAAAAAALX6GRE2E"}

    def test_internal_call_from_role(self, create_dummy_request_parameter_gateway):
        """Test the creation of a client living in the apigateway service assuming a role and creating a client with it"""
        factory = InternalClientFactory()
        test_params = {}

        def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
            test_params["is_internal"] = context.is_internal_call
            if context.internal_request_params:
                test_params.update(context.internal_request_params)
            if "sts" in context.request.headers["Authorization"]:
                response.set_response(
                    b"<?xml version='1.0' encoding='utf-8'?>\n<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleResult><Credentials><AccessKeyId>ASIAQAAAAAAAKZ4L3POJ</AccessKeyId><SecretAccessKey>JuXSf5FLeQ359frafiJ4JpjDEoB7HQLnLQEFBRlM</SecretAccessKey><SessionToken>FQoGZXIvYXdzEBYaDCjqXzwpBOq025tqq/z0qkio4HkWpvPGsLW3y4G5kcPcKpPrJ1ZVnnVMcx7JP35kzhPssefI7P08HuQKjX15L7r+mFoPCBHVZYqx5yqflWM7Di6vOfWm51DMY6RCe7cXH/n5SwSxeb0RQokIKMOZ0jK+bZN2KPqmWaH4hkAaDAsFGVBgpuEpNZm4VU75m29kxoUw2//6aTMoxgIFzuwb22dNidJYdoxzLFcAy89kJaYYYQjJ/SFKtZPlgSaekEMr6E4VCr+g9zHVUlO33YLTLaxlb3pf/+Dgq8CJCpmBo/suHJFPvfYH5zdsvUlKcczd7Svyr8RqxjbexG8uXH4=</SessionToken><Expiration>2023-03-13T11:29:08.200000Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAQAAAAAAANUGUEO76V:test-session</AssumedRoleId><Arn>arn:aws:sts::000000000000:assumed-role/test-role/test-session</Arn></AssumedRoleUser><PackedPolicySize>6</PackedPolicySize></AssumeRoleResult><ResponseMetadata><RequestId>P3CY3HH8R03LT28I31X212IQWLSY0WCECRPXPSMOTFVUAV3I8Q5A</RequestId></ResponseMetadata></AssumeRoleResponse>"
                )
            else:
                test_params["access_key_id"] = extract_access_key_id_from_auth_header(
                    context.request.headers
                )
            response.status_code = 200

        endpoint_url = create_dummy_request_parameter_gateway([echo_request_handler])

        client = factory.with_assumed_role(
            role_arn="arn:aws:iam::000000000000:role/test-role",
            service_principal=ServicePrincipal.apigateway,
            endpoint_url=endpoint_url,
        )
        assert test_params == {"is_internal": True, "service_principal": "apigateway"}
        test_params = {}

        client.lambda_.list_functions()

        assert test_params == {"is_internal": True, "access_key_id": "ASIAQAAAAAAAKZ4L3POJ"}

    def test_internal_call_from_service(self, create_dummy_request_parameter_gateway):
        """Test the creation of a client from a service on behalf of some resource"""
        factory = InternalClientFactory()
        test_params = {}

        def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
            test_params["is_internal"] = context.is_internal_call
            if context.internal_request_params:
                test_params.update(context.internal_request_params)
            response.status_code = 200

        endpoint_url = create_dummy_request_parameter_gateway([echo_request_handler])
        clients = factory(
            endpoint_url=endpoint_url,
        )

        expected_result = {
            "is_internal": True,
            "service_principal": "apigatway",
            "source_arn": "arn:aws:apigateway:us-east-1::/apis/a1a1a1a1",
        }
        clients.lambda_.request_metadata(
            source_arn=expected_result["source_arn"],
            service_principal=expected_result["service_principal"],
        ).list_functions()

        assert test_params == expected_result

    def test_external_call_to_provider(self, create_dummy_request_parameter_gateway):
        """Test the creation of a client to be used to connect to a downstream provider implementation"""
        factory = ExternalClientFactory()
        test_params = {}

        def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
            test_params["is_internal"] = context.is_internal_call
            test_params["params"] = context.internal_request_params
            response.status_code = 200

        endpoint_url = create_dummy_request_parameter_gateway([echo_request_handler])
        clients = factory(
            endpoint_url=endpoint_url,
        )

        expected_result = {"is_internal": False, "params": None}
        clients.lambda_.list_functions()

        assert test_params == expected_result

    def test_external_call_from_test(self, create_dummy_request_parameter_gateway):
        """Test the creation of a client to be used to connect in a test"""
        factory = ExternalClientFactory()
        test_params = {}

        def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
            test_params["is_internal"] = context.is_internal_call
            test_params["params"] = context.internal_request_params
            test_params["region"] = context.region
            response.status_code = 200

        endpoint_url = create_dummy_request_parameter_gateway(
            [add_region_from_header, echo_request_handler]
        )
        clients = factory(
            region_name="eu-central-1",
            endpoint_url=endpoint_url,
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )

        expected_result = {"is_internal": False, "params": None, "region": "eu-central-1"}
        clients.lambda_.list_functions()

        assert test_params == expected_result

    def test_region_override(self):
        # Boto has an odd behaviour when using a non-default (any other region than us-east-1) in config
        # If the region in arg is non-default, it gives the arg the precedence
        # But if the region in arg is default (us-east-1), it gives precedence to one in config
        # This test asserts that this behaviour is handled by client factories and always give precedence to arg region

        factory = ExternalClientFactory()

        config = botocore.config.Config(region_name="eu-north-1")

        assert factory(region_name="us-east-1", config=config).s3.meta.region_name == "us-east-1"
        assert factory(region_name="us-west-1", config=config).s3.meta.region_name == "us-west-1"
