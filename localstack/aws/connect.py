"""
LocalStack client stack.

This module provides the interface to perform cross-service communication between
LocalStack providers.
"""
import json
import logging
import threading
from abc import ABC, abstractmethod
from functools import cache
from typing import TYPE_CHECKING, Optional, TypedDict

from boto3.session import Session
from botocore.client import BaseClient
from botocore.config import Config

from localstack import config
from localstack.constants import (
    INTERNAL_AWS_ACCESS_KEY_ID,
    INTERNAL_AWS_SECRET_ACCESS_KEY,
    MAX_POOL_CONNECTIONS,
)
from localstack.utils.aws.aws_stack import get_local_service_url
from localstack.utils.aws.request_context import get_region_from_request_context

if TYPE_CHECKING:
    from mypy_boto3_acm import ACMClient
    from mypy_boto3_apigateway import APIGatewayClient
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_cognito_idp import CognitoIdentityProviderClient
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_dynamodbstreams import DynamoDBStreamsClient
    from mypy_boto3_ec2 import EC2Client
    from mypy_boto3_ecr import ECRClient
    from mypy_boto3_es import ElasticsearchServiceClient
    from mypy_boto3_events import EventBridgeClient
    from mypy_boto3_firehose import FirehoseClient
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_kinesis import KinesisClient
    from mypy_boto3_kms import KMSClient
    from mypy_boto3_lambda import LambdaClient
    from mypy_boto3_logs import CloudWatchLogsClient
    from mypy_boto3_opensearch import OpenSearchServiceClient
    from mypy_boto3_redshift import RedshiftClient
    from mypy_boto3_resource_groups import ResourceGroupsClient
    from mypy_boto3_resourcegroupstaggingapi import ResourceGroupsTaggingAPIClient
    from mypy_boto3_route53 import Route53Client
    from mypy_boto3_route53resolver import Route53ResolverClient
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_s3control import S3ControlClient
    from mypy_boto3_secretsmanager import SecretsManagerClient
    from mypy_boto3_ses import SESClient
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sqs import SQSClient
    from mypy_boto3_ssm import SSMClient
    from mypy_boto3_stepfunctions import SFNClient
    from mypy_boto3_sts import STSClient
    from mypy_boto3_transcribe import TranscribeClient


LOG = logging.getLogger(__name__)


def attribute_name_to_service_name(attribute_name):
    """
    Converts a python-compatible attribute name to the boto service name
    :param attribute_name: Python compatible attribute name. In essential the service name, if it is a python keyword
        prefixed by `aws`, and all `-` replaced by `_`.
    :return:
    """
    if attribute_name.startswith("aws"):
        # remove aws prefix for services named like a keyword.
        # Most notably, "awslambda" -> "lambda"
        attribute_name = attribute_name[3:]
    # replace all _ with -: cognito_idp -> cognito-idp
    return attribute_name.replace("_", "-")


#
# Data transfer object
#

INTERNAL_REQUEST_PARAMS_HEADER = "x-localstack-data"
"""Request header which contains the data transfer object."""


class InternalRequestParameters(TypedDict):
    """
    LocalStack Data Transfer Object.

    This is sent with every internal request and contains any additional information
    LocalStack might need for the purpose of policy enforcement. It is serialised
    into text and sent in the request header.

    Attributes can be added as needed. The keys should roughly correspond to:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
    """

    source_arn: str | None
    """ARN of resource which is triggering the call"""

    service_principal: str | None
    """Service principal making this call"""


def dump_dto(data: InternalRequestParameters) -> str:
    # TODO@viren: Minification can be improved using custom JSONEncoder that uses shortened keys

    # To produce a compact JSON representation of DTO, remove spaces from separators
    return json.dumps(data, separators=(",", ":"))


def load_dto(data: str) -> InternalRequestParameters:
    return json.loads(data)


#
# Factory
#
class ServiceClientResult:
    """
    TODO
    """

    acm: "ACMClient"
    apigateway: "APIGatewayClient"
    awslambda: "LambdaClient"
    cloudformation: "CloudFormationClient"
    cloudwatch: "CloudWatchClient"
    cognito_idp: "CognitoIdentityProviderClient"
    dynamodb: "DynamoDBClient"
    dynamodbstreams: "DynamoDBStreamsClient"
    ec2: "EC2Client"
    ecr: "ECRClient"
    es: "ElasticsearchServiceClient"
    events: "EventBridgeClient"
    firehose: "FirehoseClient"
    iam: "IAMClient"
    kinesis: "KinesisClient"
    kms: "KMSClient"
    logs: "CloudWatchLogsClient"
    opensearch: "OpenSearchServiceClient"
    redshift: "RedshiftClient"
    resource_groups: "ResourceGroupsClient"
    resourcegroupstaggingapi: "ResourceGroupsTaggingAPIClient"
    route53: "Route53Client"
    route53resolver: "Route53ResolverClient"
    s3: "S3Client"
    s3control: "S3ControlClient"
    secretsmanager: "SecretsManagerClient"
    ses: "SESClient"
    sns: "SNSClient"
    sqs: "SQSClient"
    ssm: "SSMClient"
    stepfunctions: "SFNClient"
    sts: "STSClient"
    transcribe: "TranscribeClient"

    def __init__(
        self, *, factory: "ClientFactory", client_creation_params: dict[str, str | Config | None]
    ):
        self._factory = factory
        self._client_creation_params = client_creation_params

    def __getattr__(self, service: str):
        service = attribute_name_to_service_name(service)
        return self._factory.get_client(service_name=service, **self._client_creation_params)


class ClientFactory(ABC):
    """
    Factory to build the AWS client.

    Boto client creation is resource intensive. This class caches all Boto
    clients it creates and must be used instead of directly using boto lib.
    """

    def __init__(
        self,
        use_ssl: bool = False,
        verify: bool = False,
        session: Session = None,
        config: Config = None,
    ):
        """
        :param use_ssl: Whether to use SSL
        :param verify: Whether to verify SSL certificates
        :param session: Session to be used for client creation. Will create a new session if not provided.
            Please note that sessions are not generally thread safe.
            Either create a new session for each factory or make sure the session is not shared with another thread.
            The factory itself has a lock for the session, so as long as you only use the session in one factory,
            it should be fine using the factory in a multithreaded context.
        :param config: Config used as default for client creation.
        """
        self._use_ssl = use_ssl
        self._verify = verify
        self._config: Config = config or Config(max_pool_connections=MAX_POOL_CONNECTIONS)
        self._session: Session = session or Session()
        self._create_client_lock = threading.RLock()

    def __call__(
        self,
        *,
        region_name: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        endpoint_url: str = None,
        config: Config = None,
    ) -> ServiceClientResult:
        """
        Get back an object which lets you select the typed service you want to access with the given attributes

        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, loads from botocore session.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param config: Boto config for advanced use.
        :return: Service Region Client Creator
        """
        params = {
            "region_name": region_name,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
            "aws_session_token": aws_session_token,
            "endpoint_url": endpoint_url,
            "config": config,
        }
        return ServiceClientResult(factory=self, client_creation_params=params)

    @abstractmethod
    def get_client(
        self,
        service_name: str,
        region_name: Optional[str],
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        endpoint_url: str = None,
        config: Config = None,
    ):
        raise NotImplementedError()

    def _get_client_post_hook(self, client: BaseClient) -> BaseClient:
        """
        This is called after the client is created by Boto.

        Any modifications to the client can be implemented here in subclasses
        without affecting the caching mechanism.
        """
        return client

    # TODO @cache here might result in a memory leak, as it keeps a reference to `self`
    # We might need an alternative caching decorator with a weak ref to `self`
    # Otherwise factories might never be garbage collected
    @cache
    def _get_client(
        self,
        service_name: str,
        region_name: str,
        use_ssl: bool,
        verify: bool,
        endpoint_url: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_session_token: str,
        config: Config,
    ) -> BaseClient:
        """
        Returns a boto3 client with the given configuration, and the hooks added by `_get_client_post_hook`.
        This is a cached call, so modifications to the used client will affect others.
        Please use another instance of the factory, should you want to modify clients.
        Client creation is behind a lock as it is not generally thread safe.

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, loads from botocore session.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param config: Boto config for advanced use.
        :return: Boto3 client.
        """
        with self._create_client_lock:
            client = self._session.client(
                service_name=service_name,
                region_name=region_name,
                use_ssl=use_ssl,
                verify=verify,
                endpoint_url=endpoint_url,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                config=config,
            )

        return self._get_client_post_hook(client)

    #
    # Boto session utilities
    #
    def _get_session_region(self) -> str:
        """
        Return AWS region as set in the Boto session.
        """
        return self._session.region_name

    def _get_region(self) -> str:
        """
        Return the AWS region name from following sources, in order of availability.
        - LocalStack request context
        - LocalStack default region
        - Boto session
        """
        return (
            get_region_from_request_context()
            or config.DEFAULT_REGION
            or self._get_session_region()  # TODO this will never be called, as DEFAULT_REGION defaults to 'us-east-1'
        )


class InternalClientFactory(ClientFactory):
    def _get_client_post_hook(self, client: BaseClient) -> BaseClient:
        """
        Register handlers that enable internal data object transfer mechanism
        for internal clients.
        """
        client.meta.events.register(
            "provide-client-params.*.*", handler=_handler_create_request_parameters
        )
        client.meta.events.register("before-call.*.*", handler=_handler_inject_dto_header)

        return client

    def get_client(
        self,
        service_name: str,
        region_name: Optional[str],
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        endpoint_url: str = None,
        config: Config = None,
    ) -> BaseClient:
        """
        Build and return client for connections originating within LocalStack.

        All API operation methods (such as `.list_buckets()` or `.run_instances()`
        take additional args that start with `_` prefix. These are used to pass
        additional information to LocalStack server during internal calls.

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Region name. See note above.
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            Defaults to LocalStack internal credentials.
        :param aws_secret_access_key: Secret key to use for the client.
            Defaults to LocalStack internal credentials.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param config: Boto config for advanced use.
        """

        return self._get_client(
            service_name=service_name,
            region_name=region_name or self._get_region(),
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url or get_local_service_url(service_name),
            aws_access_key_id=aws_access_key_id or INTERNAL_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=aws_secret_access_key or INTERNAL_AWS_SECRET_ACCESS_KEY,
            aws_session_token=aws_session_token,
            config=config or self._config,
        )


class ExternalClientFactory(ClientFactory):
    def get_client(
        self,
        service_name: str,
        region_name: Optional[str],
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        endpoint_url: str = None,
        config: Config = None,
    ) -> BaseClient:
        """
        Build and return client for connections originating outside LocalStack.

        If either of the access keys or region are set to None, they are loaded from following
        locations:
        - AWS environment variables
        - Credentials file `~/.aws/credentials`
        - Config file `~/.aws/config`

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, loads from botocore session.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param config: Boto config for advanced use.
        """

        return self._get_client(
            service_name=service_name,
            region_name=region_name or self._get_region(),
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url or get_local_service_url(service_name),
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            config=config or self._config,
        )


connect_to = InternalClientFactory()
connect_externally_to = ExternalClientFactory()

#
# Handlers
#


def _handler_create_request_parameters(params, model, context, **kwargs):
    """
    Construct the data transfer object at the time of parsing the client
    parameters and proxy it via the Boto context dict.

    This handler enables the use of additional keyword parameters in Boto API
    operation functions.
    """

    # Names of arguments that can be passed to Boto API operation functions.
    # These must correspond to entries on the data transfer object.
    dto = InternalRequestParameters()
    for member in InternalRequestParameters.__annotations__.keys():
        parameter = f"_{''.join([part.title() for part in member.split('_')])}"
        if parameter in params:
            dto[member] = params.pop(parameter)

    context["_localstack"] = dto


def _handler_inject_dto_header(model, params, request_signer, context, **kwargs):
    """
    Retrieve the data transfer object from the Boto context dict and serialise
    it as part of the request headers.
    """
    if (dto := context.pop("_localstack", None)) is not None:
        params["headers"][INTERNAL_REQUEST_PARAMS_HEADER] = dump_dto(dto)
