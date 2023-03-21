"""
LocalStack client stack.

This module provides the interface to perform cross-service communication between
LocalStack providers.
"""
import json
import logging
import threading
from abc import ABC, abstractmethod
from functools import cache, partial
from typing import TYPE_CHECKING, Any, Callable, Generic, Optional, TypedDict, TypeVar, Union

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
    from mypy_boto3_amplify import AmplifyClient
    from mypy_boto3_apigateway import APIGatewayClient
    from mypy_boto3_apigatewayv2 import ApiGatewayV2Client
    from mypy_boto3_appconfig import AppConfigClient
    from mypy_boto3_appsync import AppSyncClient
    from mypy_boto3_athena import AthenaClient
    from mypy_boto3_autoscaling import AutoScalingClient
    from mypy_boto3_backup import BackupClient
    from mypy_boto3_batch import BatchClient
    from mypy_boto3_ce import CostExplorerClient
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_cloudfront import CloudFrontClient
    from mypy_boto3_cloudtrail import CloudTrailClient
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_codecommit import CodeCommitClient
    from mypy_boto3_cognito_identity import CognitoIdentityClient
    from mypy_boto3_cognito_idp import CognitoIdentityProviderClient
    from mypy_boto3_docdb import DocDBClient
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_dynamodbstreams import DynamoDBStreamsClient
    from mypy_boto3_ec2 import EC2Client
    from mypy_boto3_ecr import ECRClient
    from mypy_boto3_ecs import ECSClient
    from mypy_boto3_eks import EKSClient
    from mypy_boto3_elasticbeanstalk import ElasticBeanstalkClient
    from mypy_boto3_elbv2 import ElasticLoadBalancingv2Client
    from mypy_boto3_emr import EMRClient
    from mypy_boto3_es import ElasticsearchServiceClient
    from mypy_boto3_events import EventBridgeClient
    from mypy_boto3_firehose import FirehoseClient
    from mypy_boto3_glacier import GlacierClient
    from mypy_boto3_glue import GlueClient
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_iot import IoTClient
    from mypy_boto3_iot_data import IoTDataPlaneClient
    from mypy_boto3_iotanalytics import IoTAnalyticsClient
    from mypy_boto3_iotwireless import IoTWirelessClient
    from mypy_boto3_kafka import KafkaClient
    from mypy_boto3_kinesis import KinesisClient
    from mypy_boto3_kms import KMSClient
    from mypy_boto3_lakeformation import LakeFormationClient
    from mypy_boto3_lambda import LambdaClient
    from mypy_boto3_logs import CloudWatchLogsClient
    from mypy_boto3_mediastore import MediaStoreClient
    from mypy_boto3_mq import MQClient
    from mypy_boto3_mwaa import MWAAClient
    from mypy_boto3_neptune import NeptuneClient
    from mypy_boto3_opensearch import OpenSearchServiceClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_pi import PIClient
    from mypy_boto3_qldb import QLDBClient
    from mypy_boto3_qldb_session import QLDBSessionClient
    from mypy_boto3_rds import RDSClient
    from mypy_boto3_rds_data import RDSDataServiceClient
    from mypy_boto3_redshift import RedshiftClient
    from mypy_boto3_redshift_data import RedshiftDataAPIServiceClient
    from mypy_boto3_resource_groups import ResourceGroupsClient
    from mypy_boto3_resourcegroupstaggingapi import ResourceGroupsTaggingAPIClient
    from mypy_boto3_route53 import Route53Client
    from mypy_boto3_route53resolver import Route53ResolverClient
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_s3control import S3ControlClient
    from mypy_boto3_sagemaker import SageMakerClient
    from mypy_boto3_sagemaker_runtime import SageMakerRuntimeClient
    from mypy_boto3_secretsmanager import SecretsManagerClient
    from mypy_boto3_serverlessrepo import ServerlessApplicationRepositoryClient
    from mypy_boto3_servicediscovery import ServiceDiscoveryClient
    from mypy_boto3_ses import SESClient
    from mypy_boto3_sesv2 import SESV2Client
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sqs import SQSClient
    from mypy_boto3_ssm import SSMClient
    from mypy_boto3_stepfunctions import SFNClient
    from mypy_boto3_sts import STSClient
    from mypy_boto3_timestream_query import TimestreamQueryClient
    from mypy_boto3_timestream_write import TimestreamWriteClient
    from mypy_boto3_transcribe import TranscribeServiceClient
    from mypy_boto3_xray import XRayClient


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
    # To produce a compact JSON representation of DTO, remove spaces from separators
    # If possible, we could use a custom encoder to further decrease header size in the future
    return json.dumps(data, separators=(",", ":"))


def load_dto(data: str) -> InternalRequestParameters:
    return json.loads(data)


T = TypeVar("T")


class MetadataRequestInjector(Generic[T]):
    def __init__(self, client: T):
        self._client = client
        self._params = None

    def __getattr__(self, item):
        target = getattr(self._client, item)
        if not isinstance(target, Callable):
            return target
        if self._params:
            return partial(target, **self._params)
        else:
            return target

    def request_metadata(
        self, source_arn: str | None = None, service_principal: str | None = None
    ) -> Union[T, "MetadataRequestInjector[T]"]:
        params = {}
        if source_arn:
            params["_SourceArn"] = source_arn
        if service_principal:
            params["_ServicePrincipal"] = service_principal
        self._params = params
        return self


#
# Factory
#
class ServiceLevelClientFactory:
    """
    A service level client factory, preseeded with parameters for the boto3 client creation.
    Will create any service client with parameters already provided by the ClientFactory.
    """

    acm: Union["ACMClient", MetadataRequestInjector["ACMClient"]]
    amplify: Union["AmplifyClient", MetadataRequestInjector["AmplifyClient"]]
    apigateway: Union["APIGatewayClient", MetadataRequestInjector["APIGatewayClient"]]
    apigatewayv2: Union["ApiGatewayV2Client", MetadataRequestInjector["ApiGatewayV2Client"]]
    appconfig: Union["AppConfigClient", MetadataRequestInjector["AppConfigClient"]]
    appsync: Union["AppSyncClient", MetadataRequestInjector["AppSyncClient"]]
    athena: Union["AthenaClient", MetadataRequestInjector["AthenaClient"]]
    autoscaling: Union["AutoScalingClient", MetadataRequestInjector["AutoScalingClient"]]
    awslambda: Union["LambdaClient", MetadataRequestInjector["LambdaClient"]]
    backup: Union["BackupClient", MetadataRequestInjector["BackupClient"]]
    batch: Union["BatchClient", MetadataRequestInjector["BatchClient"]]
    ce: Union["CostExplorerClient", MetadataRequestInjector["CostExplorerClient"]]
    cloudformation: Union["CloudFormationClient", MetadataRequestInjector["CloudFormationClient"]]
    cloudfront: Union["CloudFrontClient", MetadataRequestInjector["CloudFrontClient"]]
    cloudtrail: Union["CloudTrailClient", MetadataRequestInjector["CloudTrailClient"]]
    cloudwatch: Union["CloudWatchClient", MetadataRequestInjector["CloudWatchClient"]]
    codecommit: Union["CodeCommitClient", MetadataRequestInjector["CodeCommitClient"]]
    cognito_identity: Union[
        "CognitoIdentityClient", MetadataRequestInjector["CognitoIdentityClient"]
    ]
    cognito_idp: Union[
        "CognitoIdentityProviderClient", MetadataRequestInjector["CognitoIdentityProviderClient"]
    ]
    docdb: Union["DocDBClient", MetadataRequestInjector["DocDBClient"]]
    dynamodb: Union["DynamoDBClient", MetadataRequestInjector["DynamoDBClient"]]
    dynamodbstreams: Union[
        "DynamoDBStreamsClient", MetadataRequestInjector["DynamoDBStreamsClient"]
    ]
    ec2: Union["EC2Client", MetadataRequestInjector["EC2Client"]]
    ecr: Union["ECRClient", MetadataRequestInjector["ECRClient"]]
    ecs: Union["ECSClient", MetadataRequestInjector["ECSClient"]]
    eks: Union["EKSClient", MetadataRequestInjector["EKSClient"]]
    elasticbeanstalk: Union[
        "ElasticBeanstalkClient", MetadataRequestInjector["ElasticBeanstalkClient"]
    ]
    elbv2: Union[
        "ElasticLoadBalancingv2Client", MetadataRequestInjector["ElasticLoadBalancingv2Client"]
    ]
    emr: Union["EMRClient", MetadataRequestInjector["EMRClient"]]
    es: Union["ElasticsearchServiceClient", MetadataRequestInjector["ElasticsearchServiceClient"]]
    events: Union["EventBridgeClient", MetadataRequestInjector["EventBridgeClient"]]
    firehose: Union["FirehoseClient", MetadataRequestInjector["FirehoseClient"]]
    glacier: Union["GlacierClient", MetadataRequestInjector["GlacierClient"]]
    glue: Union["GlueClient", MetadataRequestInjector["GlueClient"]]
    iam: Union["IAMClient", MetadataRequestInjector["IAMClient"]]
    iot: Union["IoTClient", MetadataRequestInjector["IoTClient"]]
    iot_data: Union["IoTDataPlaneClient", MetadataRequestInjector["IoTDataPlaneClient"]]
    iotanalytics: Union["IoTAnalyticsClient", MetadataRequestInjector["IoTAnalyticsClient"]]
    iotwireless: Union["IoTWirelessClient", MetadataRequestInjector["IoTWirelessClient"]]
    kafka: Union["KafkaClient", MetadataRequestInjector["KafkaClient"]]
    kinesis: Union["KinesisClient", MetadataRequestInjector["KinesisClient"]]
    kms: Union["KMSClient", MetadataRequestInjector["KMSClient"]]
    lakeformation: Union["LakeFormationClient", MetadataRequestInjector["LakeFormationClient"]]
    logs: Union["CloudWatchLogsClient", MetadataRequestInjector["CloudWatchLogsClient"]]
    mediastore: Union["MediaStoreClient", MetadataRequestInjector["MediaStoreClient"]]
    mq: Union["MQClient", MetadataRequestInjector["MQClient"]]
    mwaa: Union["MWAAClient", MetadataRequestInjector["MWAAClient"]]
    neptune: Union["NeptuneClient", MetadataRequestInjector["NeptuneClient"]]
    opensearch: Union["OpenSearchServiceClient", MetadataRequestInjector["OpenSearchServiceClient"]]
    organizations: Union["OrganizationsClient", MetadataRequestInjector["OrganizationsClient"]]
    pi: Union["PIClient", MetadataRequestInjector["PIClient"]]
    qldb: Union["QLDBClient", MetadataRequestInjector["QLDBClient"]]
    qldb_session: Union["QLDBSessionClient", MetadataRequestInjector["QLDBSessionClient"]]
    rds: Union["RDSClient", MetadataRequestInjector["RDSClient"]]
    rds_data: Union["RDSDataServiceClient", MetadataRequestInjector["RDSDataServiceClient"]]
    redshift: Union["RedshiftClient", MetadataRequestInjector["RedshiftClient"]]
    redshift_data: Union[
        "RedshiftDataAPIServiceClient", MetadataRequestInjector["RedshiftDataAPIServiceClient"]
    ]
    resource_groups: Union["ResourceGroupsClient", MetadataRequestInjector["ResourceGroupsClient"]]
    resourcegroupstaggingapi: Union[
        "ResourceGroupsTaggingAPIClient", MetadataRequestInjector["ResourceGroupsTaggingAPIClient"]
    ]
    route53: Union["Route53Client", MetadataRequestInjector["Route53Client"]]
    route53resolver: Union[
        "Route53ResolverClient", MetadataRequestInjector["Route53ResolverClient"]
    ]
    s3: Union["S3Client", MetadataRequestInjector["S3Client"]]
    s3control: Union["S3ControlClient", MetadataRequestInjector["S3ControlClient"]]
    sagemaker: Union["SageMakerClient", MetadataRequestInjector["SageMakerClient"]]
    sagemaker_runtime: Union[
        "SageMakerRuntimeClient", MetadataRequestInjector["SageMakerRuntimeClient"]
    ]
    secretsmanager: Union["SecretsManagerClient", MetadataRequestInjector["SecretsManagerClient"]]
    serverlessrepo: Union[
        "ServerlessApplicationRepositoryClient",
        MetadataRequestInjector["ServerlessApplicationRepositoryClient"],
    ]
    servicediscovery: Union[
        "ServiceDiscoveryClient", MetadataRequestInjector["ServiceDiscoveryClient"]
    ]
    ses: Union["SESClient", MetadataRequestInjector["SESClient"]]
    sesv2: Union["SESV2Client", MetadataRequestInjector["SESV2Client"]]
    sns: Union["SNSClient", MetadataRequestInjector["SNSClient"]]
    sqs: Union["SQSClient", MetadataRequestInjector["SQSClient"]]
    ssm: Union["SSMClient", MetadataRequestInjector["SSMClient"]]
    stepfunctions: Union["SFNClient", MetadataRequestInjector["SFNClient"]]
    sts: Union["STSClient", MetadataRequestInjector["STSClient"]]
    timestream_query: Union[
        "TimestreamQueryClient", MetadataRequestInjector["TimestreamQueryClient"]
    ]
    timestream_write: Union[
        "TimestreamWriteClient", MetadataRequestInjector["TimestreamWriteClient"]
    ]
    transcribe: Union["TranscribeServiceClient", MetadataRequestInjector["TranscribeServiceClient"]]
    xray: Union["XRayClient", MetadataRequestInjector["XRayClient"]]

    def __init__(
        self, *, factory: "ClientFactory", client_creation_params: dict[str, str | Config | None]
    ):
        self._factory = factory
        self._client_creation_params = client_creation_params

    def __getattr__(self, service: str):
        service = attribute_name_to_service_name(service)
        return MetadataRequestInjector(
            client=self._factory.get_client(service_name=service, **self._client_creation_params)
        )


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
    ) -> ServiceLevelClientFactory:
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
        return ServiceLevelClientFactory(factory=self, client_creation_params=params)

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
            get_region_from_request_context() or self._get_session_region() or config.DEFAULT_REGION
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


def _handler_create_request_parameters(params: dict[str, Any], context: dict[str, Any], **kwargs):
    """
    Construct the data transfer object at the time of parsing the client
    parameters and proxy it via the Boto context dict.

    This handler enables the use of additional keyword parameters in Boto API
    operation functions.

    It uses the `InternalRequestParameters` type annotations to handle supported parameters.
    The keys supported by this type will be converted to method parameters by prefixing it with an underscore `_`
    and converting the snake case to camel case.
    Example:
        service_principal -> _ServicePrincipal
    """

    # Names of arguments that can be passed to Boto API operation functions.
    # These must correspond to entries on the data transfer object.
    dto = InternalRequestParameters()
    for member in InternalRequestParameters.__annotations__.keys():
        parameter = f"_{''.join([part.title() for part in member.split('_')])}"
        if parameter in params:
            dto[member] = params.pop(parameter)

    context["_localstack"] = dto


def _handler_inject_dto_header(params: dict[str, Any], context: dict[str, Any], **kwargs):
    """
    Retrieve the data transfer object from the Boto context dict and serialise
    it as part of the request headers.
    """
    if (dto := context.pop("_localstack", None)) is not None:
        params["headers"][INTERNAL_REQUEST_PARAMS_HEADER] = dump_dto(dto)
