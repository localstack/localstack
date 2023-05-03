import abc
from typing import TYPE_CHECKING, Union

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
    from mypy_boto3_cloudcontrol import CloudControlApiClient
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_cloudfront import CloudFrontClient
    from mypy_boto3_cloudtrail import CloudTrailClient
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_codecommit import CodeCommitClient
    from mypy_boto3_cognito_identity import CognitoIdentityClient
    from mypy_boto3_cognito_idp import CognitoIdentityProviderClient
    from mypy_boto3_dms import DatabaseMigrationServiceClient
    from mypy_boto3_docdb import DocDBClient
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_dynamodbstreams import DynamoDBStreamsClient
    from mypy_boto3_ec2 import EC2Client
    from mypy_boto3_ecr import ECRClient
    from mypy_boto3_ecs import ECSClient
    from mypy_boto3_efs import EFSClient
    from mypy_boto3_eks import EKSClient
    from mypy_boto3_elasticache import ElastiCacheClient
    from mypy_boto3_elasticbeanstalk import ElasticBeanstalkClient
    from mypy_boto3_elbv2 import ElasticLoadBalancingv2Client
    from mypy_boto3_emr import EMRClient
    from mypy_boto3_es import ElasticsearchServiceClient
    from mypy_boto3_events import EventBridgeClient
    from mypy_boto3_firehose import FirehoseClient
    from mypy_boto3_fis import FISClient
    from mypy_boto3_glacier import GlacierClient
    from mypy_boto3_glue import GlueClient
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_iot import IoTClient
    from mypy_boto3_iot_data import IoTDataPlaneClient
    from mypy_boto3_iotanalytics import IoTAnalyticsClient
    from mypy_boto3_iotwireless import IoTWirelessClient
    from mypy_boto3_kafka import KafkaClient
    from mypy_boto3_kinesis import KinesisClient
    from mypy_boto3_kinesisanalytics import KinesisAnalyticsClient
    from mypy_boto3_kinesisanalyticsv2 import KinesisAnalyticsV2Client
    from mypy_boto3_kms import KMSClient
    from mypy_boto3_lakeformation import LakeFormationClient
    from mypy_boto3_lambda import LambdaClient
    from mypy_boto3_logs import CloudWatchLogsClient
    from mypy_boto3_mediaconvert import MediaConvertClient
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

    from localstack.aws.connect import MetadataRequestInjector


class TypedServiceClientFactory(abc.ABC):
    acm: Union["ACMClient", "MetadataRequestInjector[ACMClient]"]
    amplify: Union["AmplifyClient", "MetadataRequestInjector[AmplifyClient]"]
    apigateway: Union["APIGatewayClient", "MetadataRequestInjector[APIGatewayClient]"]
    apigatewayv2: Union["ApiGatewayV2Client", "MetadataRequestInjector[ApiGatewayV2Client]"]
    appconfig: Union["AppConfigClient", "MetadataRequestInjector[AppConfigClient]"]
    appsync: Union["AppSyncClient", "MetadataRequestInjector[AppSyncClient]"]
    athena: Union["AthenaClient", "MetadataRequestInjector[AthenaClient]"]
    autoscaling: Union["AutoScalingClient", "MetadataRequestInjector[AutoScalingClient]"]
    awslambda: Union["LambdaClient", "MetadataRequestInjector[LambdaClient]"]
    backup: Union["BackupClient", "MetadataRequestInjector[BackupClient]"]
    batch: Union["BatchClient", "MetadataRequestInjector[BatchClient]"]
    ce: Union["CostExplorerClient", "MetadataRequestInjector[CostExplorerClient]"]
    cloudcontrol: Union["CloudControlApiClient", "MetadataRequestInjector[CloudControlApiClient]"]
    cloudformation: Union["CloudFormationClient", "MetadataRequestInjector[CloudFormationClient]"]
    cloudfront: Union["CloudFrontClient", "MetadataRequestInjector[CloudFrontClient]"]
    cloudtrail: Union["CloudTrailClient", "MetadataRequestInjector[CloudTrailClient]"]
    cloudwatch: Union["CloudWatchClient", "MetadataRequestInjector[CloudWatchClient]"]
    codecommit: Union["CodeCommitClient", "MetadataRequestInjector[CodeCommitClient]"]
    cognito_identity: Union[
        "CognitoIdentityClient", "MetadataRequestInjector[CognitoIdentityClient]"
    ]
    cognito_idp: Union[
        "CognitoIdentityProviderClient", "MetadataRequestInjector[CognitoIdentityProviderClient]"
    ]
    dms: Union[
        "DatabaseMigrationServiceClient", "MetadataRequestInjector[DatabaseMigrationServiceClient]"
    ]
    docdb: Union["DocDBClient", "MetadataRequestInjector[DocDBClient]"]
    dynamodb: Union["DynamoDBClient", "MetadataRequestInjector[DynamoDBClient]"]
    dynamodbstreams: Union[
        "DynamoDBStreamsClient", "MetadataRequestInjector[DynamoDBStreamsClient]"
    ]
    ec2: Union["EC2Client", "MetadataRequestInjector[EC2Client]"]
    ecr: Union["ECRClient", "MetadataRequestInjector[ECRClient]"]
    ecs: Union["ECSClient", "MetadataRequestInjector[ECSClient]"]
    efs: Union["EFSClient", "MetadataRequestInjector[EFSClient]"]
    eks: Union["EKSClient", "MetadataRequestInjector[EKSClient]"]
    elasticache: Union["ElastiCacheClient", "MetadataRequestInjector[ElastiCacheClient]"]
    elasticbeanstalk: Union[
        "ElasticBeanstalkClient", "MetadataRequestInjector[ElasticBeanstalkClient]"
    ]
    elbv2: Union[
        "ElasticLoadBalancingv2Client", "MetadataRequestInjector[ElasticLoadBalancingv2Client]"
    ]
    emr: Union["EMRClient", "MetadataRequestInjector[EMRClient]"]
    es: Union["ElasticsearchServiceClient", "MetadataRequestInjector[ElasticsearchServiceClient]"]
    events: Union["EventBridgeClient", "MetadataRequestInjector[EventBridgeClient]"]
    firehose: Union["FirehoseClient", "MetadataRequestInjector[FirehoseClient]"]
    fis: Union["FISClient", "MetadataRequestInjector[FISClient]"]
    glacier: Union["GlacierClient", "MetadataRequestInjector[GlacierClient]"]
    glue: Union["GlueClient", "MetadataRequestInjector[GlueClient]"]
    iam: Union["IAMClient", "MetadataRequestInjector[IAMClient]"]
    iot: Union["IoTClient", "MetadataRequestInjector[IoTClient]"]
    iot_data: Union["IoTDataPlaneClient", "MetadataRequestInjector[IoTDataPlaneClient]"]
    iotanalytics: Union["IoTAnalyticsClient", "MetadataRequestInjector[IoTAnalyticsClient]"]
    iotwireless: Union["IoTWirelessClient", "MetadataRequestInjector[IoTWirelessClient]"]
    kafka: Union["KafkaClient", "MetadataRequestInjector[KafkaClient]"]
    kinesis: Union["KinesisClient", "MetadataRequestInjector[KinesisClient]"]
    kinesisanalytics: Union[
        "KinesisAnalyticsClient", "MetadataRequestInjector[KinesisAnalyticsClient]"
    ]
    kinesisanalyticsv2: Union[
        "KinesisAnalyticsV2Client", "MetadataRequestInjector[KinesisAnalyticsV2Client]"
    ]
    kms: Union["KMSClient", "MetadataRequestInjector[KMSClient]"]
    lakeformation: Union["LakeFormationClient", "MetadataRequestInjector[LakeFormationClient]"]
    logs: Union["CloudWatchLogsClient", "MetadataRequestInjector[CloudWatchLogsClient]"]
    mediaconvert: Union["MediaConvertClient", "MetadataRequestInjector[MediaConvertClient]"]
    mediastore: Union["MediaStoreClient", "MetadataRequestInjector[MediaStoreClient]"]
    mq: Union["MQClient", "MetadataRequestInjector[MQClient]"]
    mwaa: Union["MWAAClient", "MetadataRequestInjector[MWAAClient]"]
    neptune: Union["NeptuneClient", "MetadataRequestInjector[NeptuneClient]"]
    opensearch: Union["OpenSearchServiceClient", "MetadataRequestInjector[OpenSearchServiceClient]"]
    organizations: Union["OrganizationsClient", "MetadataRequestInjector[OrganizationsClient]"]
    pi: Union["PIClient", "MetadataRequestInjector[PIClient]"]
    qldb: Union["QLDBClient", "MetadataRequestInjector[QLDBClient]"]
    qldb_session: Union["QLDBSessionClient", "MetadataRequestInjector[QLDBSessionClient]"]
    rds: Union["RDSClient", "MetadataRequestInjector[RDSClient]"]
    rds_data: Union["RDSDataServiceClient", "MetadataRequestInjector[RDSDataServiceClient]"]
    redshift: Union["RedshiftClient", "MetadataRequestInjector[RedshiftClient]"]
    redshift_data: Union[
        "RedshiftDataAPIServiceClient", "MetadataRequestInjector[RedshiftDataAPIServiceClient]"
    ]
    resource_groups: Union["ResourceGroupsClient", "MetadataRequestInjector[ResourceGroupsClient]"]
    resourcegroupstaggingapi: Union[
        "ResourceGroupsTaggingAPIClient", "MetadataRequestInjector[ResourceGroupsTaggingAPIClient]"
    ]
    route53: Union["Route53Client", "MetadataRequestInjector[Route53Client]"]
    route53resolver: Union[
        "Route53ResolverClient", "MetadataRequestInjector[Route53ResolverClient]"
    ]
    s3: Union["S3Client", "MetadataRequestInjector[S3Client]"]
    s3control: Union["S3ControlClient", "MetadataRequestInjector[S3ControlClient]"]
    sagemaker: Union["SageMakerClient", "MetadataRequestInjector[SageMakerClient]"]
    sagemaker_runtime: Union[
        "SageMakerRuntimeClient", "MetadataRequestInjector[SageMakerRuntimeClient]"
    ]
    secretsmanager: Union["SecretsManagerClient", "MetadataRequestInjector[SecretsManagerClient]"]
    serverlessrepo: Union[
        "ServerlessApplicationRepositoryClient",
        "MetadataRequestInjector[ServerlessApplicationRepositoryClient]",
    ]
    servicediscovery: Union[
        "ServiceDiscoveryClient", "MetadataRequestInjector[ServiceDiscoveryClient]"
    ]
    ses: Union["SESClient", "MetadataRequestInjector[SESClient]"]
    sesv2: Union["SESV2Client", "MetadataRequestInjector[SESV2Client]"]
    sns: Union["SNSClient", "MetadataRequestInjector[SNSClient]"]
    sqs: Union["SQSClient", "MetadataRequestInjector[SQSClient]"]
    ssm: Union["SSMClient", "MetadataRequestInjector[SSMClient]"]
    stepfunctions: Union["SFNClient", "MetadataRequestInjector[SFNClient]"]
    sts: Union["STSClient", "MetadataRequestInjector[STSClient]"]
    timestream_query: Union[
        "TimestreamQueryClient", "MetadataRequestInjector[TimestreamQueryClient]"
    ]
    timestream_write: Union[
        "TimestreamWriteClient", "MetadataRequestInjector[TimestreamWriteClient]"
    ]
    transcribe: Union["TranscribeServiceClient", "MetadataRequestInjector[TranscribeServiceClient]"]
    xray: Union["XRayClient", "MetadataRequestInjector[XRayClient]"]


class ServicePrincipal(str):
    """
    Class containing defined service principals.
    To add to this list, please look up the correct service principal name for the service.
    They are in the format `<service-name>.amazonaws.com`, and can be found in the AWS IAM documentation.
    It is usually found under the `Service linked Roles` link for the respective service.
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html

    You can also find a list of service principals here:
    https://gist.github.com/shortjared/4c1e3fe52bdfa47522cfe5b41e5d6f22

    To save some space in our DTOs, we only add the `<service-name>` part of the service principal here.
    """

    awslambda = "lambda"
    apigateway = "apigateway"
    firehose = "firehose"
    sqs = "sqs"
    sns = "sns"
