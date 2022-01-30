import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

MaxResults = int
__boolean = bool
__double = float
__integer = int
__integerMin1Max15 = int
__integerMin1Max16384 = int
__string = str
__stringMin1Max128 = str
__stringMin1Max64 = str
__stringMin5Max32 = str


class BrokerAZDistribution(str):
    DEFAULT = "DEFAULT"


class ClientBroker(str):
    TLS = "TLS"
    TLS_PLAINTEXT = "TLS_PLAINTEXT"
    PLAINTEXT = "PLAINTEXT"


class ClusterState(str):
    ACTIVE = "ACTIVE"
    CREATING = "CREATING"
    DELETING = "DELETING"
    FAILED = "FAILED"
    HEALING = "HEALING"
    MAINTENANCE = "MAINTENANCE"
    REBOOTING_BROKER = "REBOOTING_BROKER"
    UPDATING = "UPDATING"


class ClusterType(str):
    PROVISIONED = "PROVISIONED"
    SERVERLESS = "SERVERLESS"


class ConfigurationState(str):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    DELETE_FAILED = "DELETE_FAILED"


class EnhancedMonitoring(str):
    DEFAULT = "DEFAULT"
    PER_BROKER = "PER_BROKER"
    PER_TOPIC_PER_BROKER = "PER_TOPIC_PER_BROKER"
    PER_TOPIC_PER_PARTITION = "PER_TOPIC_PER_PARTITION"


class KafkaVersionStatus(str):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"


class NodeType(str):
    BROKER = "BROKER"


class BadRequestException(ServiceException):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


class ConflictException(ServiceException):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


class ForbiddenException(ServiceException):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


class InternalServerErrorException(ServiceException):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


class NotFoundException(ServiceException):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


class ServiceUnavailableException(ServiceException):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


class TooManyRequestsException(ServiceException):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


class UnauthorizedException(ServiceException):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


__listOf__string = List[__string]


class BatchAssociateScramSecretRequest(ServiceRequest):
    ClusterArn: __string
    SecretArnList: __listOf__string


class UnprocessedScramSecret(TypedDict, total=False):
    ErrorCode: Optional[__string]
    ErrorMessage: Optional[__string]
    SecretArn: Optional[__string]


__listOfUnprocessedScramSecret = List[UnprocessedScramSecret]


class BatchAssociateScramSecretResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    UnprocessedScramSecrets: Optional[__listOfUnprocessedScramSecret]


class BrokerEBSVolumeInfo(TypedDict, total=False):
    KafkaBrokerNodeId: __string
    VolumeSizeGB: __integer


class S3(TypedDict, total=False):
    Bucket: Optional[__string]
    Enabled: __boolean
    Prefix: Optional[__string]


class Firehose(TypedDict, total=False):
    DeliveryStream: Optional[__string]
    Enabled: __boolean


class CloudWatchLogs(TypedDict, total=False):
    Enabled: __boolean
    LogGroup: Optional[__string]


class BrokerLogs(TypedDict, total=False):
    CloudWatchLogs: Optional[CloudWatchLogs]
    Firehose: Optional[Firehose]
    S3: Optional[S3]


class PublicAccess(TypedDict, total=False):
    Type: Optional[__string]


class ConnectivityInfo(TypedDict, total=False):
    PublicAccess: Optional[PublicAccess]


class EBSStorageInfo(TypedDict, total=False):
    VolumeSize: Optional[__integerMin1Max16384]


class StorageInfo(TypedDict, total=False):
    EbsStorageInfo: Optional[EBSStorageInfo]


class BrokerNodeGroupInfo(TypedDict, total=False):
    BrokerAZDistribution: Optional[BrokerAZDistribution]
    ClientSubnets: __listOf__string
    InstanceType: __stringMin5Max32
    SecurityGroups: Optional[__listOf__string]
    StorageInfo: Optional[StorageInfo]
    ConnectivityInfo: Optional[ConnectivityInfo]


__long = int


class BrokerSoftwareInfo(TypedDict, total=False):
    ConfigurationArn: Optional[__string]
    ConfigurationRevision: Optional[__long]
    KafkaVersion: Optional[__string]


class BrokerNodeInfo(TypedDict, total=False):
    AttachedENIId: Optional[__string]
    BrokerId: Optional[__double]
    ClientSubnet: Optional[__string]
    ClientVpcIpAddress: Optional[__string]
    CurrentBrokerSoftwareInfo: Optional[BrokerSoftwareInfo]
    Endpoints: Optional[__listOf__string]


class Unauthenticated(TypedDict, total=False):
    Enabled: Optional[__boolean]


class Tls(TypedDict, total=False):
    CertificateAuthorityArnList: Optional[__listOf__string]
    Enabled: Optional[__boolean]


class Iam(TypedDict, total=False):
    Enabled: Optional[__boolean]


class Scram(TypedDict, total=False):
    Enabled: Optional[__boolean]


class Sasl(TypedDict, total=False):
    Scram: Optional[Scram]
    Iam: Optional[Iam]


class ClientAuthentication(TypedDict, total=False):
    Sasl: Optional[Sasl]
    Tls: Optional[Tls]
    Unauthenticated: Optional[Unauthenticated]


class ServerlessSasl(TypedDict, total=False):
    Iam: Optional[Iam]


class ServerlessClientAuthentication(TypedDict, total=False):
    Sasl: Optional[ServerlessSasl]


__mapOf__string = Dict[__string, __string]


class StateInfo(TypedDict, total=False):
    Code: Optional[__string]
    Message: Optional[__string]


class LoggingInfo(TypedDict, total=False):
    BrokerLogs: BrokerLogs


class NodeExporter(TypedDict, total=False):
    EnabledInBroker: __boolean


class JmxExporter(TypedDict, total=False):
    EnabledInBroker: __boolean


class Prometheus(TypedDict, total=False):
    JmxExporter: Optional[JmxExporter]
    NodeExporter: Optional[NodeExporter]


class OpenMonitoring(TypedDict, total=False):
    Prometheus: Prometheus


class EncryptionInTransit(TypedDict, total=False):
    ClientBroker: Optional[ClientBroker]
    InCluster: Optional[__boolean]


class EncryptionAtRest(TypedDict, total=False):
    DataVolumeKMSKeyId: __string


class EncryptionInfo(TypedDict, total=False):
    EncryptionAtRest: Optional[EncryptionAtRest]
    EncryptionInTransit: Optional[EncryptionInTransit]


__timestampIso8601 = datetime


class ClusterInfo(TypedDict, total=False):
    ActiveOperationArn: Optional[__string]
    BrokerNodeGroupInfo: Optional[BrokerNodeGroupInfo]
    ClientAuthentication: Optional[ClientAuthentication]
    ClusterArn: Optional[__string]
    ClusterName: Optional[__string]
    CreationTime: Optional[__timestampIso8601]
    CurrentBrokerSoftwareInfo: Optional[BrokerSoftwareInfo]
    CurrentVersion: Optional[__string]
    EncryptionInfo: Optional[EncryptionInfo]
    EnhancedMonitoring: Optional[EnhancedMonitoring]
    OpenMonitoring: Optional[OpenMonitoring]
    LoggingInfo: Optional[LoggingInfo]
    NumberOfBrokerNodes: Optional[__integer]
    State: Optional[ClusterState]
    StateInfo: Optional[StateInfo]
    Tags: Optional[__mapOf__string]
    ZookeeperConnectString: Optional[__string]
    ZookeeperConnectStringTls: Optional[__string]


class VpcConfig(TypedDict, total=False):
    SubnetIds: __listOf__string
    SecurityGroupIds: Optional[__listOf__string]


__listOfVpcConfig = List[VpcConfig]


class Serverless(TypedDict, total=False):
    VpcConfigs: __listOfVpcConfig
    ClientAuthentication: Optional[ServerlessClientAuthentication]


class NodeExporterInfo(TypedDict, total=False):
    EnabledInBroker: __boolean


class JmxExporterInfo(TypedDict, total=False):
    EnabledInBroker: __boolean


class PrometheusInfo(TypedDict, total=False):
    JmxExporter: Optional[JmxExporterInfo]
    NodeExporter: Optional[NodeExporterInfo]


class OpenMonitoringInfo(TypedDict, total=False):
    Prometheus: PrometheusInfo


class Provisioned(TypedDict, total=False):
    BrokerNodeGroupInfo: BrokerNodeGroupInfo
    CurrentBrokerSoftwareInfo: Optional[BrokerSoftwareInfo]
    ClientAuthentication: Optional[ClientAuthentication]
    EncryptionInfo: Optional[EncryptionInfo]
    EnhancedMonitoring: Optional[EnhancedMonitoring]
    OpenMonitoring: Optional[OpenMonitoringInfo]
    LoggingInfo: Optional[LoggingInfo]
    NumberOfBrokerNodes: __integerMin1Max15
    ZookeeperConnectString: Optional[__string]
    ZookeeperConnectStringTls: Optional[__string]


class Cluster(TypedDict, total=False):
    ActiveOperationArn: Optional[__string]
    ClusterType: Optional[ClusterType]
    ClusterArn: Optional[__string]
    ClusterName: Optional[__string]
    CreationTime: Optional[__timestampIso8601]
    CurrentVersion: Optional[__string]
    State: Optional[ClusterState]
    StateInfo: Optional[StateInfo]
    Tags: Optional[__mapOf__string]
    Provisioned: Optional[Provisioned]
    Serverless: Optional[Serverless]


class ConfigurationInfo(TypedDict, total=False):
    Arn: __string
    Revision: __long


__listOfBrokerEBSVolumeInfo = List[BrokerEBSVolumeInfo]


class MutableClusterInfo(TypedDict, total=False):
    BrokerEBSVolumeInfo: Optional[__listOfBrokerEBSVolumeInfo]
    ConfigurationInfo: Optional[ConfigurationInfo]
    NumberOfBrokerNodes: Optional[__integer]
    EnhancedMonitoring: Optional[EnhancedMonitoring]
    OpenMonitoring: Optional[OpenMonitoring]
    KafkaVersion: Optional[__string]
    LoggingInfo: Optional[LoggingInfo]
    InstanceType: Optional[__stringMin5Max32]
    ClientAuthentication: Optional[ClientAuthentication]
    EncryptionInfo: Optional[EncryptionInfo]
    ConnectivityInfo: Optional[ConnectivityInfo]


class ClusterOperationStepInfo(TypedDict, total=False):
    StepStatus: Optional[__string]


class ClusterOperationStep(TypedDict, total=False):
    StepInfo: Optional[ClusterOperationStepInfo]
    StepName: Optional[__string]


__listOfClusterOperationStep = List[ClusterOperationStep]


class ErrorInfo(TypedDict, total=False):
    ErrorCode: Optional[__string]
    ErrorString: Optional[__string]


class ClusterOperationInfo(TypedDict, total=False):
    ClientRequestId: Optional[__string]
    ClusterArn: Optional[__string]
    CreationTime: Optional[__timestampIso8601]
    EndTime: Optional[__timestampIso8601]
    ErrorInfo: Optional[ErrorInfo]
    OperationArn: Optional[__string]
    OperationState: Optional[__string]
    OperationSteps: Optional[__listOfClusterOperationStep]
    OperationType: Optional[__string]
    SourceClusterInfo: Optional[MutableClusterInfo]
    TargetClusterInfo: Optional[MutableClusterInfo]


class ProvisionedRequest(TypedDict, total=False):
    BrokerNodeGroupInfo: BrokerNodeGroupInfo
    ClientAuthentication: Optional[ClientAuthentication]
    ConfigurationInfo: Optional[ConfigurationInfo]
    EncryptionInfo: Optional[EncryptionInfo]
    EnhancedMonitoring: Optional[EnhancedMonitoring]
    OpenMonitoring: Optional[OpenMonitoringInfo]
    KafkaVersion: __stringMin1Max128
    LoggingInfo: Optional[LoggingInfo]
    NumberOfBrokerNodes: __integerMin1Max15


class ServerlessRequest(TypedDict, total=False):
    VpcConfigs: __listOfVpcConfig
    ClientAuthentication: Optional[ServerlessClientAuthentication]


class CompatibleKafkaVersion(TypedDict, total=False):
    SourceVersion: Optional[__string]
    TargetVersions: Optional[__listOf__string]


class ConfigurationRevision(TypedDict, total=False):
    CreationTime: __timestampIso8601
    Description: Optional[__string]
    Revision: __long


class Configuration(TypedDict, total=False):
    Arn: __string
    CreationTime: __timestampIso8601
    Description: __string
    KafkaVersions: __listOf__string
    LatestRevision: ConfigurationRevision
    Name: __string
    State: ConfigurationState


class CreateClusterV2Request(ServiceRequest):
    ClusterName: __stringMin1Max64
    Tags: Optional[__mapOf__string]
    Provisioned: Optional[ProvisionedRequest]
    Serverless: Optional[ServerlessRequest]


class CreateClusterRequest(ServiceRequest):
    BrokerNodeGroupInfo: BrokerNodeGroupInfo
    ClientAuthentication: Optional[ClientAuthentication]
    ClusterName: __stringMin1Max64
    ConfigurationInfo: Optional[ConfigurationInfo]
    EncryptionInfo: Optional[EncryptionInfo]
    EnhancedMonitoring: Optional[EnhancedMonitoring]
    OpenMonitoring: Optional[OpenMonitoringInfo]
    KafkaVersion: __stringMin1Max128
    LoggingInfo: Optional[LoggingInfo]
    NumberOfBrokerNodes: __integerMin1Max15
    Tags: Optional[__mapOf__string]


class CreateClusterResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterName: Optional[__string]
    State: Optional[ClusterState]


class CreateClusterV2Response(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterName: Optional[__string]
    State: Optional[ClusterState]
    ClusterType: Optional[ClusterType]


__blob = bytes


class CreateConfigurationRequest(ServiceRequest):
    Description: Optional[__string]
    KafkaVersions: Optional[__listOf__string]
    Name: __string
    ServerProperties: __blob


class CreateConfigurationResponse(TypedDict, total=False):
    Arn: Optional[__string]
    CreationTime: Optional[__timestampIso8601]
    LatestRevision: Optional[ConfigurationRevision]
    Name: Optional[__string]
    State: Optional[ConfigurationState]


class DeleteClusterRequest(ServiceRequest):
    ClusterArn: __string
    CurrentVersion: Optional[__string]


class DeleteClusterResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    State: Optional[ClusterState]


class DeleteConfigurationRequest(ServiceRequest):
    Arn: __string


class DeleteConfigurationResponse(TypedDict, total=False):
    Arn: Optional[__string]
    State: Optional[ConfigurationState]


class DescribeClusterOperationRequest(ServiceRequest):
    ClusterOperationArn: __string


class DescribeClusterOperationResponse(TypedDict, total=False):
    ClusterOperationInfo: Optional[ClusterOperationInfo]


class DescribeClusterRequest(ServiceRequest):
    ClusterArn: __string


class DescribeClusterV2Request(ServiceRequest):
    ClusterArn: __string


class DescribeClusterResponse(TypedDict, total=False):
    ClusterInfo: Optional[ClusterInfo]


class DescribeClusterV2Response(TypedDict, total=False):
    ClusterInfo: Optional[Cluster]


class DescribeConfigurationRequest(ServiceRequest):
    Arn: __string


class DescribeConfigurationResponse(TypedDict, total=False):
    Arn: Optional[__string]
    CreationTime: Optional[__timestampIso8601]
    Description: Optional[__string]
    KafkaVersions: Optional[__listOf__string]
    LatestRevision: Optional[ConfigurationRevision]
    Name: Optional[__string]
    State: Optional[ConfigurationState]


class DescribeConfigurationRevisionRequest(ServiceRequest):
    Arn: __string
    Revision: __long


class DescribeConfigurationRevisionResponse(TypedDict, total=False):
    Arn: Optional[__string]
    CreationTime: Optional[__timestampIso8601]
    Description: Optional[__string]
    Revision: Optional[__long]
    ServerProperties: Optional[__blob]


class BatchDisassociateScramSecretRequest(ServiceRequest):
    ClusterArn: __string
    SecretArnList: __listOf__string


class BatchDisassociateScramSecretResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    UnprocessedScramSecrets: Optional[__listOfUnprocessedScramSecret]


class Error(TypedDict, total=False):
    InvalidParameter: Optional[__string]
    Message: Optional[__string]


class GetBootstrapBrokersRequest(ServiceRequest):
    ClusterArn: __string


class GetBootstrapBrokersResponse(TypedDict, total=False):
    BootstrapBrokerString: Optional[__string]
    BootstrapBrokerStringTls: Optional[__string]
    BootstrapBrokerStringSaslScram: Optional[__string]
    BootstrapBrokerStringSaslIam: Optional[__string]
    BootstrapBrokerStringPublicTls: Optional[__string]
    BootstrapBrokerStringPublicSaslScram: Optional[__string]
    BootstrapBrokerStringPublicSaslIam: Optional[__string]


class GetCompatibleKafkaVersionsRequest(ServiceRequest):
    ClusterArn: Optional[__string]


__listOfCompatibleKafkaVersion = List[CompatibleKafkaVersion]


class GetCompatibleKafkaVersionsResponse(TypedDict, total=False):
    CompatibleKafkaVersions: Optional[__listOfCompatibleKafkaVersion]


class KafkaVersion(TypedDict, total=False):
    Version: Optional[__string]
    Status: Optional[KafkaVersionStatus]


class ListClusterOperationsRequest(ServiceRequest):
    ClusterArn: __string
    MaxResults: Optional[MaxResults]
    NextToken: Optional[__string]


__listOfClusterOperationInfo = List[ClusterOperationInfo]


class ListClusterOperationsResponse(TypedDict, total=False):
    ClusterOperationInfoList: Optional[__listOfClusterOperationInfo]
    NextToken: Optional[__string]


class ListClustersRequest(ServiceRequest):
    ClusterNameFilter: Optional[__string]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[__string]


class ListClustersV2Request(ServiceRequest):
    ClusterNameFilter: Optional[__string]
    ClusterTypeFilter: Optional[__string]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[__string]


__listOfClusterInfo = List[ClusterInfo]


class ListClustersResponse(TypedDict, total=False):
    ClusterInfoList: Optional[__listOfClusterInfo]
    NextToken: Optional[__string]


__listOfCluster = List[Cluster]


class ListClustersV2Response(TypedDict, total=False):
    ClusterInfoList: Optional[__listOfCluster]
    NextToken: Optional[__string]


class ListConfigurationRevisionsRequest(ServiceRequest):
    Arn: __string
    MaxResults: Optional[MaxResults]
    NextToken: Optional[__string]


__listOfConfigurationRevision = List[ConfigurationRevision]


class ListConfigurationRevisionsResponse(TypedDict, total=False):
    NextToken: Optional[__string]
    Revisions: Optional[__listOfConfigurationRevision]


class ListConfigurationsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[__string]


__listOfConfiguration = List[Configuration]


class ListConfigurationsResponse(TypedDict, total=False):
    Configurations: Optional[__listOfConfiguration]
    NextToken: Optional[__string]


class ListKafkaVersionsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[__string]


__listOfKafkaVersion = List[KafkaVersion]


class ListKafkaVersionsResponse(TypedDict, total=False):
    KafkaVersions: Optional[__listOfKafkaVersion]
    NextToken: Optional[__string]


class ListNodesRequest(ServiceRequest):
    ClusterArn: __string
    MaxResults: Optional[MaxResults]
    NextToken: Optional[__string]


class ZookeeperNodeInfo(TypedDict, total=False):
    AttachedENIId: Optional[__string]
    ClientVpcIpAddress: Optional[__string]
    Endpoints: Optional[__listOf__string]
    ZookeeperId: Optional[__double]
    ZookeeperVersion: Optional[__string]


class NodeInfo(TypedDict, total=False):
    AddedToClusterTime: Optional[__string]
    BrokerNodeInfo: Optional[BrokerNodeInfo]
    InstanceType: Optional[__string]
    NodeARN: Optional[__string]
    NodeType: Optional[NodeType]
    ZookeeperNodeInfo: Optional[ZookeeperNodeInfo]


__listOfNodeInfo = List[NodeInfo]


class ListNodesResponse(TypedDict, total=False):
    NextToken: Optional[__string]
    NodeInfoList: Optional[__listOfNodeInfo]


class ListScramSecretsRequest(ServiceRequest):
    ClusterArn: __string
    MaxResults: Optional[MaxResults]
    NextToken: Optional[__string]


class ListScramSecretsResponse(TypedDict, total=False):
    NextToken: Optional[__string]
    SecretArnList: Optional[__listOf__string]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: __string


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[__mapOf__string]


class RebootBrokerRequest(ServiceRequest):
    BrokerIds: __listOf__string
    ClusterArn: __string


class RebootBrokerResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class TagResourceRequest(ServiceRequest):
    ResourceArn: __string
    Tags: __mapOf__string


class UntagResourceRequest(ServiceRequest):
    ResourceArn: __string
    TagKeys: __listOf__string


class UpdateBrokerCountRequest(ServiceRequest):
    ClusterArn: __string
    CurrentVersion: __string
    TargetNumberOfBrokerNodes: __integerMin1Max15


class UpdateBrokerCountResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class UpdateBrokerTypeRequest(ServiceRequest):
    ClusterArn: __string
    CurrentVersion: __string
    TargetInstanceType: __string


class UpdateBrokerTypeResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class UpdateBrokerStorageRequest(ServiceRequest):
    ClusterArn: __string
    CurrentVersion: __string
    TargetBrokerEBSVolumeInfo: __listOfBrokerEBSVolumeInfo


class UpdateBrokerStorageResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class UpdateClusterConfigurationRequest(ServiceRequest):
    ClusterArn: __string
    ConfigurationInfo: ConfigurationInfo
    CurrentVersion: __string


class UpdateClusterConfigurationResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class UpdateClusterKafkaVersionRequest(ServiceRequest):
    ClusterArn: __string
    ConfigurationInfo: Optional[ConfigurationInfo]
    CurrentVersion: __string
    TargetKafkaVersion: __string


class UpdateClusterKafkaVersionResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class UpdateMonitoringRequest(ServiceRequest):
    ClusterArn: __string
    CurrentVersion: __string
    EnhancedMonitoring: Optional[EnhancedMonitoring]
    OpenMonitoring: Optional[OpenMonitoringInfo]
    LoggingInfo: Optional[LoggingInfo]


class UpdateMonitoringResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class UpdateSecurityRequest(ServiceRequest):
    ClientAuthentication: Optional[ClientAuthentication]
    ClusterArn: __string
    CurrentVersion: __string
    EncryptionInfo: Optional[EncryptionInfo]


class UpdateSecurityResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class UpdateConfigurationRequest(ServiceRequest):
    Arn: __string
    Description: Optional[__string]
    ServerProperties: __blob


class UpdateConfigurationResponse(TypedDict, total=False):
    Arn: Optional[__string]
    LatestRevision: Optional[ConfigurationRevision]


class UpdateConnectivityRequest(ServiceRequest):
    ClusterArn: __string
    ConnectivityInfo: ConnectivityInfo
    CurrentVersion: __string


class UpdateConnectivityResponse(TypedDict, total=False):
    ClusterArn: Optional[__string]
    ClusterOperationArn: Optional[__string]


class KafkaApi:

    service = "kafka"
    version = "2018-11-14"

    @handler("BatchAssociateScramSecret")
    def batch_associate_scram_secret(
        self,
        context: RequestContext,
        cluster_arn: __string,
        secret_arn_list: __listOf__string,
    ) -> BatchAssociateScramSecretResponse:
        raise NotImplementedError

    @handler("CreateCluster")
    def create_cluster(
        self,
        context: RequestContext,
        broker_node_group_info: BrokerNodeGroupInfo,
        kafka_version: __stringMin1Max128,
        number_of_broker_nodes: __integerMin1Max15,
        cluster_name: __stringMin1Max64,
        client_authentication: ClientAuthentication = None,
        configuration_info: ConfigurationInfo = None,
        encryption_info: EncryptionInfo = None,
        enhanced_monitoring: EnhancedMonitoring = None,
        open_monitoring: OpenMonitoringInfo = None,
        logging_info: LoggingInfo = None,
        tags: __mapOf__string = None,
    ) -> CreateClusterResponse:
        raise NotImplementedError

    @handler("CreateClusterV2")
    def create_cluster_v2(
        self,
        context: RequestContext,
        cluster_name: __stringMin1Max64,
        tags: __mapOf__string = None,
        provisioned: ProvisionedRequest = None,
        serverless: ServerlessRequest = None,
    ) -> CreateClusterV2Response:
        raise NotImplementedError

    @handler("CreateConfiguration")
    def create_configuration(
        self,
        context: RequestContext,
        server_properties: __blob,
        name: __string,
        description: __string = None,
        kafka_versions: __listOf__string = None,
    ) -> CreateConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteCluster")
    def delete_cluster(
        self,
        context: RequestContext,
        cluster_arn: __string,
        current_version: __string = None,
    ) -> DeleteClusterResponse:
        raise NotImplementedError

    @handler("DeleteConfiguration")
    def delete_configuration(
        self, context: RequestContext, arn: __string
    ) -> DeleteConfigurationResponse:
        raise NotImplementedError

    @handler("DescribeCluster")
    def describe_cluster(
        self, context: RequestContext, cluster_arn: __string
    ) -> DescribeClusterResponse:
        raise NotImplementedError

    @handler("DescribeClusterV2")
    def describe_cluster_v2(
        self, context: RequestContext, cluster_arn: __string
    ) -> DescribeClusterV2Response:
        raise NotImplementedError

    @handler("DescribeClusterOperation")
    def describe_cluster_operation(
        self, context: RequestContext, cluster_operation_arn: __string
    ) -> DescribeClusterOperationResponse:
        raise NotImplementedError

    @handler("DescribeConfiguration")
    def describe_configuration(
        self, context: RequestContext, arn: __string
    ) -> DescribeConfigurationResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRevision")
    def describe_configuration_revision(
        self, context: RequestContext, revision: __long, arn: __string
    ) -> DescribeConfigurationRevisionResponse:
        raise NotImplementedError

    @handler("BatchDisassociateScramSecret")
    def batch_disassociate_scram_secret(
        self,
        context: RequestContext,
        cluster_arn: __string,
        secret_arn_list: __listOf__string,
    ) -> BatchDisassociateScramSecretResponse:
        raise NotImplementedError

    @handler("GetBootstrapBrokers")
    def get_bootstrap_brokers(
        self, context: RequestContext, cluster_arn: __string
    ) -> GetBootstrapBrokersResponse:
        raise NotImplementedError

    @handler("GetCompatibleKafkaVersions")
    def get_compatible_kafka_versions(
        self, context: RequestContext, cluster_arn: __string = None
    ) -> GetCompatibleKafkaVersionsResponse:
        raise NotImplementedError

    @handler("ListClusterOperations")
    def list_cluster_operations(
        self,
        context: RequestContext,
        cluster_arn: __string,
        max_results: MaxResults = None,
        next_token: __string = None,
    ) -> ListClusterOperationsResponse:
        raise NotImplementedError

    @handler("ListClusters")
    def list_clusters(
        self,
        context: RequestContext,
        cluster_name_filter: __string = None,
        max_results: MaxResults = None,
        next_token: __string = None,
    ) -> ListClustersResponse:
        raise NotImplementedError

    @handler("ListClustersV2")
    def list_clusters_v2(
        self,
        context: RequestContext,
        cluster_name_filter: __string = None,
        cluster_type_filter: __string = None,
        max_results: MaxResults = None,
        next_token: __string = None,
    ) -> ListClustersV2Response:
        raise NotImplementedError

    @handler("ListConfigurationRevisions")
    def list_configuration_revisions(
        self,
        context: RequestContext,
        arn: __string,
        max_results: MaxResults = None,
        next_token: __string = None,
    ) -> ListConfigurationRevisionsResponse:
        raise NotImplementedError

    @handler("ListConfigurations")
    def list_configurations(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: __string = None,
    ) -> ListConfigurationsResponse:
        raise NotImplementedError

    @handler("ListKafkaVersions")
    def list_kafka_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: __string = None,
    ) -> ListKafkaVersionsResponse:
        raise NotImplementedError

    @handler("ListNodes")
    def list_nodes(
        self,
        context: RequestContext,
        cluster_arn: __string,
        max_results: MaxResults = None,
        next_token: __string = None,
    ) -> ListNodesResponse:
        raise NotImplementedError

    @handler("ListScramSecrets")
    def list_scram_secrets(
        self,
        context: RequestContext,
        cluster_arn: __string,
        max_results: MaxResults = None,
        next_token: __string = None,
    ) -> ListScramSecretsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: __string
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("RebootBroker")
    def reboot_broker(
        self,
        context: RequestContext,
        cluster_arn: __string,
        broker_ids: __listOf__string,
    ) -> RebootBrokerResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: __string, tags: __mapOf__string
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        tag_keys: __listOf__string,
        resource_arn: __string,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateBrokerCount")
    def update_broker_count(
        self,
        context: RequestContext,
        cluster_arn: __string,
        current_version: __string,
        target_number_of_broker_nodes: __integerMin1Max15,
    ) -> UpdateBrokerCountResponse:
        raise NotImplementedError

    @handler("UpdateBrokerType")
    def update_broker_type(
        self,
        context: RequestContext,
        cluster_arn: __string,
        current_version: __string,
        target_instance_type: __string,
    ) -> UpdateBrokerTypeResponse:
        raise NotImplementedError

    @handler("UpdateBrokerStorage")
    def update_broker_storage(
        self,
        context: RequestContext,
        cluster_arn: __string,
        target_broker_ebs_volume_info: __listOfBrokerEBSVolumeInfo,
        current_version: __string,
    ) -> UpdateBrokerStorageResponse:
        raise NotImplementedError

    @handler("UpdateConfiguration")
    def update_configuration(
        self,
        context: RequestContext,
        arn: __string,
        server_properties: __blob,
        description: __string = None,
    ) -> UpdateConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateConnectivity")
    def update_connectivity(
        self,
        context: RequestContext,
        cluster_arn: __string,
        connectivity_info: ConnectivityInfo,
        current_version: __string,
    ) -> UpdateConnectivityResponse:
        raise NotImplementedError

    @handler("UpdateClusterConfiguration")
    def update_cluster_configuration(
        self,
        context: RequestContext,
        cluster_arn: __string,
        current_version: __string,
        configuration_info: ConfigurationInfo,
    ) -> UpdateClusterConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateClusterKafkaVersion")
    def update_cluster_kafka_version(
        self,
        context: RequestContext,
        cluster_arn: __string,
        target_kafka_version: __string,
        current_version: __string,
        configuration_info: ConfigurationInfo = None,
    ) -> UpdateClusterKafkaVersionResponse:
        raise NotImplementedError

    @handler("UpdateMonitoring")
    def update_monitoring(
        self,
        context: RequestContext,
        cluster_arn: __string,
        current_version: __string,
        enhanced_monitoring: EnhancedMonitoring = None,
        open_monitoring: OpenMonitoringInfo = None,
        logging_info: LoggingInfo = None,
    ) -> UpdateMonitoringResponse:
        raise NotImplementedError

    @handler("UpdateSecurity")
    def update_security(
        self,
        context: RequestContext,
        cluster_arn: __string,
        current_version: __string,
        client_authentication: ClientAuthentication = None,
        encryption_info: EncryptionInfo = None,
    ) -> UpdateSecurityResponse:
        raise NotImplementedError
