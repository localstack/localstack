import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
BoxedBoolean = bool
BoxedInteger = int
Capacity = int
ClusterName = str
DescribeAddonVersionsRequestMaxResults = int
FargateProfilesRequestMaxResults = int
ListAddonsRequestMaxResults = int
ListClustersRequestMaxResults = int
ListIdentityProviderConfigsRequestMaxResults = int
ListNodegroupsRequestMaxResults = int
ListUpdatesRequestMaxResults = int
NonZeroInteger = int
PercentCapacity = int
RoleArn = str
String = str
TagKey = str
TagValue = str
ZeroCapacity = int
labelKey = str
labelValue = str
requiredClaimsKey = str
requiredClaimsValue = str
taintKey = str
taintValue = str


class AMITypes(str):
    AL2_x86_64 = "AL2_x86_64"
    AL2_x86_64_GPU = "AL2_x86_64_GPU"
    AL2_ARM_64 = "AL2_ARM_64"
    CUSTOM = "CUSTOM"
    BOTTLEROCKET_ARM_64 = "BOTTLEROCKET_ARM_64"
    BOTTLEROCKET_x86_64 = "BOTTLEROCKET_x86_64"


class AddonIssueCode(str):
    AccessDenied = "AccessDenied"
    InternalFailure = "InternalFailure"
    ClusterUnreachable = "ClusterUnreachable"
    InsufficientNumberOfReplicas = "InsufficientNumberOfReplicas"
    ConfigurationConflict = "ConfigurationConflict"
    AdmissionRequestDenied = "AdmissionRequestDenied"
    UnsupportedAddonModification = "UnsupportedAddonModification"
    K8sResourceNotFound = "K8sResourceNotFound"


class AddonStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    CREATE_FAILED = "CREATE_FAILED"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    DELETE_FAILED = "DELETE_FAILED"
    DEGRADED = "DEGRADED"


class CapacityTypes(str):
    ON_DEMAND = "ON_DEMAND"
    SPOT = "SPOT"


class ClusterStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    FAILED = "FAILED"
    UPDATING = "UPDATING"
    PENDING = "PENDING"


class ConnectorConfigProvider(str):
    EKS_ANYWHERE = "EKS_ANYWHERE"
    ANTHOS = "ANTHOS"
    GKE = "GKE"
    AKS = "AKS"
    OPENSHIFT = "OPENSHIFT"
    TANZU = "TANZU"
    RANCHER = "RANCHER"
    EC2 = "EC2"
    OTHER = "OTHER"


class ErrorCode(str):
    SubnetNotFound = "SubnetNotFound"
    SecurityGroupNotFound = "SecurityGroupNotFound"
    EniLimitReached = "EniLimitReached"
    IpNotAvailable = "IpNotAvailable"
    AccessDenied = "AccessDenied"
    OperationNotPermitted = "OperationNotPermitted"
    VpcIdNotFound = "VpcIdNotFound"
    Unknown = "Unknown"
    NodeCreationFailure = "NodeCreationFailure"
    PodEvictionFailure = "PodEvictionFailure"
    InsufficientFreeAddresses = "InsufficientFreeAddresses"
    ClusterUnreachable = "ClusterUnreachable"
    InsufficientNumberOfReplicas = "InsufficientNumberOfReplicas"
    ConfigurationConflict = "ConfigurationConflict"
    AdmissionRequestDenied = "AdmissionRequestDenied"
    UnsupportedAddonModification = "UnsupportedAddonModification"
    K8sResourceNotFound = "K8sResourceNotFound"


class FargateProfileStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_FAILED = "DELETE_FAILED"


class IpFamily(str):
    ipv4 = "ipv4"
    ipv6 = "ipv6"


class LogType(str):
    api = "api"
    audit = "audit"
    authenticator = "authenticator"
    controllerManager = "controllerManager"
    scheduler = "scheduler"


class NodegroupIssueCode(str):
    AutoScalingGroupNotFound = "AutoScalingGroupNotFound"
    AutoScalingGroupInvalidConfiguration = "AutoScalingGroupInvalidConfiguration"
    Ec2SecurityGroupNotFound = "Ec2SecurityGroupNotFound"
    Ec2SecurityGroupDeletionFailure = "Ec2SecurityGroupDeletionFailure"
    Ec2LaunchTemplateNotFound = "Ec2LaunchTemplateNotFound"
    Ec2LaunchTemplateVersionMismatch = "Ec2LaunchTemplateVersionMismatch"
    Ec2SubnetNotFound = "Ec2SubnetNotFound"
    Ec2SubnetInvalidConfiguration = "Ec2SubnetInvalidConfiguration"
    IamInstanceProfileNotFound = "IamInstanceProfileNotFound"
    IamLimitExceeded = "IamLimitExceeded"
    IamNodeRoleNotFound = "IamNodeRoleNotFound"
    NodeCreationFailure = "NodeCreationFailure"
    AsgInstanceLaunchFailures = "AsgInstanceLaunchFailures"
    InstanceLimitExceeded = "InstanceLimitExceeded"
    InsufficientFreeAddresses = "InsufficientFreeAddresses"
    AccessDenied = "AccessDenied"
    InternalFailure = "InternalFailure"
    ClusterUnreachable = "ClusterUnreachable"


class NodegroupStatus(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_FAILED = "DELETE_FAILED"
    DEGRADED = "DEGRADED"


class ResolveConflicts(str):
    OVERWRITE = "OVERWRITE"
    NONE = "NONE"


class TaintEffect(str):
    NO_SCHEDULE = "NO_SCHEDULE"
    NO_EXECUTE = "NO_EXECUTE"
    PREFER_NO_SCHEDULE = "PREFER_NO_SCHEDULE"


class UpdateParamType(str):
    Version = "Version"
    PlatformVersion = "PlatformVersion"
    EndpointPrivateAccess = "EndpointPrivateAccess"
    EndpointPublicAccess = "EndpointPublicAccess"
    ClusterLogging = "ClusterLogging"
    DesiredSize = "DesiredSize"
    LabelsToAdd = "LabelsToAdd"
    LabelsToRemove = "LabelsToRemove"
    TaintsToAdd = "TaintsToAdd"
    TaintsToRemove = "TaintsToRemove"
    MaxSize = "MaxSize"
    MinSize = "MinSize"
    ReleaseVersion = "ReleaseVersion"
    PublicAccessCidrs = "PublicAccessCidrs"
    LaunchTemplateName = "LaunchTemplateName"
    LaunchTemplateVersion = "LaunchTemplateVersion"
    IdentityProviderConfig = "IdentityProviderConfig"
    EncryptionConfig = "EncryptionConfig"
    AddonVersion = "AddonVersion"
    ServiceAccountRoleArn = "ServiceAccountRoleArn"
    ResolveConflicts = "ResolveConflicts"
    MaxUnavailable = "MaxUnavailable"
    MaxUnavailablePercentage = "MaxUnavailablePercentage"


class UpdateStatus(str):
    InProgress = "InProgress"
    Failed = "Failed"
    Cancelled = "Cancelled"
    Successful = "Successful"


class UpdateType(str):
    VersionUpdate = "VersionUpdate"
    EndpointAccessUpdate = "EndpointAccessUpdate"
    LoggingUpdate = "LoggingUpdate"
    ConfigUpdate = "ConfigUpdate"
    AssociateIdentityProviderConfig = "AssociateIdentityProviderConfig"
    DisassociateIdentityProviderConfig = "DisassociateIdentityProviderConfig"
    AssociateEncryptionConfig = "AssociateEncryptionConfig"
    AddonUpdate = "AddonUpdate"


class configStatus(str):
    CREATING = "CREATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"


class AccessDeniedException(ServiceException):
    message: Optional[String]


class BadRequestException(ServiceException):
    message: Optional[String]


class ClientException(ServiceException):
    clusterName: Optional[String]
    nodegroupName: Optional[String]
    addonName: Optional[String]
    message: Optional[String]


class InvalidParameterException(ServiceException):
    clusterName: Optional[String]
    nodegroupName: Optional[String]
    fargateProfileName: Optional[String]
    addonName: Optional[String]
    message: Optional[String]


class InvalidRequestException(ServiceException):
    clusterName: Optional[String]
    nodegroupName: Optional[String]
    addonName: Optional[String]
    message: Optional[String]


class NotFoundException(ServiceException):
    message: Optional[String]


class ResourceInUseException(ServiceException):
    clusterName: Optional[String]
    nodegroupName: Optional[String]
    addonName: Optional[String]
    message: Optional[String]


class ResourceLimitExceededException(ServiceException):
    clusterName: Optional[String]
    nodegroupName: Optional[String]
    message: Optional[String]


class ResourceNotFoundException(ServiceException):
    clusterName: Optional[String]
    nodegroupName: Optional[String]
    fargateProfileName: Optional[String]
    addonName: Optional[String]
    message: Optional[String]


class ResourcePropagationDelayException(ServiceException):
    message: Optional[String]


class ServerException(ServiceException):
    clusterName: Optional[String]
    nodegroupName: Optional[String]
    addonName: Optional[String]
    message: Optional[String]


class ServiceUnavailableException(ServiceException):
    message: Optional[String]


StringList = List[String]


class UnsupportedAvailabilityZoneException(ServiceException):
    message: Optional[String]
    clusterName: Optional[String]
    nodegroupName: Optional[String]
    validZones: Optional[StringList]


TagMap = Dict[TagKey, TagValue]
Timestamp = datetime


class AddonIssue(TypedDict, total=False):
    code: Optional[AddonIssueCode]
    message: Optional[String]
    resourceIds: Optional[StringList]


AddonIssueList = List[AddonIssue]


class AddonHealth(TypedDict, total=False):
    issues: Optional[AddonIssueList]


class Addon(TypedDict, total=False):
    addonName: Optional[String]
    clusterName: Optional[ClusterName]
    status: Optional[AddonStatus]
    addonVersion: Optional[String]
    health: Optional[AddonHealth]
    addonArn: Optional[String]
    createdAt: Optional[Timestamp]
    modifiedAt: Optional[Timestamp]
    serviceAccountRoleArn: Optional[String]
    tags: Optional[TagMap]


class Compatibility(TypedDict, total=False):
    clusterVersion: Optional[String]
    platformVersions: Optional[StringList]
    defaultVersion: Optional[Boolean]


Compatibilities = List[Compatibility]


class AddonVersionInfo(TypedDict, total=False):
    addonVersion: Optional[String]
    architecture: Optional[StringList]
    compatibilities: Optional[Compatibilities]


AddonVersionInfoList = List[AddonVersionInfo]
AddonInfo = TypedDict(
    "AddonInfo",
    {
        "addonName": Optional[String],
        "type": Optional[String],
        "addonVersions": Optional[AddonVersionInfoList],
    },
    total=False,
)
Addons = List[AddonInfo]


class Provider(TypedDict, total=False):
    keyArn: Optional[String]


class EncryptionConfig(TypedDict, total=False):
    resources: Optional[StringList]
    provider: Optional[Provider]


EncryptionConfigList = List[EncryptionConfig]


class AssociateEncryptionConfigRequest(ServiceRequest):
    clusterName: String
    encryptionConfig: EncryptionConfigList
    clientRequestToken: Optional[String]


class ErrorDetail(TypedDict, total=False):
    errorCode: Optional[ErrorCode]
    errorMessage: Optional[String]
    resourceIds: Optional[StringList]


ErrorDetails = List[ErrorDetail]
UpdateParam = TypedDict(
    "UpdateParam",
    {
        "type": Optional[UpdateParamType],
        "value": Optional[String],
    },
    total=False,
)
UpdateParams = List[UpdateParam]
Update = TypedDict(
    "Update",
    {
        "id": Optional[String],
        "status": Optional[UpdateStatus],
        "type": Optional[UpdateType],
        "params": Optional[UpdateParams],
        "createdAt": Optional[Timestamp],
        "errors": Optional[ErrorDetails],
    },
    total=False,
)


class AssociateEncryptionConfigResponse(TypedDict, total=False):
    update: Optional[Update]


requiredClaimsMap = Dict[requiredClaimsKey, requiredClaimsValue]


class OidcIdentityProviderConfigRequest(TypedDict, total=False):
    identityProviderConfigName: String
    issuerUrl: String
    clientId: String
    usernameClaim: Optional[String]
    usernamePrefix: Optional[String]
    groupsClaim: Optional[String]
    groupsPrefix: Optional[String]
    requiredClaims: Optional[requiredClaimsMap]


class AssociateIdentityProviderConfigRequest(ServiceRequest):
    clusterName: String
    oidc: OidcIdentityProviderConfigRequest
    tags: Optional[TagMap]
    clientRequestToken: Optional[String]


class AssociateIdentityProviderConfigResponse(TypedDict, total=False):
    update: Optional[Update]
    tags: Optional[TagMap]


class AutoScalingGroup(TypedDict, total=False):
    name: Optional[String]


AutoScalingGroupList = List[AutoScalingGroup]


class Certificate(TypedDict, total=False):
    data: Optional[String]


class ConnectorConfigResponse(TypedDict, total=False):
    activationId: Optional[String]
    activationCode: Optional[String]
    activationExpiry: Optional[Timestamp]
    provider: Optional[String]
    roleArn: Optional[String]


class OIDC(TypedDict, total=False):
    issuer: Optional[String]


class Identity(TypedDict, total=False):
    oidc: Optional[OIDC]


LogTypes = List[LogType]


class LogSetup(TypedDict, total=False):
    types: Optional[LogTypes]
    enabled: Optional[BoxedBoolean]


LogSetups = List[LogSetup]


class Logging(TypedDict, total=False):
    clusterLogging: Optional[LogSetups]


class KubernetesNetworkConfigResponse(TypedDict, total=False):
    serviceIpv4Cidr: Optional[String]
    serviceIpv6Cidr: Optional[String]
    ipFamily: Optional[IpFamily]


class VpcConfigResponse(TypedDict, total=False):
    subnetIds: Optional[StringList]
    securityGroupIds: Optional[StringList]
    clusterSecurityGroupId: Optional[String]
    vpcId: Optional[String]
    endpointPublicAccess: Optional[Boolean]
    endpointPrivateAccess: Optional[Boolean]
    publicAccessCidrs: Optional[StringList]


class Cluster(TypedDict, total=False):
    name: Optional[String]
    arn: Optional[String]
    createdAt: Optional[Timestamp]
    version: Optional[String]
    endpoint: Optional[String]
    roleArn: Optional[String]
    resourcesVpcConfig: Optional[VpcConfigResponse]
    kubernetesNetworkConfig: Optional[KubernetesNetworkConfigResponse]
    logging: Optional[Logging]
    identity: Optional[Identity]
    status: Optional[ClusterStatus]
    certificateAuthority: Optional[Certificate]
    clientRequestToken: Optional[String]
    platformVersion: Optional[String]
    tags: Optional[TagMap]
    encryptionConfig: Optional[EncryptionConfigList]
    connectorConfig: Optional[ConnectorConfigResponse]


class ConnectorConfigRequest(TypedDict, total=False):
    roleArn: String
    provider: ConnectorConfigProvider


class CreateAddonRequest(ServiceRequest):
    clusterName: ClusterName
    addonName: String
    addonVersion: Optional[String]
    serviceAccountRoleArn: Optional[RoleArn]
    resolveConflicts: Optional[ResolveConflicts]
    clientRequestToken: Optional[String]
    tags: Optional[TagMap]


class CreateAddonResponse(TypedDict, total=False):
    addon: Optional[Addon]


class KubernetesNetworkConfigRequest(TypedDict, total=False):
    serviceIpv4Cidr: Optional[String]
    ipFamily: Optional[IpFamily]


class VpcConfigRequest(TypedDict, total=False):
    subnetIds: Optional[StringList]
    securityGroupIds: Optional[StringList]
    endpointPublicAccess: Optional[BoxedBoolean]
    endpointPrivateAccess: Optional[BoxedBoolean]
    publicAccessCidrs: Optional[StringList]


class CreateClusterRequest(ServiceRequest):
    name: ClusterName
    version: Optional[String]
    roleArn: String
    resourcesVpcConfig: VpcConfigRequest
    kubernetesNetworkConfig: Optional[KubernetesNetworkConfigRequest]
    logging: Optional[Logging]
    clientRequestToken: Optional[String]
    tags: Optional[TagMap]
    encryptionConfig: Optional[EncryptionConfigList]


class CreateClusterResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


FargateProfileLabel = Dict[String, String]


class FargateProfileSelector(TypedDict, total=False):
    namespace: Optional[String]
    labels: Optional[FargateProfileLabel]


FargateProfileSelectors = List[FargateProfileSelector]


class CreateFargateProfileRequest(ServiceRequest):
    fargateProfileName: String
    clusterName: String
    podExecutionRoleArn: String
    subnets: Optional[StringList]
    selectors: Optional[FargateProfileSelectors]
    clientRequestToken: Optional[String]
    tags: Optional[TagMap]


class FargateProfile(TypedDict, total=False):
    fargateProfileName: Optional[String]
    fargateProfileArn: Optional[String]
    clusterName: Optional[String]
    createdAt: Optional[Timestamp]
    podExecutionRoleArn: Optional[String]
    subnets: Optional[StringList]
    selectors: Optional[FargateProfileSelectors]
    status: Optional[FargateProfileStatus]
    tags: Optional[TagMap]


class CreateFargateProfileResponse(TypedDict, total=False):
    fargateProfile: Optional[FargateProfile]


class NodegroupUpdateConfig(TypedDict, total=False):
    maxUnavailable: Optional[NonZeroInteger]
    maxUnavailablePercentage: Optional[PercentCapacity]


class LaunchTemplateSpecification(TypedDict, total=False):
    name: Optional[String]
    version: Optional[String]
    id: Optional[String]


class Taint(TypedDict, total=False):
    key: Optional[taintKey]
    value: Optional[taintValue]
    effect: Optional[TaintEffect]


taintsList = List[Taint]
labelsMap = Dict[labelKey, labelValue]


class RemoteAccessConfig(TypedDict, total=False):
    ec2SshKey: Optional[String]
    sourceSecurityGroups: Optional[StringList]


class NodegroupScalingConfig(TypedDict, total=False):
    minSize: Optional[ZeroCapacity]
    maxSize: Optional[Capacity]
    desiredSize: Optional[ZeroCapacity]


class CreateNodegroupRequest(ServiceRequest):
    clusterName: String
    nodegroupName: String
    scalingConfig: Optional[NodegroupScalingConfig]
    diskSize: Optional[BoxedInteger]
    subnets: StringList
    instanceTypes: Optional[StringList]
    amiType: Optional[AMITypes]
    remoteAccess: Optional[RemoteAccessConfig]
    nodeRole: String
    labels: Optional[labelsMap]
    taints: Optional[taintsList]
    tags: Optional[TagMap]
    clientRequestToken: Optional[String]
    launchTemplate: Optional[LaunchTemplateSpecification]
    updateConfig: Optional[NodegroupUpdateConfig]
    capacityType: Optional[CapacityTypes]
    version: Optional[String]
    releaseVersion: Optional[String]


class Issue(TypedDict, total=False):
    code: Optional[NodegroupIssueCode]
    message: Optional[String]
    resourceIds: Optional[StringList]


IssueList = List[Issue]


class NodegroupHealth(TypedDict, total=False):
    issues: Optional[IssueList]


class NodegroupResources(TypedDict, total=False):
    autoScalingGroups: Optional[AutoScalingGroupList]
    remoteAccessSecurityGroup: Optional[String]


class Nodegroup(TypedDict, total=False):
    nodegroupName: Optional[String]
    nodegroupArn: Optional[String]
    clusterName: Optional[String]
    version: Optional[String]
    releaseVersion: Optional[String]
    createdAt: Optional[Timestamp]
    modifiedAt: Optional[Timestamp]
    status: Optional[NodegroupStatus]
    capacityType: Optional[CapacityTypes]
    scalingConfig: Optional[NodegroupScalingConfig]
    instanceTypes: Optional[StringList]
    subnets: Optional[StringList]
    remoteAccess: Optional[RemoteAccessConfig]
    amiType: Optional[AMITypes]
    nodeRole: Optional[String]
    labels: Optional[labelsMap]
    taints: Optional[taintsList]
    resources: Optional[NodegroupResources]
    diskSize: Optional[BoxedInteger]
    health: Optional[NodegroupHealth]
    updateConfig: Optional[NodegroupUpdateConfig]
    launchTemplate: Optional[LaunchTemplateSpecification]
    tags: Optional[TagMap]


class CreateNodegroupResponse(TypedDict, total=False):
    nodegroup: Optional[Nodegroup]


class DeleteAddonRequest(ServiceRequest):
    clusterName: ClusterName
    addonName: String
    preserve: Optional[Boolean]


class DeleteAddonResponse(TypedDict, total=False):
    addon: Optional[Addon]


class DeleteClusterRequest(ServiceRequest):
    name: String


class DeleteClusterResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


class DeleteFargateProfileRequest(ServiceRequest):
    clusterName: String
    fargateProfileName: String


class DeleteFargateProfileResponse(TypedDict, total=False):
    fargateProfile: Optional[FargateProfile]


class DeleteNodegroupRequest(ServiceRequest):
    clusterName: String
    nodegroupName: String


class DeleteNodegroupResponse(TypedDict, total=False):
    nodegroup: Optional[Nodegroup]


class DeregisterClusterRequest(ServiceRequest):
    name: String


class DeregisterClusterResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


class DescribeAddonRequest(ServiceRequest):
    clusterName: ClusterName
    addonName: String


class DescribeAddonResponse(TypedDict, total=False):
    addon: Optional[Addon]


class DescribeAddonVersionsRequest(ServiceRequest):
    kubernetesVersion: Optional[String]
    maxResults: Optional[DescribeAddonVersionsRequestMaxResults]
    nextToken: Optional[String]
    addonName: Optional[String]


class DescribeAddonVersionsResponse(TypedDict, total=False):
    addons: Optional[Addons]
    nextToken: Optional[String]


class DescribeClusterRequest(ServiceRequest):
    name: String


class DescribeClusterResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


class DescribeFargateProfileRequest(ServiceRequest):
    clusterName: String
    fargateProfileName: String


class DescribeFargateProfileResponse(TypedDict, total=False):
    fargateProfile: Optional[FargateProfile]


IdentityProviderConfig = TypedDict(
    "IdentityProviderConfig",
    {
        "type": String,
        "name": String,
    },
    total=False,
)


class DescribeIdentityProviderConfigRequest(ServiceRequest):
    clusterName: String
    identityProviderConfig: IdentityProviderConfig


class OidcIdentityProviderConfig(TypedDict, total=False):
    identityProviderConfigName: Optional[String]
    identityProviderConfigArn: Optional[String]
    clusterName: Optional[String]
    issuerUrl: Optional[String]
    clientId: Optional[String]
    usernameClaim: Optional[String]
    usernamePrefix: Optional[String]
    groupsClaim: Optional[String]
    groupsPrefix: Optional[String]
    requiredClaims: Optional[requiredClaimsMap]
    tags: Optional[TagMap]
    status: Optional[configStatus]


class IdentityProviderConfigResponse(TypedDict, total=False):
    oidc: Optional[OidcIdentityProviderConfig]


class DescribeIdentityProviderConfigResponse(TypedDict, total=False):
    identityProviderConfig: Optional[IdentityProviderConfigResponse]


class DescribeNodegroupRequest(ServiceRequest):
    clusterName: String
    nodegroupName: String


class DescribeNodegroupResponse(TypedDict, total=False):
    nodegroup: Optional[Nodegroup]


class DescribeUpdateRequest(ServiceRequest):
    name: String
    updateId: String
    nodegroupName: Optional[String]
    addonName: Optional[String]


class DescribeUpdateResponse(TypedDict, total=False):
    update: Optional[Update]


class DisassociateIdentityProviderConfigRequest(ServiceRequest):
    clusterName: String
    identityProviderConfig: IdentityProviderConfig
    clientRequestToken: Optional[String]


class DisassociateIdentityProviderConfigResponse(TypedDict, total=False):
    update: Optional[Update]


IdentityProviderConfigs = List[IdentityProviderConfig]
IncludeClustersList = List[String]


class ListAddonsRequest(ServiceRequest):
    clusterName: ClusterName
    maxResults: Optional[ListAddonsRequestMaxResults]
    nextToken: Optional[String]


class ListAddonsResponse(TypedDict, total=False):
    addons: Optional[StringList]
    nextToken: Optional[String]


class ListClustersRequest(ServiceRequest):
    maxResults: Optional[ListClustersRequestMaxResults]
    nextToken: Optional[String]
    include: Optional[IncludeClustersList]


class ListClustersResponse(TypedDict, total=False):
    clusters: Optional[StringList]
    nextToken: Optional[String]


class ListFargateProfilesRequest(ServiceRequest):
    clusterName: String
    maxResults: Optional[FargateProfilesRequestMaxResults]
    nextToken: Optional[String]


class ListFargateProfilesResponse(TypedDict, total=False):
    fargateProfileNames: Optional[StringList]
    nextToken: Optional[String]


class ListIdentityProviderConfigsRequest(ServiceRequest):
    clusterName: String
    maxResults: Optional[ListIdentityProviderConfigsRequestMaxResults]
    nextToken: Optional[String]


class ListIdentityProviderConfigsResponse(TypedDict, total=False):
    identityProviderConfigs: Optional[IdentityProviderConfigs]
    nextToken: Optional[String]


class ListNodegroupsRequest(ServiceRequest):
    clusterName: String
    maxResults: Optional[ListNodegroupsRequestMaxResults]
    nextToken: Optional[String]


class ListNodegroupsResponse(TypedDict, total=False):
    nodegroups: Optional[StringList]
    nextToken: Optional[String]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: String


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagMap]


class ListUpdatesRequest(ServiceRequest):
    name: String
    nodegroupName: Optional[String]
    addonName: Optional[String]
    nextToken: Optional[String]
    maxResults: Optional[ListUpdatesRequestMaxResults]


class ListUpdatesResponse(TypedDict, total=False):
    updateIds: Optional[StringList]
    nextToken: Optional[String]


class RegisterClusterRequest(ServiceRequest):
    name: ClusterName
    connectorConfig: ConnectorConfigRequest
    clientRequestToken: Optional[String]
    tags: Optional[TagMap]


class RegisterClusterResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: String
    tags: TagMap


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: String
    tagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateAddonRequest(ServiceRequest):
    clusterName: ClusterName
    addonName: String
    addonVersion: Optional[String]
    serviceAccountRoleArn: Optional[RoleArn]
    resolveConflicts: Optional[ResolveConflicts]
    clientRequestToken: Optional[String]


class UpdateAddonResponse(TypedDict, total=False):
    update: Optional[Update]


class UpdateClusterConfigRequest(ServiceRequest):
    name: String
    resourcesVpcConfig: Optional[VpcConfigRequest]
    logging: Optional[Logging]
    clientRequestToken: Optional[String]


class UpdateClusterConfigResponse(TypedDict, total=False):
    update: Optional[Update]


class UpdateClusterVersionRequest(ServiceRequest):
    name: String
    version: String
    clientRequestToken: Optional[String]


class UpdateClusterVersionResponse(TypedDict, total=False):
    update: Optional[Update]


labelsKeyList = List[String]


class UpdateLabelsPayload(TypedDict, total=False):
    addOrUpdateLabels: Optional[labelsMap]
    removeLabels: Optional[labelsKeyList]


class UpdateTaintsPayload(TypedDict, total=False):
    addOrUpdateTaints: Optional[taintsList]
    removeTaints: Optional[taintsList]


class UpdateNodegroupConfigRequest(ServiceRequest):
    clusterName: String
    nodegroupName: String
    labels: Optional[UpdateLabelsPayload]
    taints: Optional[UpdateTaintsPayload]
    scalingConfig: Optional[NodegroupScalingConfig]
    updateConfig: Optional[NodegroupUpdateConfig]
    clientRequestToken: Optional[String]


class UpdateNodegroupConfigResponse(TypedDict, total=False):
    update: Optional[Update]


class UpdateNodegroupVersionRequest(ServiceRequest):
    clusterName: String
    nodegroupName: String
    version: Optional[String]
    releaseVersion: Optional[String]
    launchTemplate: Optional[LaunchTemplateSpecification]
    force: Optional[Boolean]
    clientRequestToken: Optional[String]


class UpdateNodegroupVersionResponse(TypedDict, total=False):
    update: Optional[Update]


class EksApi:

    service = "eks"
    version = "2017-11-01"

    @handler("AssociateEncryptionConfig")
    def associate_encryption_config(
        self,
        context: RequestContext,
        cluster_name: String,
        encryption_config: EncryptionConfigList,
        client_request_token: String = None,
    ) -> AssociateEncryptionConfigResponse:
        raise NotImplementedError

    @handler("AssociateIdentityProviderConfig")
    def associate_identity_provider_config(
        self,
        context: RequestContext,
        cluster_name: String,
        oidc: OidcIdentityProviderConfigRequest,
        tags: TagMap = None,
        client_request_token: String = None,
    ) -> AssociateIdentityProviderConfigResponse:
        raise NotImplementedError

    @handler("CreateAddon")
    def create_addon(
        self,
        context: RequestContext,
        cluster_name: ClusterName,
        addon_name: String,
        addon_version: String = None,
        service_account_role_arn: RoleArn = None,
        resolve_conflicts: ResolveConflicts = None,
        client_request_token: String = None,
        tags: TagMap = None,
    ) -> CreateAddonResponse:
        raise NotImplementedError

    @handler("CreateCluster")
    def create_cluster(
        self,
        context: RequestContext,
        name: ClusterName,
        role_arn: String,
        resources_vpc_config: VpcConfigRequest,
        version: String = None,
        kubernetes_network_config: KubernetesNetworkConfigRequest = None,
        logging: Logging = None,
        client_request_token: String = None,
        tags: TagMap = None,
        encryption_config: EncryptionConfigList = None,
    ) -> CreateClusterResponse:
        raise NotImplementedError

    @handler("CreateFargateProfile")
    def create_fargate_profile(
        self,
        context: RequestContext,
        fargate_profile_name: String,
        cluster_name: String,
        pod_execution_role_arn: String,
        subnets: StringList = None,
        selectors: FargateProfileSelectors = None,
        client_request_token: String = None,
        tags: TagMap = None,
    ) -> CreateFargateProfileResponse:
        raise NotImplementedError

    @handler("CreateNodegroup")
    def create_nodegroup(
        self,
        context: RequestContext,
        cluster_name: String,
        nodegroup_name: String,
        subnets: StringList,
        node_role: String,
        scaling_config: NodegroupScalingConfig = None,
        disk_size: BoxedInteger = None,
        instance_types: StringList = None,
        ami_type: AMITypes = None,
        remote_access: RemoteAccessConfig = None,
        labels: labelsMap = None,
        taints: taintsList = None,
        tags: TagMap = None,
        client_request_token: String = None,
        launch_template: LaunchTemplateSpecification = None,
        update_config: NodegroupUpdateConfig = None,
        capacity_type: CapacityTypes = None,
        version: String = None,
        release_version: String = None,
    ) -> CreateNodegroupResponse:
        raise NotImplementedError

    @handler("DeleteAddon")
    def delete_addon(
        self,
        context: RequestContext,
        cluster_name: ClusterName,
        addon_name: String,
        preserve: Boolean = None,
    ) -> DeleteAddonResponse:
        raise NotImplementedError

    @handler("DeleteCluster")
    def delete_cluster(self, context: RequestContext, name: String) -> DeleteClusterResponse:
        raise NotImplementedError

    @handler("DeleteFargateProfile")
    def delete_fargate_profile(
        self, context: RequestContext, cluster_name: String, fargate_profile_name: String
    ) -> DeleteFargateProfileResponse:
        raise NotImplementedError

    @handler("DeleteNodegroup")
    def delete_nodegroup(
        self, context: RequestContext, cluster_name: String, nodegroup_name: String
    ) -> DeleteNodegroupResponse:
        raise NotImplementedError

    @handler("DeregisterCluster")
    def deregister_cluster(
        self, context: RequestContext, name: String
    ) -> DeregisterClusterResponse:
        raise NotImplementedError

    @handler("DescribeAddon")
    def describe_addon(
        self, context: RequestContext, cluster_name: ClusterName, addon_name: String
    ) -> DescribeAddonResponse:
        raise NotImplementedError

    @handler("DescribeAddonVersions")
    def describe_addon_versions(
        self,
        context: RequestContext,
        kubernetes_version: String = None,
        max_results: DescribeAddonVersionsRequestMaxResults = None,
        next_token: String = None,
        addon_name: String = None,
    ) -> DescribeAddonVersionsResponse:
        raise NotImplementedError

    @handler("DescribeCluster")
    def describe_cluster(self, context: RequestContext, name: String) -> DescribeClusterResponse:
        raise NotImplementedError

    @handler("DescribeFargateProfile")
    def describe_fargate_profile(
        self, context: RequestContext, cluster_name: String, fargate_profile_name: String
    ) -> DescribeFargateProfileResponse:
        raise NotImplementedError

    @handler("DescribeIdentityProviderConfig")
    def describe_identity_provider_config(
        self,
        context: RequestContext,
        cluster_name: String,
        identity_provider_config: IdentityProviderConfig,
    ) -> DescribeIdentityProviderConfigResponse:
        raise NotImplementedError

    @handler("DescribeNodegroup")
    def describe_nodegroup(
        self, context: RequestContext, cluster_name: String, nodegroup_name: String
    ) -> DescribeNodegroupResponse:
        raise NotImplementedError

    @handler("DescribeUpdate")
    def describe_update(
        self,
        context: RequestContext,
        name: String,
        update_id: String,
        nodegroup_name: String = None,
        addon_name: String = None,
    ) -> DescribeUpdateResponse:
        raise NotImplementedError

    @handler("DisassociateIdentityProviderConfig")
    def disassociate_identity_provider_config(
        self,
        context: RequestContext,
        cluster_name: String,
        identity_provider_config: IdentityProviderConfig,
        client_request_token: String = None,
    ) -> DisassociateIdentityProviderConfigResponse:
        raise NotImplementedError

    @handler("ListAddons")
    def list_addons(
        self,
        context: RequestContext,
        cluster_name: ClusterName,
        max_results: ListAddonsRequestMaxResults = None,
        next_token: String = None,
    ) -> ListAddonsResponse:
        raise NotImplementedError

    @handler("ListClusters")
    def list_clusters(
        self,
        context: RequestContext,
        max_results: ListClustersRequestMaxResults = None,
        next_token: String = None,
        include: IncludeClustersList = None,
    ) -> ListClustersResponse:
        raise NotImplementedError

    @handler("ListFargateProfiles")
    def list_fargate_profiles(
        self,
        context: RequestContext,
        cluster_name: String,
        max_results: FargateProfilesRequestMaxResults = None,
        next_token: String = None,
    ) -> ListFargateProfilesResponse:
        raise NotImplementedError

    @handler("ListIdentityProviderConfigs")
    def list_identity_provider_configs(
        self,
        context: RequestContext,
        cluster_name: String,
        max_results: ListIdentityProviderConfigsRequestMaxResults = None,
        next_token: String = None,
    ) -> ListIdentityProviderConfigsResponse:
        raise NotImplementedError

    @handler("ListNodegroups")
    def list_nodegroups(
        self,
        context: RequestContext,
        cluster_name: String,
        max_results: ListNodegroupsRequestMaxResults = None,
        next_token: String = None,
    ) -> ListNodegroupsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: String
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListUpdates")
    def list_updates(
        self,
        context: RequestContext,
        name: String,
        nodegroup_name: String = None,
        addon_name: String = None,
        next_token: String = None,
        max_results: ListUpdatesRequestMaxResults = None,
    ) -> ListUpdatesResponse:
        raise NotImplementedError

    @handler("RegisterCluster")
    def register_cluster(
        self,
        context: RequestContext,
        name: ClusterName,
        connector_config: ConnectorConfigRequest,
        client_request_token: String = None,
        tags: TagMap = None,
    ) -> RegisterClusterResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: String, tags: TagMap
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: String, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateAddon")
    def update_addon(
        self,
        context: RequestContext,
        cluster_name: ClusterName,
        addon_name: String,
        addon_version: String = None,
        service_account_role_arn: RoleArn = None,
        resolve_conflicts: ResolveConflicts = None,
        client_request_token: String = None,
    ) -> UpdateAddonResponse:
        raise NotImplementedError

    @handler("UpdateClusterConfig")
    def update_cluster_config(
        self,
        context: RequestContext,
        name: String,
        resources_vpc_config: VpcConfigRequest = None,
        logging: Logging = None,
        client_request_token: String = None,
    ) -> UpdateClusterConfigResponse:
        raise NotImplementedError

    @handler("UpdateClusterVersion")
    def update_cluster_version(
        self,
        context: RequestContext,
        name: String,
        version: String,
        client_request_token: String = None,
    ) -> UpdateClusterVersionResponse:
        raise NotImplementedError

    @handler("UpdateNodegroupConfig")
    def update_nodegroup_config(
        self,
        context: RequestContext,
        cluster_name: String,
        nodegroup_name: String,
        labels: UpdateLabelsPayload = None,
        taints: UpdateTaintsPayload = None,
        scaling_config: NodegroupScalingConfig = None,
        update_config: NodegroupUpdateConfig = None,
        client_request_token: String = None,
    ) -> UpdateNodegroupConfigResponse:
        raise NotImplementedError

    @handler("UpdateNodegroupVersion")
    def update_nodegroup_version(
        self,
        context: RequestContext,
        cluster_name: String,
        nodegroup_name: String,
        version: String = None,
        release_version: String = None,
        launch_template: LaunchTemplateSpecification = None,
        force: Boolean = None,
        client_request_token: String = None,
    ) -> UpdateNodegroupVersionResponse:
        raise NotImplementedError
