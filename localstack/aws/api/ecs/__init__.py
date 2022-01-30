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
CapacityProviderStrategyItemBase = int
CapacityProviderStrategyItemWeight = int
Double = float
Integer = int
ManagedScalingInstanceWarmupPeriod = int
ManagedScalingStepSize = int
ManagedScalingTargetCapacity = int
SensitiveString = str
String = str
TagKey = str
TagValue = str


class AgentUpdateStatus(str):
    PENDING = "PENDING"
    STAGING = "STAGING"
    STAGED = "STAGED"
    UPDATING = "UPDATING"
    UPDATED = "UPDATED"
    FAILED = "FAILED"


class AssignPublicIp(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class CPUArchitecture(str):
    X86_64 = "X86_64"
    ARM64 = "ARM64"


class CapacityProviderField(str):
    TAGS = "TAGS"


class CapacityProviderStatus(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class CapacityProviderUpdateStatus(str):
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    DELETE_COMPLETE = "DELETE_COMPLETE"
    DELETE_FAILED = "DELETE_FAILED"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_COMPLETE = "UPDATE_COMPLETE"
    UPDATE_FAILED = "UPDATE_FAILED"


class ClusterField(str):
    ATTACHMENTS = "ATTACHMENTS"
    CONFIGURATIONS = "CONFIGURATIONS"
    SETTINGS = "SETTINGS"
    STATISTICS = "STATISTICS"
    TAGS = "TAGS"


class ClusterSettingName(str):
    containerInsights = "containerInsights"


class Compatibility(str):
    EC2 = "EC2"
    FARGATE = "FARGATE"
    EXTERNAL = "EXTERNAL"


class Connectivity(str):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"


class ContainerCondition(str):
    START = "START"
    COMPLETE = "COMPLETE"
    SUCCESS = "SUCCESS"
    HEALTHY = "HEALTHY"


class ContainerInstanceField(str):
    TAGS = "TAGS"
    CONTAINER_INSTANCE_HEALTH = "CONTAINER_INSTANCE_HEALTH"


class ContainerInstanceStatus(str):
    ACTIVE = "ACTIVE"
    DRAINING = "DRAINING"
    REGISTERING = "REGISTERING"
    DEREGISTERING = "DEREGISTERING"
    REGISTRATION_FAILED = "REGISTRATION_FAILED"


class DeploymentControllerType(str):
    ECS = "ECS"
    CODE_DEPLOY = "CODE_DEPLOY"
    EXTERNAL = "EXTERNAL"


class DeploymentRolloutState(str):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"


class DesiredStatus(str):
    RUNNING = "RUNNING"
    PENDING = "PENDING"
    STOPPED = "STOPPED"


class DeviceCgroupPermission(str):
    read = "read"
    write = "write"
    mknod = "mknod"


class EFSAuthorizationConfigIAM(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class EFSTransitEncryption(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class EnvironmentFileType(str):
    s3 = "s3"


class ExecuteCommandLogging(str):
    NONE = "NONE"
    DEFAULT = "DEFAULT"
    OVERRIDE = "OVERRIDE"


class FirelensConfigurationType(str):
    fluentd = "fluentd"
    fluentbit = "fluentbit"


class HealthStatus(str):
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


class InstanceHealthCheckState(str):
    OK = "OK"
    IMPAIRED = "IMPAIRED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    INITIALIZING = "INITIALIZING"


class InstanceHealthCheckType(str):
    CONTAINER_RUNTIME = "CONTAINER_RUNTIME"


class IpcMode(str):
    host = "host"
    task = "task"
    none = "none"


class LaunchType(str):
    EC2 = "EC2"
    FARGATE = "FARGATE"
    EXTERNAL = "EXTERNAL"


class LogDriver(str):
    json_file = "json-file"
    syslog = "syslog"
    journald = "journald"
    gelf = "gelf"
    fluentd = "fluentd"
    awslogs = "awslogs"
    splunk = "splunk"
    awsfirelens = "awsfirelens"


class ManagedAgentName(str):
    ExecuteCommandAgent = "ExecuteCommandAgent"


class ManagedScalingStatus(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ManagedTerminationProtection(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class NetworkMode(str):
    bridge = "bridge"
    host = "host"
    awsvpc = "awsvpc"
    none = "none"


class OSFamily(str):
    WINDOWS_SERVER_2019_FULL = "WINDOWS_SERVER_2019_FULL"
    WINDOWS_SERVER_2019_CORE = "WINDOWS_SERVER_2019_CORE"
    WINDOWS_SERVER_2016_FULL = "WINDOWS_SERVER_2016_FULL"
    WINDOWS_SERVER_2004_CORE = "WINDOWS_SERVER_2004_CORE"
    WINDOWS_SERVER_2022_CORE = "WINDOWS_SERVER_2022_CORE"
    WINDOWS_SERVER_2022_FULL = "WINDOWS_SERVER_2022_FULL"
    WINDOWS_SERVER_20H2_CORE = "WINDOWS_SERVER_20H2_CORE"
    LINUX = "LINUX"


class PidMode(str):
    host = "host"
    task = "task"


class PlacementConstraintType(str):
    distinctInstance = "distinctInstance"
    memberOf = "memberOf"


class PlacementStrategyType(str):
    random = "random"
    spread = "spread"
    binpack = "binpack"


class PlatformDeviceType(str):
    GPU = "GPU"


class PropagateTags(str):
    TASK_DEFINITION = "TASK_DEFINITION"
    SERVICE = "SERVICE"


class ProxyConfigurationType(str):
    APPMESH = "APPMESH"


class ResourceType(str):
    GPU = "GPU"
    InferenceAccelerator = "InferenceAccelerator"


class ScaleUnit(str):
    PERCENT = "PERCENT"


class SchedulingStrategy(str):
    REPLICA = "REPLICA"
    DAEMON = "DAEMON"


class Scope(str):
    task = "task"
    shared = "shared"


class ServiceField(str):
    TAGS = "TAGS"


class SettingName(str):
    serviceLongArnFormat = "serviceLongArnFormat"
    taskLongArnFormat = "taskLongArnFormat"
    containerInstanceLongArnFormat = "containerInstanceLongArnFormat"
    awsvpcTrunking = "awsvpcTrunking"
    containerInsights = "containerInsights"


class SortOrder(str):
    ASC = "ASC"
    DESC = "DESC"


class StabilityStatus(str):
    STEADY_STATE = "STEADY_STATE"
    STABILIZING = "STABILIZING"


class TargetType(str):
    container_instance = "container-instance"


class TaskDefinitionFamilyStatus(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ALL = "ALL"


class TaskDefinitionField(str):
    TAGS = "TAGS"


class TaskDefinitionPlacementConstraintType(str):
    memberOf = "memberOf"


class TaskDefinitionStatus(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class TaskField(str):
    TAGS = "TAGS"


class TaskSetField(str):
    TAGS = "TAGS"


class TaskStopCode(str):
    TaskFailedToStart = "TaskFailedToStart"
    EssentialContainerExited = "EssentialContainerExited"
    UserInitiated = "UserInitiated"


class TransportProtocol(str):
    tcp = "tcp"
    udp = "udp"


class UlimitName(str):
    core = "core"
    cpu = "cpu"
    data = "data"
    fsize = "fsize"
    locks = "locks"
    memlock = "memlock"
    msgqueue = "msgqueue"
    nice = "nice"
    nofile = "nofile"
    nproc = "nproc"
    rss = "rss"
    rtprio = "rtprio"
    rttime = "rttime"
    sigpending = "sigpending"
    stack = "stack"


class AccessDeniedException(ServiceException):
    pass


class AttributeLimitExceededException(ServiceException):
    pass


class BlockedException(ServiceException):
    pass


class ClientException(ServiceException):
    message: Optional[String]


class ClusterContainsContainerInstancesException(ServiceException):
    pass


class ClusterContainsServicesException(ServiceException):
    pass


class ClusterContainsTasksException(ServiceException):
    pass


class ClusterNotFoundException(ServiceException):
    pass


class InvalidParameterException(ServiceException):
    pass


class LimitExceededException(ServiceException):
    pass


class MissingVersionException(ServiceException):
    pass


class NoUpdateAvailableException(ServiceException):
    pass


class PlatformTaskDefinitionIncompatibilityException(ServiceException):
    pass


class PlatformUnknownException(ServiceException):
    pass


class ResourceInUseException(ServiceException):
    pass


class ResourceNotFoundException(ServiceException):
    pass


class ServerException(ServiceException):
    message: Optional[String]


class ServiceNotActiveException(ServiceException):
    pass


class ServiceNotFoundException(ServiceException):
    pass


class TargetNotConnectedException(ServiceException):
    pass


class TargetNotFoundException(ServiceException):
    pass


class TaskSetNotFoundException(ServiceException):
    pass


class UnsupportedFeatureException(ServiceException):
    pass


class UpdateInProgressException(ServiceException):
    pass


class KeyValuePair(TypedDict, total=False):
    name: Optional[String]
    value: Optional[String]


AttachmentDetails = List[KeyValuePair]
Attachment = TypedDict(
    "Attachment",
    {
        "id": Optional[String],
        "type": Optional[String],
        "status": Optional[String],
        "details": Optional[AttachmentDetails],
    },
    total=False,
)


class AttachmentStateChange(TypedDict, total=False):
    attachmentArn: String
    status: String


AttachmentStateChanges = List[AttachmentStateChange]
Attachments = List[Attachment]


class Attribute(TypedDict, total=False):
    name: String
    value: Optional[String]
    targetType: Optional[TargetType]
    targetId: Optional[String]


Attributes = List[Attribute]


class ManagedScaling(TypedDict, total=False):
    status: Optional[ManagedScalingStatus]
    targetCapacity: Optional[ManagedScalingTargetCapacity]
    minimumScalingStepSize: Optional[ManagedScalingStepSize]
    maximumScalingStepSize: Optional[ManagedScalingStepSize]
    instanceWarmupPeriod: Optional[ManagedScalingInstanceWarmupPeriod]


class AutoScalingGroupProvider(TypedDict, total=False):
    autoScalingGroupArn: String
    managedScaling: Optional[ManagedScaling]
    managedTerminationProtection: Optional[ManagedTerminationProtection]


class AutoScalingGroupProviderUpdate(TypedDict, total=False):
    managedScaling: Optional[ManagedScaling]
    managedTerminationProtection: Optional[ManagedTerminationProtection]


StringList = List[String]


class AwsVpcConfiguration(TypedDict, total=False):
    subnets: StringList
    securityGroups: Optional[StringList]
    assignPublicIp: Optional[AssignPublicIp]


class Tag(TypedDict, total=False):
    key: Optional[TagKey]
    value: Optional[TagValue]


Tags = List[Tag]


class CapacityProvider(TypedDict, total=False):
    capacityProviderArn: Optional[String]
    name: Optional[String]
    status: Optional[CapacityProviderStatus]
    autoScalingGroupProvider: Optional[AutoScalingGroupProvider]
    updateStatus: Optional[CapacityProviderUpdateStatus]
    updateStatusReason: Optional[String]
    tags: Optional[Tags]


CapacityProviderFieldList = List[CapacityProviderField]


class CapacityProviderStrategyItem(TypedDict, total=False):
    capacityProvider: String
    weight: Optional[CapacityProviderStrategyItemWeight]
    base: Optional[CapacityProviderStrategyItemBase]


CapacityProviderStrategy = List[CapacityProviderStrategyItem]
CapacityProviders = List[CapacityProvider]


class ClusterSetting(TypedDict, total=False):
    name: Optional[ClusterSettingName]
    value: Optional[String]


ClusterSettings = List[ClusterSetting]
Statistics = List[KeyValuePair]


class ExecuteCommandLogConfiguration(TypedDict, total=False):
    cloudWatchLogGroupName: Optional[String]
    cloudWatchEncryptionEnabled: Optional[Boolean]
    s3BucketName: Optional[String]
    s3EncryptionEnabled: Optional[Boolean]
    s3KeyPrefix: Optional[String]


class ExecuteCommandConfiguration(TypedDict, total=False):
    kmsKeyId: Optional[String]
    logging: Optional[ExecuteCommandLogging]
    logConfiguration: Optional[ExecuteCommandLogConfiguration]


class ClusterConfiguration(TypedDict, total=False):
    executeCommandConfiguration: Optional[ExecuteCommandConfiguration]


class Cluster(TypedDict, total=False):
    clusterArn: Optional[String]
    clusterName: Optional[String]
    configuration: Optional[ClusterConfiguration]
    status: Optional[String]
    registeredContainerInstancesCount: Optional[Integer]
    runningTasksCount: Optional[Integer]
    pendingTasksCount: Optional[Integer]
    activeServicesCount: Optional[Integer]
    statistics: Optional[Statistics]
    tags: Optional[Tags]
    settings: Optional[ClusterSettings]
    capacityProviders: Optional[StringList]
    defaultCapacityProviderStrategy: Optional[CapacityProviderStrategy]
    attachments: Optional[Attachments]
    attachmentsStatus: Optional[String]


ClusterFieldList = List[ClusterField]
Clusters = List[Cluster]
CompatibilityList = List[Compatibility]
GpuIds = List[String]
Timestamp = datetime


class ManagedAgent(TypedDict, total=False):
    lastStartedAt: Optional[Timestamp]
    name: Optional[ManagedAgentName]
    reason: Optional[String]
    lastStatus: Optional[String]


ManagedAgents = List[ManagedAgent]


class NetworkInterface(TypedDict, total=False):
    attachmentId: Optional[String]
    privateIpv4Address: Optional[String]
    ipv6Address: Optional[String]


NetworkInterfaces = List[NetworkInterface]


class NetworkBinding(TypedDict, total=False):
    bindIP: Optional[String]
    containerPort: Optional[BoxedInteger]
    hostPort: Optional[BoxedInteger]
    protocol: Optional[TransportProtocol]


NetworkBindings = List[NetworkBinding]


class Container(TypedDict, total=False):
    containerArn: Optional[String]
    taskArn: Optional[String]
    name: Optional[String]
    image: Optional[String]
    imageDigest: Optional[String]
    runtimeId: Optional[String]
    lastStatus: Optional[String]
    exitCode: Optional[BoxedInteger]
    reason: Optional[String]
    networkBindings: Optional[NetworkBindings]
    networkInterfaces: Optional[NetworkInterfaces]
    healthStatus: Optional[HealthStatus]
    managedAgents: Optional[ManagedAgents]
    cpu: Optional[String]
    memory: Optional[String]
    memoryReservation: Optional[String]
    gpuIds: Optional[GpuIds]


FirelensConfigurationOptionsMap = Dict[String, String]
FirelensConfiguration = TypedDict(
    "FirelensConfiguration",
    {
        "type": FirelensConfigurationType,
        "options": Optional[FirelensConfigurationOptionsMap],
    },
    total=False,
)
ResourceRequirement = TypedDict(
    "ResourceRequirement",
    {
        "value": String,
        "type": ResourceType,
    },
    total=False,
)
ResourceRequirements = List[ResourceRequirement]


class SystemControl(TypedDict, total=False):
    namespace: Optional[String]
    value: Optional[String]


SystemControls = List[SystemControl]


class HealthCheck(TypedDict, total=False):
    command: StringList
    interval: Optional[BoxedInteger]
    timeout: Optional[BoxedInteger]
    retries: Optional[BoxedInteger]
    startPeriod: Optional[BoxedInteger]


class Secret(TypedDict, total=False):
    name: String
    valueFrom: String


SecretList = List[Secret]
LogConfigurationOptionsMap = Dict[String, String]


class LogConfiguration(TypedDict, total=False):
    logDriver: LogDriver
    options: Optional[LogConfigurationOptionsMap]
    secretOptions: Optional[SecretList]


class Ulimit(TypedDict, total=False):
    name: UlimitName
    softLimit: Integer
    hardLimit: Integer


UlimitList = List[Ulimit]
DockerLabelsMap = Dict[String, String]


class HostEntry(TypedDict, total=False):
    hostname: String
    ipAddress: String


HostEntryList = List[HostEntry]


class ContainerDependency(TypedDict, total=False):
    containerName: String
    condition: ContainerCondition


ContainerDependencies = List[ContainerDependency]


class Tmpfs(TypedDict, total=False):
    containerPath: String
    size: Integer
    mountOptions: Optional[StringList]


TmpfsList = List[Tmpfs]
DeviceCgroupPermissions = List[DeviceCgroupPermission]


class Device(TypedDict, total=False):
    hostPath: String
    containerPath: Optional[String]
    permissions: Optional[DeviceCgroupPermissions]


DevicesList = List[Device]


class KernelCapabilities(TypedDict, total=False):
    add: Optional[StringList]
    drop: Optional[StringList]


class LinuxParameters(TypedDict, total=False):
    capabilities: Optional[KernelCapabilities]
    devices: Optional[DevicesList]
    initProcessEnabled: Optional[BoxedBoolean]
    sharedMemorySize: Optional[BoxedInteger]
    tmpfs: Optional[TmpfsList]
    maxSwap: Optional[BoxedInteger]
    swappiness: Optional[BoxedInteger]


class VolumeFrom(TypedDict, total=False):
    sourceContainer: Optional[String]
    readOnly: Optional[BoxedBoolean]


VolumeFromList = List[VolumeFrom]


class MountPoint(TypedDict, total=False):
    sourceVolume: Optional[String]
    containerPath: Optional[String]
    readOnly: Optional[BoxedBoolean]


MountPointList = List[MountPoint]
EnvironmentFile = TypedDict(
    "EnvironmentFile",
    {
        "value": String,
        "type": EnvironmentFileType,
    },
    total=False,
)
EnvironmentFiles = List[EnvironmentFile]
EnvironmentVariables = List[KeyValuePair]


class PortMapping(TypedDict, total=False):
    containerPort: Optional[BoxedInteger]
    hostPort: Optional[BoxedInteger]
    protocol: Optional[TransportProtocol]


PortMappingList = List[PortMapping]


class RepositoryCredentials(TypedDict, total=False):
    credentialsParameter: String


class ContainerDefinition(TypedDict, total=False):
    name: Optional[String]
    image: Optional[String]
    repositoryCredentials: Optional[RepositoryCredentials]
    cpu: Optional[Integer]
    memory: Optional[BoxedInteger]
    memoryReservation: Optional[BoxedInteger]
    links: Optional[StringList]
    portMappings: Optional[PortMappingList]
    essential: Optional[BoxedBoolean]
    entryPoint: Optional[StringList]
    command: Optional[StringList]
    environment: Optional[EnvironmentVariables]
    environmentFiles: Optional[EnvironmentFiles]
    mountPoints: Optional[MountPointList]
    volumesFrom: Optional[VolumeFromList]
    linuxParameters: Optional[LinuxParameters]
    secrets: Optional[SecretList]
    dependsOn: Optional[ContainerDependencies]
    startTimeout: Optional[BoxedInteger]
    stopTimeout: Optional[BoxedInteger]
    hostname: Optional[String]
    user: Optional[String]
    workingDirectory: Optional[String]
    disableNetworking: Optional[BoxedBoolean]
    privileged: Optional[BoxedBoolean]
    readonlyRootFilesystem: Optional[BoxedBoolean]
    dnsServers: Optional[StringList]
    dnsSearchDomains: Optional[StringList]
    extraHosts: Optional[HostEntryList]
    dockerSecurityOptions: Optional[StringList]
    interactive: Optional[BoxedBoolean]
    pseudoTerminal: Optional[BoxedBoolean]
    dockerLabels: Optional[DockerLabelsMap]
    ulimits: Optional[UlimitList]
    logConfiguration: Optional[LogConfiguration]
    healthCheck: Optional[HealthCheck]
    systemControls: Optional[SystemControls]
    resourceRequirements: Optional[ResourceRequirements]
    firelensConfiguration: Optional[FirelensConfiguration]


ContainerDefinitions = List[ContainerDefinition]
InstanceHealthCheckResult = TypedDict(
    "InstanceHealthCheckResult",
    {
        "type": Optional[InstanceHealthCheckType],
        "status": Optional[InstanceHealthCheckState],
        "lastUpdated": Optional[Timestamp],
        "lastStatusChange": Optional[Timestamp],
    },
    total=False,
)
InstanceHealthCheckResultList = List[InstanceHealthCheckResult]


class ContainerInstanceHealthStatus(TypedDict, total=False):
    overallStatus: Optional[InstanceHealthCheckState]
    details: Optional[InstanceHealthCheckResultList]


Long = int
Resource = TypedDict(
    "Resource",
    {
        "name": Optional[String],
        "type": Optional[String],
        "doubleValue": Optional[Double],
        "longValue": Optional[Long],
        "integerValue": Optional[Integer],
        "stringSetValue": Optional[StringList],
    },
    total=False,
)
Resources = List[Resource]


class VersionInfo(TypedDict, total=False):
    agentVersion: Optional[String]
    agentHash: Optional[String]
    dockerVersion: Optional[String]


class ContainerInstance(TypedDict, total=False):
    containerInstanceArn: Optional[String]
    ec2InstanceId: Optional[String]
    capacityProviderName: Optional[String]
    version: Optional[Long]
    versionInfo: Optional[VersionInfo]
    remainingResources: Optional[Resources]
    registeredResources: Optional[Resources]
    status: Optional[String]
    statusReason: Optional[String]
    agentConnected: Optional[Boolean]
    runningTasksCount: Optional[Integer]
    pendingTasksCount: Optional[Integer]
    agentUpdateStatus: Optional[AgentUpdateStatus]
    attributes: Optional[Attributes]
    registeredAt: Optional[Timestamp]
    attachments: Optional[Attachments]
    tags: Optional[Tags]
    healthStatus: Optional[ContainerInstanceHealthStatus]


ContainerInstanceFieldList = List[ContainerInstanceField]
ContainerInstances = List[ContainerInstance]


class ContainerOverride(TypedDict, total=False):
    name: Optional[String]
    command: Optional[StringList]
    environment: Optional[EnvironmentVariables]
    environmentFiles: Optional[EnvironmentFiles]
    cpu: Optional[BoxedInteger]
    memory: Optional[BoxedInteger]
    memoryReservation: Optional[BoxedInteger]
    resourceRequirements: Optional[ResourceRequirements]


ContainerOverrides = List[ContainerOverride]


class ContainerStateChange(TypedDict, total=False):
    containerName: Optional[String]
    imageDigest: Optional[String]
    runtimeId: Optional[String]
    exitCode: Optional[BoxedInteger]
    networkBindings: Optional[NetworkBindings]
    reason: Optional[String]
    status: Optional[String]


ContainerStateChanges = List[ContainerStateChange]
Containers = List[Container]


class CreateCapacityProviderRequest(ServiceRequest):
    name: String
    autoScalingGroupProvider: AutoScalingGroupProvider
    tags: Optional[Tags]


class CreateCapacityProviderResponse(TypedDict, total=False):
    capacityProvider: Optional[CapacityProvider]


class CreateClusterRequest(ServiceRequest):
    clusterName: Optional[String]
    tags: Optional[Tags]
    settings: Optional[ClusterSettings]
    configuration: Optional[ClusterConfiguration]
    capacityProviders: Optional[StringList]
    defaultCapacityProviderStrategy: Optional[CapacityProviderStrategy]


class CreateClusterResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


DeploymentController = TypedDict(
    "DeploymentController",
    {
        "type": DeploymentControllerType,
    },
    total=False,
)


class NetworkConfiguration(TypedDict, total=False):
    awsvpcConfiguration: Optional[AwsVpcConfiguration]


PlacementStrategy = TypedDict(
    "PlacementStrategy",
    {
        "type": Optional[PlacementStrategyType],
        "field": Optional[String],
    },
    total=False,
)
PlacementStrategies = List[PlacementStrategy]
PlacementConstraint = TypedDict(
    "PlacementConstraint",
    {
        "type": Optional[PlacementConstraintType],
        "expression": Optional[String],
    },
    total=False,
)
PlacementConstraints = List[PlacementConstraint]


class DeploymentCircuitBreaker(TypedDict, total=False):
    enable: Boolean
    rollback: Boolean


class DeploymentConfiguration(TypedDict, total=False):
    deploymentCircuitBreaker: Optional[DeploymentCircuitBreaker]
    maximumPercent: Optional[BoxedInteger]
    minimumHealthyPercent: Optional[BoxedInteger]


class ServiceRegistry(TypedDict, total=False):
    registryArn: Optional[String]
    port: Optional[BoxedInteger]
    containerName: Optional[String]
    containerPort: Optional[BoxedInteger]


ServiceRegistries = List[ServiceRegistry]


class LoadBalancer(TypedDict, total=False):
    targetGroupArn: Optional[String]
    loadBalancerName: Optional[String]
    containerName: Optional[String]
    containerPort: Optional[BoxedInteger]


LoadBalancers = List[LoadBalancer]


class CreateServiceRequest(ServiceRequest):
    cluster: Optional[String]
    serviceName: String
    taskDefinition: Optional[String]
    loadBalancers: Optional[LoadBalancers]
    serviceRegistries: Optional[ServiceRegistries]
    desiredCount: Optional[BoxedInteger]
    clientToken: Optional[String]
    launchType: Optional[LaunchType]
    capacityProviderStrategy: Optional[CapacityProviderStrategy]
    platformVersion: Optional[String]
    role: Optional[String]
    deploymentConfiguration: Optional[DeploymentConfiguration]
    placementConstraints: Optional[PlacementConstraints]
    placementStrategy: Optional[PlacementStrategies]
    networkConfiguration: Optional[NetworkConfiguration]
    healthCheckGracePeriodSeconds: Optional[BoxedInteger]
    schedulingStrategy: Optional[SchedulingStrategy]
    deploymentController: Optional[DeploymentController]
    tags: Optional[Tags]
    enableECSManagedTags: Optional[Boolean]
    propagateTags: Optional[PropagateTags]
    enableExecuteCommand: Optional[Boolean]


class ServiceEvent(TypedDict, total=False):
    id: Optional[String]
    createdAt: Optional[Timestamp]
    message: Optional[String]


ServiceEvents = List[ServiceEvent]


class Deployment(TypedDict, total=False):
    id: Optional[String]
    status: Optional[String]
    taskDefinition: Optional[String]
    desiredCount: Optional[Integer]
    pendingCount: Optional[Integer]
    runningCount: Optional[Integer]
    failedTasks: Optional[Integer]
    createdAt: Optional[Timestamp]
    updatedAt: Optional[Timestamp]
    capacityProviderStrategy: Optional[CapacityProviderStrategy]
    launchType: Optional[LaunchType]
    platformVersion: Optional[String]
    platformFamily: Optional[String]
    networkConfiguration: Optional[NetworkConfiguration]
    rolloutState: Optional[DeploymentRolloutState]
    rolloutStateReason: Optional[String]


Deployments = List[Deployment]


class Scale(TypedDict, total=False):
    value: Optional[Double]
    unit: Optional[ScaleUnit]


class TaskSet(TypedDict, total=False):
    id: Optional[String]
    taskSetArn: Optional[String]
    serviceArn: Optional[String]
    clusterArn: Optional[String]
    startedBy: Optional[String]
    externalId: Optional[String]
    status: Optional[String]
    taskDefinition: Optional[String]
    computedDesiredCount: Optional[Integer]
    pendingCount: Optional[Integer]
    runningCount: Optional[Integer]
    createdAt: Optional[Timestamp]
    updatedAt: Optional[Timestamp]
    launchType: Optional[LaunchType]
    capacityProviderStrategy: Optional[CapacityProviderStrategy]
    platformVersion: Optional[String]
    platformFamily: Optional[String]
    networkConfiguration: Optional[NetworkConfiguration]
    loadBalancers: Optional[LoadBalancers]
    serviceRegistries: Optional[ServiceRegistries]
    scale: Optional[Scale]
    stabilityStatus: Optional[StabilityStatus]
    stabilityStatusAt: Optional[Timestamp]
    tags: Optional[Tags]


TaskSets = List[TaskSet]


class Service(TypedDict, total=False):
    serviceArn: Optional[String]
    serviceName: Optional[String]
    clusterArn: Optional[String]
    loadBalancers: Optional[LoadBalancers]
    serviceRegistries: Optional[ServiceRegistries]
    status: Optional[String]
    desiredCount: Optional[Integer]
    runningCount: Optional[Integer]
    pendingCount: Optional[Integer]
    launchType: Optional[LaunchType]
    capacityProviderStrategy: Optional[CapacityProviderStrategy]
    platformVersion: Optional[String]
    platformFamily: Optional[String]
    taskDefinition: Optional[String]
    deploymentConfiguration: Optional[DeploymentConfiguration]
    taskSets: Optional[TaskSets]
    deployments: Optional[Deployments]
    roleArn: Optional[String]
    events: Optional[ServiceEvents]
    createdAt: Optional[Timestamp]
    placementConstraints: Optional[PlacementConstraints]
    placementStrategy: Optional[PlacementStrategies]
    networkConfiguration: Optional[NetworkConfiguration]
    healthCheckGracePeriodSeconds: Optional[BoxedInteger]
    schedulingStrategy: Optional[SchedulingStrategy]
    deploymentController: Optional[DeploymentController]
    tags: Optional[Tags]
    createdBy: Optional[String]
    enableECSManagedTags: Optional[Boolean]
    propagateTags: Optional[PropagateTags]
    enableExecuteCommand: Optional[Boolean]


class CreateServiceResponse(TypedDict, total=False):
    service: Optional[Service]


class CreateTaskSetRequest(ServiceRequest):
    service: String
    cluster: String
    externalId: Optional[String]
    taskDefinition: String
    networkConfiguration: Optional[NetworkConfiguration]
    loadBalancers: Optional[LoadBalancers]
    serviceRegistries: Optional[ServiceRegistries]
    launchType: Optional[LaunchType]
    capacityProviderStrategy: Optional[CapacityProviderStrategy]
    platformVersion: Optional[String]
    scale: Optional[Scale]
    clientToken: Optional[String]
    tags: Optional[Tags]


class CreateTaskSetResponse(TypedDict, total=False):
    taskSet: Optional[TaskSet]


class DeleteAccountSettingRequest(ServiceRequest):
    name: SettingName
    principalArn: Optional[String]


class Setting(TypedDict, total=False):
    name: Optional[SettingName]
    value: Optional[String]
    principalArn: Optional[String]


class DeleteAccountSettingResponse(TypedDict, total=False):
    setting: Optional[Setting]


class DeleteAttributesRequest(ServiceRequest):
    cluster: Optional[String]
    attributes: Attributes


class DeleteAttributesResponse(TypedDict, total=False):
    attributes: Optional[Attributes]


class DeleteCapacityProviderRequest(ServiceRequest):
    capacityProvider: String


class DeleteCapacityProviderResponse(TypedDict, total=False):
    capacityProvider: Optional[CapacityProvider]


class DeleteClusterRequest(ServiceRequest):
    cluster: String


class DeleteClusterResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


class DeleteServiceRequest(ServiceRequest):
    cluster: Optional[String]
    service: String
    force: Optional[BoxedBoolean]


class DeleteServiceResponse(TypedDict, total=False):
    service: Optional[Service]


class DeleteTaskSetRequest(ServiceRequest):
    cluster: String
    service: String
    taskSet: String
    force: Optional[BoxedBoolean]


class DeleteTaskSetResponse(TypedDict, total=False):
    taskSet: Optional[TaskSet]


class DeregisterContainerInstanceRequest(ServiceRequest):
    cluster: Optional[String]
    containerInstance: String
    force: Optional[BoxedBoolean]


class DeregisterContainerInstanceResponse(TypedDict, total=False):
    containerInstance: Optional[ContainerInstance]


class DeregisterTaskDefinitionRequest(ServiceRequest):
    taskDefinition: String


class EphemeralStorage(TypedDict, total=False):
    sizeInGiB: Integer


ProxyConfigurationProperties = List[KeyValuePair]
ProxyConfiguration = TypedDict(
    "ProxyConfiguration",
    {
        "type": Optional[ProxyConfigurationType],
        "containerName": String,
        "properties": Optional[ProxyConfigurationProperties],
    },
    total=False,
)


class InferenceAccelerator(TypedDict, total=False):
    deviceName: String
    deviceType: String


InferenceAccelerators = List[InferenceAccelerator]


class RuntimePlatform(TypedDict, total=False):
    cpuArchitecture: Optional[CPUArchitecture]
    operatingSystemFamily: Optional[OSFamily]


TaskDefinitionPlacementConstraint = TypedDict(
    "TaskDefinitionPlacementConstraint",
    {
        "type": Optional[TaskDefinitionPlacementConstraintType],
        "expression": Optional[String],
    },
    total=False,
)
TaskDefinitionPlacementConstraints = List[TaskDefinitionPlacementConstraint]
RequiresAttributes = List[Attribute]


class FSxWindowsFileServerAuthorizationConfig(TypedDict, total=False):
    credentialsParameter: String
    domain: String


class FSxWindowsFileServerVolumeConfiguration(TypedDict, total=False):
    fileSystemId: String
    rootDirectory: String
    authorizationConfig: FSxWindowsFileServerAuthorizationConfig


class EFSAuthorizationConfig(TypedDict, total=False):
    accessPointId: Optional[String]
    iam: Optional[EFSAuthorizationConfigIAM]


class EFSVolumeConfiguration(TypedDict, total=False):
    fileSystemId: String
    rootDirectory: Optional[String]
    transitEncryption: Optional[EFSTransitEncryption]
    transitEncryptionPort: Optional[BoxedInteger]
    authorizationConfig: Optional[EFSAuthorizationConfig]


StringMap = Dict[String, String]


class DockerVolumeConfiguration(TypedDict, total=False):
    scope: Optional[Scope]
    autoprovision: Optional[BoxedBoolean]
    driver: Optional[String]
    driverOpts: Optional[StringMap]
    labels: Optional[StringMap]


class HostVolumeProperties(TypedDict, total=False):
    sourcePath: Optional[String]


class Volume(TypedDict, total=False):
    name: Optional[String]
    host: Optional[HostVolumeProperties]
    dockerVolumeConfiguration: Optional[DockerVolumeConfiguration]
    efsVolumeConfiguration: Optional[EFSVolumeConfiguration]
    fsxWindowsFileServerVolumeConfiguration: Optional[FSxWindowsFileServerVolumeConfiguration]


VolumeList = List[Volume]


class TaskDefinition(TypedDict, total=False):
    taskDefinitionArn: Optional[String]
    containerDefinitions: Optional[ContainerDefinitions]
    family: Optional[String]
    taskRoleArn: Optional[String]
    executionRoleArn: Optional[String]
    networkMode: Optional[NetworkMode]
    revision: Optional[Integer]
    volumes: Optional[VolumeList]
    status: Optional[TaskDefinitionStatus]
    requiresAttributes: Optional[RequiresAttributes]
    placementConstraints: Optional[TaskDefinitionPlacementConstraints]
    compatibilities: Optional[CompatibilityList]
    runtimePlatform: Optional[RuntimePlatform]
    requiresCompatibilities: Optional[CompatibilityList]
    cpu: Optional[String]
    memory: Optional[String]
    inferenceAccelerators: Optional[InferenceAccelerators]
    pidMode: Optional[PidMode]
    ipcMode: Optional[IpcMode]
    proxyConfiguration: Optional[ProxyConfiguration]
    registeredAt: Optional[Timestamp]
    deregisteredAt: Optional[Timestamp]
    registeredBy: Optional[String]
    ephemeralStorage: Optional[EphemeralStorage]


class DeregisterTaskDefinitionResponse(TypedDict, total=False):
    taskDefinition: Optional[TaskDefinition]


class DescribeCapacityProvidersRequest(ServiceRequest):
    capacityProviders: Optional[StringList]
    include: Optional[CapacityProviderFieldList]
    maxResults: Optional[BoxedInteger]
    nextToken: Optional[String]


class Failure(TypedDict, total=False):
    arn: Optional[String]
    reason: Optional[String]
    detail: Optional[String]


Failures = List[Failure]


class DescribeCapacityProvidersResponse(TypedDict, total=False):
    capacityProviders: Optional[CapacityProviders]
    failures: Optional[Failures]
    nextToken: Optional[String]


class DescribeClustersRequest(ServiceRequest):
    clusters: Optional[StringList]
    include: Optional[ClusterFieldList]


class DescribeClustersResponse(TypedDict, total=False):
    clusters: Optional[Clusters]
    failures: Optional[Failures]


class DescribeContainerInstancesRequest(ServiceRequest):
    cluster: Optional[String]
    containerInstances: StringList
    include: Optional[ContainerInstanceFieldList]


class DescribeContainerInstancesResponse(TypedDict, total=False):
    containerInstances: Optional[ContainerInstances]
    failures: Optional[Failures]


ServiceFieldList = List[ServiceField]


class DescribeServicesRequest(ServiceRequest):
    cluster: Optional[String]
    services: StringList
    include: Optional[ServiceFieldList]


Services = List[Service]


class DescribeServicesResponse(TypedDict, total=False):
    services: Optional[Services]
    failures: Optional[Failures]


TaskDefinitionFieldList = List[TaskDefinitionField]


class DescribeTaskDefinitionRequest(ServiceRequest):
    taskDefinition: String
    include: Optional[TaskDefinitionFieldList]


class DescribeTaskDefinitionResponse(TypedDict, total=False):
    taskDefinition: Optional[TaskDefinition]
    tags: Optional[Tags]


TaskSetFieldList = List[TaskSetField]


class DescribeTaskSetsRequest(ServiceRequest):
    cluster: String
    service: String
    taskSets: Optional[StringList]
    include: Optional[TaskSetFieldList]


class DescribeTaskSetsResponse(TypedDict, total=False):
    taskSets: Optional[TaskSets]
    failures: Optional[Failures]


TaskFieldList = List[TaskField]


class DescribeTasksRequest(ServiceRequest):
    cluster: Optional[String]
    tasks: StringList
    include: Optional[TaskFieldList]


class InferenceAcceleratorOverride(TypedDict, total=False):
    deviceName: Optional[String]
    deviceType: Optional[String]


InferenceAcceleratorOverrides = List[InferenceAcceleratorOverride]


class TaskOverride(TypedDict, total=False):
    containerOverrides: Optional[ContainerOverrides]
    cpu: Optional[String]
    inferenceAcceleratorOverrides: Optional[InferenceAcceleratorOverrides]
    executionRoleArn: Optional[String]
    memory: Optional[String]
    taskRoleArn: Optional[String]
    ephemeralStorage: Optional[EphemeralStorage]


class Task(TypedDict, total=False):
    attachments: Optional[Attachments]
    attributes: Optional[Attributes]
    availabilityZone: Optional[String]
    capacityProviderName: Optional[String]
    clusterArn: Optional[String]
    connectivity: Optional[Connectivity]
    connectivityAt: Optional[Timestamp]
    containerInstanceArn: Optional[String]
    containers: Optional[Containers]
    cpu: Optional[String]
    createdAt: Optional[Timestamp]
    desiredStatus: Optional[String]
    enableExecuteCommand: Optional[Boolean]
    executionStoppedAt: Optional[Timestamp]
    group: Optional[String]
    healthStatus: Optional[HealthStatus]
    inferenceAccelerators: Optional[InferenceAccelerators]
    lastStatus: Optional[String]
    launchType: Optional[LaunchType]
    memory: Optional[String]
    overrides: Optional[TaskOverride]
    platformVersion: Optional[String]
    platformFamily: Optional[String]
    pullStartedAt: Optional[Timestamp]
    pullStoppedAt: Optional[Timestamp]
    startedAt: Optional[Timestamp]
    startedBy: Optional[String]
    stopCode: Optional[TaskStopCode]
    stoppedAt: Optional[Timestamp]
    stoppedReason: Optional[String]
    stoppingAt: Optional[Timestamp]
    tags: Optional[Tags]
    taskArn: Optional[String]
    taskDefinitionArn: Optional[String]
    version: Optional[Long]
    ephemeralStorage: Optional[EphemeralStorage]


Tasks = List[Task]


class DescribeTasksResponse(TypedDict, total=False):
    tasks: Optional[Tasks]
    failures: Optional[Failures]


class DiscoverPollEndpointRequest(ServiceRequest):
    containerInstance: Optional[String]
    cluster: Optional[String]


class DiscoverPollEndpointResponse(TypedDict, total=False):
    endpoint: Optional[String]
    telemetryEndpoint: Optional[String]


class ExecuteCommandRequest(ServiceRequest):
    cluster: Optional[String]
    container: Optional[String]
    command: String
    interactive: Boolean
    task: String


class Session(TypedDict, total=False):
    sessionId: Optional[String]
    streamUrl: Optional[String]
    tokenValue: Optional[SensitiveString]


class ExecuteCommandResponse(TypedDict, total=False):
    clusterArn: Optional[String]
    containerArn: Optional[String]
    containerName: Optional[String]
    interactive: Optional[Boolean]
    session: Optional[Session]
    taskArn: Optional[String]


class ListAccountSettingsRequest(ServiceRequest):
    name: Optional[SettingName]
    value: Optional[String]
    principalArn: Optional[String]
    effectiveSettings: Optional[Boolean]
    nextToken: Optional[String]
    maxResults: Optional[Integer]


Settings = List[Setting]


class ListAccountSettingsResponse(TypedDict, total=False):
    settings: Optional[Settings]
    nextToken: Optional[String]


class ListAttributesRequest(ServiceRequest):
    cluster: Optional[String]
    targetType: TargetType
    attributeName: Optional[String]
    attributeValue: Optional[String]
    nextToken: Optional[String]
    maxResults: Optional[BoxedInteger]


class ListAttributesResponse(TypedDict, total=False):
    attributes: Optional[Attributes]
    nextToken: Optional[String]


class ListClustersRequest(ServiceRequest):
    nextToken: Optional[String]
    maxResults: Optional[BoxedInteger]


class ListClustersResponse(TypedDict, total=False):
    clusterArns: Optional[StringList]
    nextToken: Optional[String]


class ListContainerInstancesRequest(ServiceRequest):
    cluster: Optional[String]
    filter: Optional[String]
    nextToken: Optional[String]
    maxResults: Optional[BoxedInteger]
    status: Optional[ContainerInstanceStatus]


class ListContainerInstancesResponse(TypedDict, total=False):
    containerInstanceArns: Optional[StringList]
    nextToken: Optional[String]


class ListServicesRequest(ServiceRequest):
    cluster: Optional[String]
    nextToken: Optional[String]
    maxResults: Optional[BoxedInteger]
    launchType: Optional[LaunchType]
    schedulingStrategy: Optional[SchedulingStrategy]


class ListServicesResponse(TypedDict, total=False):
    serviceArns: Optional[StringList]
    nextToken: Optional[String]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: String


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[Tags]


class ListTaskDefinitionFamiliesRequest(ServiceRequest):
    familyPrefix: Optional[String]
    status: Optional[TaskDefinitionFamilyStatus]
    nextToken: Optional[String]
    maxResults: Optional[BoxedInteger]


class ListTaskDefinitionFamiliesResponse(TypedDict, total=False):
    families: Optional[StringList]
    nextToken: Optional[String]


class ListTaskDefinitionsRequest(ServiceRequest):
    familyPrefix: Optional[String]
    status: Optional[TaskDefinitionStatus]
    sort: Optional[SortOrder]
    nextToken: Optional[String]
    maxResults: Optional[BoxedInteger]


class ListTaskDefinitionsResponse(TypedDict, total=False):
    taskDefinitionArns: Optional[StringList]
    nextToken: Optional[String]


class ListTasksRequest(ServiceRequest):
    cluster: Optional[String]
    containerInstance: Optional[String]
    family: Optional[String]
    nextToken: Optional[String]
    maxResults: Optional[BoxedInteger]
    startedBy: Optional[String]
    serviceName: Optional[String]
    desiredStatus: Optional[DesiredStatus]
    launchType: Optional[LaunchType]


class ListTasksResponse(TypedDict, total=False):
    taskArns: Optional[StringList]
    nextToken: Optional[String]


class ManagedAgentStateChange(TypedDict, total=False):
    containerName: String
    managedAgentName: ManagedAgentName
    status: String
    reason: Optional[String]


ManagedAgentStateChanges = List[ManagedAgentStateChange]
PlatformDevice = TypedDict(
    "PlatformDevice",
    {
        "id": String,
        "type": PlatformDeviceType,
    },
    total=False,
)
PlatformDevices = List[PlatformDevice]


class PutAccountSettingDefaultRequest(ServiceRequest):
    name: SettingName
    value: String


class PutAccountSettingDefaultResponse(TypedDict, total=False):
    setting: Optional[Setting]


class PutAccountSettingRequest(ServiceRequest):
    name: SettingName
    value: String
    principalArn: Optional[String]


class PutAccountSettingResponse(TypedDict, total=False):
    setting: Optional[Setting]


class PutAttributesRequest(ServiceRequest):
    cluster: Optional[String]
    attributes: Attributes


class PutAttributesResponse(TypedDict, total=False):
    attributes: Optional[Attributes]


class PutClusterCapacityProvidersRequest(ServiceRequest):
    cluster: String
    capacityProviders: StringList
    defaultCapacityProviderStrategy: CapacityProviderStrategy


class PutClusterCapacityProvidersResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


class RegisterContainerInstanceRequest(ServiceRequest):
    cluster: Optional[String]
    instanceIdentityDocument: Optional[String]
    instanceIdentityDocumentSignature: Optional[String]
    totalResources: Optional[Resources]
    versionInfo: Optional[VersionInfo]
    containerInstanceArn: Optional[String]
    attributes: Optional[Attributes]
    platformDevices: Optional[PlatformDevices]
    tags: Optional[Tags]


class RegisterContainerInstanceResponse(TypedDict, total=False):
    containerInstance: Optional[ContainerInstance]


class RegisterTaskDefinitionRequest(ServiceRequest):
    family: String
    taskRoleArn: Optional[String]
    executionRoleArn: Optional[String]
    networkMode: Optional[NetworkMode]
    containerDefinitions: ContainerDefinitions
    volumes: Optional[VolumeList]
    placementConstraints: Optional[TaskDefinitionPlacementConstraints]
    requiresCompatibilities: Optional[CompatibilityList]
    cpu: Optional[String]
    memory: Optional[String]
    tags: Optional[Tags]
    pidMode: Optional[PidMode]
    ipcMode: Optional[IpcMode]
    proxyConfiguration: Optional[ProxyConfiguration]
    inferenceAccelerators: Optional[InferenceAccelerators]
    ephemeralStorage: Optional[EphemeralStorage]
    runtimePlatform: Optional[RuntimePlatform]


class RegisterTaskDefinitionResponse(TypedDict, total=False):
    taskDefinition: Optional[TaskDefinition]
    tags: Optional[Tags]


class RunTaskRequest(ServiceRequest):
    capacityProviderStrategy: Optional[CapacityProviderStrategy]
    cluster: Optional[String]
    count: Optional[BoxedInteger]
    enableECSManagedTags: Optional[Boolean]
    enableExecuteCommand: Optional[Boolean]
    group: Optional[String]
    launchType: Optional[LaunchType]
    networkConfiguration: Optional[NetworkConfiguration]
    overrides: Optional[TaskOverride]
    placementConstraints: Optional[PlacementConstraints]
    placementStrategy: Optional[PlacementStrategies]
    platformVersion: Optional[String]
    propagateTags: Optional[PropagateTags]
    referenceId: Optional[String]
    startedBy: Optional[String]
    tags: Optional[Tags]
    taskDefinition: String


class RunTaskResponse(TypedDict, total=False):
    tasks: Optional[Tasks]
    failures: Optional[Failures]


class StartTaskRequest(ServiceRequest):
    cluster: Optional[String]
    containerInstances: StringList
    enableECSManagedTags: Optional[Boolean]
    enableExecuteCommand: Optional[Boolean]
    group: Optional[String]
    networkConfiguration: Optional[NetworkConfiguration]
    overrides: Optional[TaskOverride]
    propagateTags: Optional[PropagateTags]
    referenceId: Optional[String]
    startedBy: Optional[String]
    tags: Optional[Tags]
    taskDefinition: String


class StartTaskResponse(TypedDict, total=False):
    tasks: Optional[Tasks]
    failures: Optional[Failures]


class StopTaskRequest(ServiceRequest):
    cluster: Optional[String]
    task: String
    reason: Optional[String]


class StopTaskResponse(TypedDict, total=False):
    task: Optional[Task]


class SubmitAttachmentStateChangesRequest(ServiceRequest):
    cluster: Optional[String]
    attachments: AttachmentStateChanges


class SubmitAttachmentStateChangesResponse(TypedDict, total=False):
    acknowledgment: Optional[String]


class SubmitContainerStateChangeRequest(ServiceRequest):
    cluster: Optional[String]
    task: Optional[String]
    containerName: Optional[String]
    runtimeId: Optional[String]
    status: Optional[String]
    exitCode: Optional[BoxedInteger]
    reason: Optional[String]
    networkBindings: Optional[NetworkBindings]


class SubmitContainerStateChangeResponse(TypedDict, total=False):
    acknowledgment: Optional[String]


class SubmitTaskStateChangeRequest(ServiceRequest):
    cluster: Optional[String]
    task: Optional[String]
    status: Optional[String]
    reason: Optional[String]
    containers: Optional[ContainerStateChanges]
    attachments: Optional[AttachmentStateChanges]
    managedAgents: Optional[ManagedAgentStateChanges]
    pullStartedAt: Optional[Timestamp]
    pullStoppedAt: Optional[Timestamp]
    executionStoppedAt: Optional[Timestamp]


class SubmitTaskStateChangeResponse(TypedDict, total=False):
    acknowledgment: Optional[String]


TagKeys = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: String
    tags: Tags


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: String
    tagKeys: TagKeys


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateCapacityProviderRequest(ServiceRequest):
    name: String
    autoScalingGroupProvider: AutoScalingGroupProviderUpdate


class UpdateCapacityProviderResponse(TypedDict, total=False):
    capacityProvider: Optional[CapacityProvider]


class UpdateClusterRequest(ServiceRequest):
    cluster: String
    settings: Optional[ClusterSettings]
    configuration: Optional[ClusterConfiguration]


class UpdateClusterResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


class UpdateClusterSettingsRequest(ServiceRequest):
    cluster: String
    settings: ClusterSettings


class UpdateClusterSettingsResponse(TypedDict, total=False):
    cluster: Optional[Cluster]


class UpdateContainerAgentRequest(ServiceRequest):
    cluster: Optional[String]
    containerInstance: String


class UpdateContainerAgentResponse(TypedDict, total=False):
    containerInstance: Optional[ContainerInstance]


class UpdateContainerInstancesStateRequest(ServiceRequest):
    cluster: Optional[String]
    containerInstances: StringList
    status: ContainerInstanceStatus


class UpdateContainerInstancesStateResponse(TypedDict, total=False):
    containerInstances: Optional[ContainerInstances]
    failures: Optional[Failures]


class UpdateServicePrimaryTaskSetRequest(ServiceRequest):
    cluster: String
    service: String
    primaryTaskSet: String


class UpdateServicePrimaryTaskSetResponse(TypedDict, total=False):
    taskSet: Optional[TaskSet]


class UpdateServiceRequest(ServiceRequest):
    cluster: Optional[String]
    service: String
    desiredCount: Optional[BoxedInteger]
    taskDefinition: Optional[String]
    capacityProviderStrategy: Optional[CapacityProviderStrategy]
    deploymentConfiguration: Optional[DeploymentConfiguration]
    networkConfiguration: Optional[NetworkConfiguration]
    placementConstraints: Optional[PlacementConstraints]
    placementStrategy: Optional[PlacementStrategies]
    platformVersion: Optional[String]
    forceNewDeployment: Optional[Boolean]
    healthCheckGracePeriodSeconds: Optional[BoxedInteger]
    enableExecuteCommand: Optional[BoxedBoolean]


class UpdateServiceResponse(TypedDict, total=False):
    service: Optional[Service]


class UpdateTaskSetRequest(ServiceRequest):
    cluster: String
    service: String
    taskSet: String
    scale: Scale


class UpdateTaskSetResponse(TypedDict, total=False):
    taskSet: Optional[TaskSet]


class EcsApi:

    service = "ecs"
    version = "2014-11-13"

    @handler("CreateCapacityProvider")
    def create_capacity_provider(
        self,
        context: RequestContext,
        name: String,
        auto_scaling_group_provider: AutoScalingGroupProvider,
        tags: Tags = None,
    ) -> CreateCapacityProviderResponse:
        raise NotImplementedError

    @handler("CreateCluster")
    def create_cluster(
        self,
        context: RequestContext,
        cluster_name: String = None,
        tags: Tags = None,
        settings: ClusterSettings = None,
        configuration: ClusterConfiguration = None,
        capacity_providers: StringList = None,
        default_capacity_provider_strategy: CapacityProviderStrategy = None,
    ) -> CreateClusterResponse:
        raise NotImplementedError

    @handler("CreateService")
    def create_service(
        self,
        context: RequestContext,
        service_name: String,
        cluster: String = None,
        task_definition: String = None,
        load_balancers: LoadBalancers = None,
        service_registries: ServiceRegistries = None,
        desired_count: BoxedInteger = None,
        client_token: String = None,
        launch_type: LaunchType = None,
        capacity_provider_strategy: CapacityProviderStrategy = None,
        platform_version: String = None,
        role: String = None,
        deployment_configuration: DeploymentConfiguration = None,
        placement_constraints: PlacementConstraints = None,
        placement_strategy: PlacementStrategies = None,
        network_configuration: NetworkConfiguration = None,
        health_check_grace_period_seconds: BoxedInteger = None,
        scheduling_strategy: SchedulingStrategy = None,
        deployment_controller: DeploymentController = None,
        tags: Tags = None,
        enable_ecs_managed_tags: Boolean = None,
        propagate_tags: PropagateTags = None,
        enable_execute_command: Boolean = None,
    ) -> CreateServiceResponse:
        raise NotImplementedError

    @handler("CreateTaskSet")
    def create_task_set(
        self,
        context: RequestContext,
        service: String,
        cluster: String,
        task_definition: String,
        external_id: String = None,
        network_configuration: NetworkConfiguration = None,
        load_balancers: LoadBalancers = None,
        service_registries: ServiceRegistries = None,
        launch_type: LaunchType = None,
        capacity_provider_strategy: CapacityProviderStrategy = None,
        platform_version: String = None,
        scale: Scale = None,
        client_token: String = None,
        tags: Tags = None,
    ) -> CreateTaskSetResponse:
        raise NotImplementedError

    @handler("DeleteAccountSetting")
    def delete_account_setting(
        self, context: RequestContext, name: SettingName, principal_arn: String = None
    ) -> DeleteAccountSettingResponse:
        raise NotImplementedError

    @handler("DeleteAttributes")
    def delete_attributes(
        self, context: RequestContext, attributes: Attributes, cluster: String = None
    ) -> DeleteAttributesResponse:
        raise NotImplementedError

    @handler("DeleteCapacityProvider")
    def delete_capacity_provider(
        self, context: RequestContext, capacity_provider: String
    ) -> DeleteCapacityProviderResponse:
        raise NotImplementedError

    @handler("DeleteCluster")
    def delete_cluster(self, context: RequestContext, cluster: String) -> DeleteClusterResponse:
        raise NotImplementedError

    @handler("DeleteService")
    def delete_service(
        self,
        context: RequestContext,
        service: String,
        cluster: String = None,
        force: BoxedBoolean = None,
    ) -> DeleteServiceResponse:
        raise NotImplementedError

    @handler("DeleteTaskSet")
    def delete_task_set(
        self,
        context: RequestContext,
        cluster: String,
        service: String,
        task_set: String,
        force: BoxedBoolean = None,
    ) -> DeleteTaskSetResponse:
        raise NotImplementedError

    @handler("DeregisterContainerInstance")
    def deregister_container_instance(
        self,
        context: RequestContext,
        container_instance: String,
        cluster: String = None,
        force: BoxedBoolean = None,
    ) -> DeregisterContainerInstanceResponse:
        raise NotImplementedError

    @handler("DeregisterTaskDefinition")
    def deregister_task_definition(
        self, context: RequestContext, task_definition: String
    ) -> DeregisterTaskDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeCapacityProviders")
    def describe_capacity_providers(
        self,
        context: RequestContext,
        capacity_providers: StringList = None,
        include: CapacityProviderFieldList = None,
        max_results: BoxedInteger = None,
        next_token: String = None,
    ) -> DescribeCapacityProvidersResponse:
        raise NotImplementedError

    @handler("DescribeClusters")
    def describe_clusters(
        self, context: RequestContext, clusters: StringList = None, include: ClusterFieldList = None
    ) -> DescribeClustersResponse:
        raise NotImplementedError

    @handler("DescribeContainerInstances")
    def describe_container_instances(
        self,
        context: RequestContext,
        container_instances: StringList,
        cluster: String = None,
        include: ContainerInstanceFieldList = None,
    ) -> DescribeContainerInstancesResponse:
        raise NotImplementedError

    @handler("DescribeServices")
    def describe_services(
        self,
        context: RequestContext,
        services: StringList,
        cluster: String = None,
        include: ServiceFieldList = None,
    ) -> DescribeServicesResponse:
        raise NotImplementedError

    @handler("DescribeTaskDefinition")
    def describe_task_definition(
        self,
        context: RequestContext,
        task_definition: String,
        include: TaskDefinitionFieldList = None,
    ) -> DescribeTaskDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeTaskSets")
    def describe_task_sets(
        self,
        context: RequestContext,
        cluster: String,
        service: String,
        task_sets: StringList = None,
        include: TaskSetFieldList = None,
    ) -> DescribeTaskSetsResponse:
        raise NotImplementedError

    @handler("DescribeTasks")
    def describe_tasks(
        self,
        context: RequestContext,
        tasks: StringList,
        cluster: String = None,
        include: TaskFieldList = None,
    ) -> DescribeTasksResponse:
        raise NotImplementedError

    @handler("DiscoverPollEndpoint")
    def discover_poll_endpoint(
        self, context: RequestContext, container_instance: String = None, cluster: String = None
    ) -> DiscoverPollEndpointResponse:
        raise NotImplementedError

    @handler("ExecuteCommand")
    def execute_command(
        self,
        context: RequestContext,
        command: String,
        interactive: Boolean,
        task: String,
        cluster: String = None,
        container: String = None,
    ) -> ExecuteCommandResponse:
        raise NotImplementedError

    @handler("ListAccountSettings")
    def list_account_settings(
        self,
        context: RequestContext,
        name: SettingName = None,
        value: String = None,
        principal_arn: String = None,
        effective_settings: Boolean = None,
        next_token: String = None,
        max_results: Integer = None,
    ) -> ListAccountSettingsResponse:
        raise NotImplementedError

    @handler("ListAttributes")
    def list_attributes(
        self,
        context: RequestContext,
        target_type: TargetType,
        cluster: String = None,
        attribute_name: String = None,
        attribute_value: String = None,
        next_token: String = None,
        max_results: BoxedInteger = None,
    ) -> ListAttributesResponse:
        raise NotImplementedError

    @handler("ListClusters")
    def list_clusters(
        self, context: RequestContext, next_token: String = None, max_results: BoxedInteger = None
    ) -> ListClustersResponse:
        raise NotImplementedError

    @handler("ListContainerInstances")
    def list_container_instances(
        self,
        context: RequestContext,
        cluster: String = None,
        filter: String = None,
        next_token: String = None,
        max_results: BoxedInteger = None,
        status: ContainerInstanceStatus = None,
    ) -> ListContainerInstancesResponse:
        raise NotImplementedError

    @handler("ListServices")
    def list_services(
        self,
        context: RequestContext,
        cluster: String = None,
        next_token: String = None,
        max_results: BoxedInteger = None,
        launch_type: LaunchType = None,
        scheduling_strategy: SchedulingStrategy = None,
    ) -> ListServicesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: String
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTaskDefinitionFamilies")
    def list_task_definition_families(
        self,
        context: RequestContext,
        family_prefix: String = None,
        status: TaskDefinitionFamilyStatus = None,
        next_token: String = None,
        max_results: BoxedInteger = None,
    ) -> ListTaskDefinitionFamiliesResponse:
        raise NotImplementedError

    @handler("ListTaskDefinitions")
    def list_task_definitions(
        self,
        context: RequestContext,
        family_prefix: String = None,
        status: TaskDefinitionStatus = None,
        sort: SortOrder = None,
        next_token: String = None,
        max_results: BoxedInteger = None,
    ) -> ListTaskDefinitionsResponse:
        raise NotImplementedError

    @handler("ListTasks")
    def list_tasks(
        self,
        context: RequestContext,
        cluster: String = None,
        container_instance: String = None,
        family: String = None,
        next_token: String = None,
        max_results: BoxedInteger = None,
        started_by: String = None,
        service_name: String = None,
        desired_status: DesiredStatus = None,
        launch_type: LaunchType = None,
    ) -> ListTasksResponse:
        raise NotImplementedError

    @handler("PutAccountSetting")
    def put_account_setting(
        self,
        context: RequestContext,
        name: SettingName,
        value: String,
        principal_arn: String = None,
    ) -> PutAccountSettingResponse:
        raise NotImplementedError

    @handler("PutAccountSettingDefault")
    def put_account_setting_default(
        self, context: RequestContext, name: SettingName, value: String
    ) -> PutAccountSettingDefaultResponse:
        raise NotImplementedError

    @handler("PutAttributes")
    def put_attributes(
        self, context: RequestContext, attributes: Attributes, cluster: String = None
    ) -> PutAttributesResponse:
        raise NotImplementedError

    @handler("PutClusterCapacityProviders")
    def put_cluster_capacity_providers(
        self,
        context: RequestContext,
        cluster: String,
        capacity_providers: StringList,
        default_capacity_provider_strategy: CapacityProviderStrategy,
    ) -> PutClusterCapacityProvidersResponse:
        raise NotImplementedError

    @handler("RegisterContainerInstance")
    def register_container_instance(
        self,
        context: RequestContext,
        cluster: String = None,
        instance_identity_document: String = None,
        instance_identity_document_signature: String = None,
        total_resources: Resources = None,
        version_info: VersionInfo = None,
        container_instance_arn: String = None,
        attributes: Attributes = None,
        platform_devices: PlatformDevices = None,
        tags: Tags = None,
    ) -> RegisterContainerInstanceResponse:
        raise NotImplementedError

    @handler("RegisterTaskDefinition")
    def register_task_definition(
        self,
        context: RequestContext,
        family: String,
        container_definitions: ContainerDefinitions,
        task_role_arn: String = None,
        execution_role_arn: String = None,
        network_mode: NetworkMode = None,
        volumes: VolumeList = None,
        placement_constraints: TaskDefinitionPlacementConstraints = None,
        requires_compatibilities: CompatibilityList = None,
        cpu: String = None,
        memory: String = None,
        tags: Tags = None,
        pid_mode: PidMode = None,
        ipc_mode: IpcMode = None,
        proxy_configuration: ProxyConfiguration = None,
        inference_accelerators: InferenceAccelerators = None,
        ephemeral_storage: EphemeralStorage = None,
        runtime_platform: RuntimePlatform = None,
    ) -> RegisterTaskDefinitionResponse:
        raise NotImplementedError

    @handler("RunTask")
    def run_task(
        self,
        context: RequestContext,
        task_definition: String,
        capacity_provider_strategy: CapacityProviderStrategy = None,
        cluster: String = None,
        count: BoxedInteger = None,
        enable_ecs_managed_tags: Boolean = None,
        enable_execute_command: Boolean = None,
        group: String = None,
        launch_type: LaunchType = None,
        network_configuration: NetworkConfiguration = None,
        overrides: TaskOverride = None,
        placement_constraints: PlacementConstraints = None,
        placement_strategy: PlacementStrategies = None,
        platform_version: String = None,
        propagate_tags: PropagateTags = None,
        reference_id: String = None,
        started_by: String = None,
        tags: Tags = None,
    ) -> RunTaskResponse:
        raise NotImplementedError

    @handler("StartTask")
    def start_task(
        self,
        context: RequestContext,
        container_instances: StringList,
        task_definition: String,
        cluster: String = None,
        enable_ecs_managed_tags: Boolean = None,
        enable_execute_command: Boolean = None,
        group: String = None,
        network_configuration: NetworkConfiguration = None,
        overrides: TaskOverride = None,
        propagate_tags: PropagateTags = None,
        reference_id: String = None,
        started_by: String = None,
        tags: Tags = None,
    ) -> StartTaskResponse:
        raise NotImplementedError

    @handler("StopTask")
    def stop_task(
        self, context: RequestContext, task: String, cluster: String = None, reason: String = None
    ) -> StopTaskResponse:
        raise NotImplementedError

    @handler("SubmitAttachmentStateChanges")
    def submit_attachment_state_changes(
        self, context: RequestContext, attachments: AttachmentStateChanges, cluster: String = None
    ) -> SubmitAttachmentStateChangesResponse:
        raise NotImplementedError

    @handler("SubmitContainerStateChange")
    def submit_container_state_change(
        self,
        context: RequestContext,
        cluster: String = None,
        task: String = None,
        container_name: String = None,
        runtime_id: String = None,
        status: String = None,
        exit_code: BoxedInteger = None,
        reason: String = None,
        network_bindings: NetworkBindings = None,
    ) -> SubmitContainerStateChangeResponse:
        raise NotImplementedError

    @handler("SubmitTaskStateChange")
    def submit_task_state_change(
        self,
        context: RequestContext,
        cluster: String = None,
        task: String = None,
        status: String = None,
        reason: String = None,
        containers: ContainerStateChanges = None,
        attachments: AttachmentStateChanges = None,
        managed_agents: ManagedAgentStateChanges = None,
        pull_started_at: Timestamp = None,
        pull_stopped_at: Timestamp = None,
        execution_stopped_at: Timestamp = None,
    ) -> SubmitTaskStateChangeResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: String, tags: Tags
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: String, tag_keys: TagKeys
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateCapacityProvider")
    def update_capacity_provider(
        self,
        context: RequestContext,
        name: String,
        auto_scaling_group_provider: AutoScalingGroupProviderUpdate,
    ) -> UpdateCapacityProviderResponse:
        raise NotImplementedError

    @handler("UpdateCluster")
    def update_cluster(
        self,
        context: RequestContext,
        cluster: String,
        settings: ClusterSettings = None,
        configuration: ClusterConfiguration = None,
    ) -> UpdateClusterResponse:
        raise NotImplementedError

    @handler("UpdateClusterSettings")
    def update_cluster_settings(
        self, context: RequestContext, cluster: String, settings: ClusterSettings
    ) -> UpdateClusterSettingsResponse:
        raise NotImplementedError

    @handler("UpdateContainerAgent")
    def update_container_agent(
        self, context: RequestContext, container_instance: String, cluster: String = None
    ) -> UpdateContainerAgentResponse:
        raise NotImplementedError

    @handler("UpdateContainerInstancesState")
    def update_container_instances_state(
        self,
        context: RequestContext,
        container_instances: StringList,
        status: ContainerInstanceStatus,
        cluster: String = None,
    ) -> UpdateContainerInstancesStateResponse:
        raise NotImplementedError

    @handler("UpdateService")
    def update_service(
        self,
        context: RequestContext,
        service: String,
        cluster: String = None,
        desired_count: BoxedInteger = None,
        task_definition: String = None,
        capacity_provider_strategy: CapacityProviderStrategy = None,
        deployment_configuration: DeploymentConfiguration = None,
        network_configuration: NetworkConfiguration = None,
        placement_constraints: PlacementConstraints = None,
        placement_strategy: PlacementStrategies = None,
        platform_version: String = None,
        force_new_deployment: Boolean = None,
        health_check_grace_period_seconds: BoxedInteger = None,
        enable_execute_command: BoxedBoolean = None,
    ) -> UpdateServiceResponse:
        raise NotImplementedError

    @handler("UpdateServicePrimaryTaskSet")
    def update_service_primary_task_set(
        self, context: RequestContext, cluster: String, service: String, primary_task_set: String
    ) -> UpdateServicePrimaryTaskSetResponse:
        raise NotImplementedError

    @handler("UpdateTaskSet")
    def update_task_set(
        self,
        context: RequestContext,
        cluster: String,
        service: String,
        task_set: String,
        scale: Scale,
    ) -> UpdateTaskSetResponse:
        raise NotImplementedError
