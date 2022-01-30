import sys
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
Float = float
ImageIdOverride = str
ImageType = str
Integer = int
String = str
TagKey = str
TagValue = str


class ArrayJobDependency(str):
    N_TO_N = "N_TO_N"
    SEQUENTIAL = "SEQUENTIAL"


class AssignPublicIp(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class CEState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class CEStatus(str):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    DELETED = "DELETED"
    VALID = "VALID"
    INVALID = "INVALID"


class CEType(str):
    MANAGED = "MANAGED"
    UNMANAGED = "UNMANAGED"


class CRAllocationStrategy(str):
    BEST_FIT = "BEST_FIT"
    BEST_FIT_PROGRESSIVE = "BEST_FIT_PROGRESSIVE"
    SPOT_CAPACITY_OPTIMIZED = "SPOT_CAPACITY_OPTIMIZED"


class CRType(str):
    EC2 = "EC2"
    SPOT = "SPOT"
    FARGATE = "FARGATE"
    FARGATE_SPOT = "FARGATE_SPOT"


class DeviceCgroupPermission(str):
    READ = "READ"
    WRITE = "WRITE"
    MKNOD = "MKNOD"


class EFSAuthorizationConfigIAM(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class EFSTransitEncryption(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class JQState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class JQStatus(str):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    DELETED = "DELETED"
    VALID = "VALID"
    INVALID = "INVALID"


class JobDefinitionType(str):
    container = "container"
    multinode = "multinode"


class JobStatus(str):
    SUBMITTED = "SUBMITTED"
    PENDING = "PENDING"
    RUNNABLE = "RUNNABLE"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class LogDriver(str):
    json_file = "json-file"
    syslog = "syslog"
    journald = "journald"
    gelf = "gelf"
    fluentd = "fluentd"
    awslogs = "awslogs"
    splunk = "splunk"


class PlatformCapability(str):
    EC2 = "EC2"
    FARGATE = "FARGATE"


class ResourceType(str):
    GPU = "GPU"
    VCPU = "VCPU"
    MEMORY = "MEMORY"


class RetryAction(str):
    RETRY = "RETRY"
    EXIT = "EXIT"


class ClientException(ServiceException):
    message: Optional[String]


class ServerException(ServiceException):
    message: Optional[String]


ArrayJobStatusSummary = Dict[String, Integer]


class ArrayProperties(TypedDict, total=False):
    size: Optional[Integer]


class ArrayPropertiesDetail(TypedDict, total=False):
    statusSummary: Optional[ArrayJobStatusSummary]
    size: Optional[Integer]
    index: Optional[Integer]


class ArrayPropertiesSummary(TypedDict, total=False):
    size: Optional[Integer]
    index: Optional[Integer]


class NetworkInterface(TypedDict, total=False):
    attachmentId: Optional[String]
    ipv6Address: Optional[String]
    privateIpv4Address: Optional[String]


NetworkInterfaceList = List[NetworkInterface]


class AttemptContainerDetail(TypedDict, total=False):
    containerInstanceArn: Optional[String]
    taskArn: Optional[String]
    exitCode: Optional[Integer]
    reason: Optional[String]
    logStreamName: Optional[String]
    networkInterfaces: Optional[NetworkInterfaceList]


Long = int


class AttemptDetail(TypedDict, total=False):
    container: Optional[AttemptContainerDetail]
    startedAt: Optional[Long]
    stoppedAt: Optional[Long]
    statusReason: Optional[String]


AttemptDetails = List[AttemptDetail]


class CancelJobRequest(ServiceRequest):
    jobId: String
    reason: String


class CancelJobResponse(TypedDict, total=False):
    pass


class Ec2Configuration(TypedDict, total=False):
    imageType: ImageType
    imageIdOverride: Optional[ImageIdOverride]


Ec2ConfigurationList = List[Ec2Configuration]


class LaunchTemplateSpecification(TypedDict, total=False):
    launchTemplateId: Optional[String]
    launchTemplateName: Optional[String]
    version: Optional[String]


TagsMap = Dict[String, String]
StringList = List[String]
ComputeResource = TypedDict(
    "ComputeResource",
    {
        "type": CRType,
        "allocationStrategy": Optional[CRAllocationStrategy],
        "minvCpus": Optional[Integer],
        "maxvCpus": Integer,
        "desiredvCpus": Optional[Integer],
        "instanceTypes": Optional[StringList],
        "imageId": Optional[String],
        "subnets": StringList,
        "securityGroupIds": Optional[StringList],
        "ec2KeyPair": Optional[String],
        "instanceRole": Optional[String],
        "tags": Optional[TagsMap],
        "placementGroup": Optional[String],
        "bidPercentage": Optional[Integer],
        "spotIamFleetRole": Optional[String],
        "launchTemplate": Optional[LaunchTemplateSpecification],
        "ec2Configuration": Optional[Ec2ConfigurationList],
    },
    total=False,
)
TagrisTagsMap = Dict[TagKey, TagValue]
ComputeEnvironmentDetail = TypedDict(
    "ComputeEnvironmentDetail",
    {
        "computeEnvironmentName": String,
        "computeEnvironmentArn": String,
        "unmanagedvCpus": Optional[Integer],
        "ecsClusterArn": String,
        "tags": Optional[TagrisTagsMap],
        "type": Optional[CEType],
        "state": Optional[CEState],
        "status": Optional[CEStatus],
        "statusReason": Optional[String],
        "computeResources": Optional[ComputeResource],
        "serviceRole": Optional[String],
    },
    total=False,
)
ComputeEnvironmentDetailList = List[ComputeEnvironmentDetail]


class ComputeEnvironmentOrder(TypedDict, total=False):
    order: Integer
    computeEnvironment: String


ComputeEnvironmentOrders = List[ComputeEnvironmentOrder]


class ComputeResourceUpdate(TypedDict, total=False):
    minvCpus: Optional[Integer]
    maxvCpus: Optional[Integer]
    desiredvCpus: Optional[Integer]
    subnets: Optional[StringList]
    securityGroupIds: Optional[StringList]


class FargatePlatformConfiguration(TypedDict, total=False):
    platformVersion: Optional[String]


class NetworkConfiguration(TypedDict, total=False):
    assignPublicIp: Optional[AssignPublicIp]


class Secret(TypedDict, total=False):
    name: String
    valueFrom: String


SecretList = List[Secret]
LogConfigurationOptionsMap = Dict[String, String]


class LogConfiguration(TypedDict, total=False):
    logDriver: LogDriver
    options: Optional[LogConfigurationOptionsMap]
    secretOptions: Optional[SecretList]


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


class LinuxParameters(TypedDict, total=False):
    devices: Optional[DevicesList]
    initProcessEnabled: Optional[Boolean]
    sharedMemorySize: Optional[Integer]
    tmpfs: Optional[TmpfsList]
    maxSwap: Optional[Integer]
    swappiness: Optional[Integer]


ResourceRequirement = TypedDict(
    "ResourceRequirement",
    {
        "value": String,
        "type": ResourceType,
    },
    total=False,
)
ResourceRequirements = List[ResourceRequirement]


class Ulimit(TypedDict, total=False):
    hardLimit: Integer
    name: String
    softLimit: Integer


Ulimits = List[Ulimit]


class MountPoint(TypedDict, total=False):
    containerPath: Optional[String]
    readOnly: Optional[Boolean]
    sourceVolume: Optional[String]


MountPoints = List[MountPoint]


class KeyValuePair(TypedDict, total=False):
    name: Optional[String]
    value: Optional[String]


EnvironmentVariables = List[KeyValuePair]


class EFSAuthorizationConfig(TypedDict, total=False):
    accessPointId: Optional[String]
    iam: Optional[EFSAuthorizationConfigIAM]


class EFSVolumeConfiguration(TypedDict, total=False):
    fileSystemId: String
    rootDirectory: Optional[String]
    transitEncryption: Optional[EFSTransitEncryption]
    transitEncryptionPort: Optional[Integer]
    authorizationConfig: Optional[EFSAuthorizationConfig]


class Host(TypedDict, total=False):
    sourcePath: Optional[String]


class Volume(TypedDict, total=False):
    host: Optional[Host]
    name: Optional[String]
    efsVolumeConfiguration: Optional[EFSVolumeConfiguration]


Volumes = List[Volume]


class ContainerDetail(TypedDict, total=False):
    image: Optional[String]
    vcpus: Optional[Integer]
    memory: Optional[Integer]
    command: Optional[StringList]
    jobRoleArn: Optional[String]
    executionRoleArn: Optional[String]
    volumes: Optional[Volumes]
    environment: Optional[EnvironmentVariables]
    mountPoints: Optional[MountPoints]
    readonlyRootFilesystem: Optional[Boolean]
    ulimits: Optional[Ulimits]
    privileged: Optional[Boolean]
    user: Optional[String]
    exitCode: Optional[Integer]
    reason: Optional[String]
    containerInstanceArn: Optional[String]
    taskArn: Optional[String]
    logStreamName: Optional[String]
    instanceType: Optional[String]
    networkInterfaces: Optional[NetworkInterfaceList]
    resourceRequirements: Optional[ResourceRequirements]
    linuxParameters: Optional[LinuxParameters]
    logConfiguration: Optional[LogConfiguration]
    secrets: Optional[SecretList]
    networkConfiguration: Optional[NetworkConfiguration]
    fargatePlatformConfiguration: Optional[FargatePlatformConfiguration]


class ContainerOverrides(TypedDict, total=False):
    vcpus: Optional[Integer]
    memory: Optional[Integer]
    command: Optional[StringList]
    instanceType: Optional[String]
    environment: Optional[EnvironmentVariables]
    resourceRequirements: Optional[ResourceRequirements]


class ContainerProperties(TypedDict, total=False):
    image: Optional[String]
    vcpus: Optional[Integer]
    memory: Optional[Integer]
    command: Optional[StringList]
    jobRoleArn: Optional[String]
    executionRoleArn: Optional[String]
    volumes: Optional[Volumes]
    environment: Optional[EnvironmentVariables]
    mountPoints: Optional[MountPoints]
    readonlyRootFilesystem: Optional[Boolean]
    privileged: Optional[Boolean]
    ulimits: Optional[Ulimits]
    user: Optional[String]
    instanceType: Optional[String]
    resourceRequirements: Optional[ResourceRequirements]
    linuxParameters: Optional[LinuxParameters]
    logConfiguration: Optional[LogConfiguration]
    secrets: Optional[SecretList]
    networkConfiguration: Optional[NetworkConfiguration]
    fargatePlatformConfiguration: Optional[FargatePlatformConfiguration]


class ContainerSummary(TypedDict, total=False):
    exitCode: Optional[Integer]
    reason: Optional[String]


CreateComputeEnvironmentRequest = TypedDict(
    "CreateComputeEnvironmentRequest",
    {
        "computeEnvironmentName": String,
        "type": CEType,
        "state": Optional[CEState],
        "unmanagedvCpus": Optional[Integer],
        "computeResources": Optional[ComputeResource],
        "serviceRole": Optional[String],
        "tags": Optional[TagrisTagsMap],
    },
    total=False,
)


class CreateComputeEnvironmentResponse(TypedDict, total=False):
    computeEnvironmentName: Optional[String]
    computeEnvironmentArn: Optional[String]


class CreateJobQueueRequest(ServiceRequest):
    jobQueueName: String
    state: Optional[JQState]
    schedulingPolicyArn: Optional[String]
    priority: Integer
    computeEnvironmentOrder: ComputeEnvironmentOrders
    tags: Optional[TagrisTagsMap]


class CreateJobQueueResponse(TypedDict, total=False):
    jobQueueName: String
    jobQueueArn: String


class ShareAttributes(TypedDict, total=False):
    shareIdentifier: String
    weightFactor: Optional[Float]


ShareAttributesList = List[ShareAttributes]


class FairsharePolicy(TypedDict, total=False):
    shareDecaySeconds: Optional[Integer]
    computeReservation: Optional[Integer]
    shareDistribution: Optional[ShareAttributesList]


class CreateSchedulingPolicyRequest(ServiceRequest):
    name: String
    fairsharePolicy: Optional[FairsharePolicy]
    tags: Optional[TagrisTagsMap]


class CreateSchedulingPolicyResponse(TypedDict, total=False):
    name: String
    arn: String


class DeleteComputeEnvironmentRequest(ServiceRequest):
    computeEnvironment: String


class DeleteComputeEnvironmentResponse(TypedDict, total=False):
    pass


class DeleteJobQueueRequest(ServiceRequest):
    jobQueue: String


class DeleteJobQueueResponse(TypedDict, total=False):
    pass


class DeleteSchedulingPolicyRequest(ServiceRequest):
    arn: String


class DeleteSchedulingPolicyResponse(TypedDict, total=False):
    pass


class DeregisterJobDefinitionRequest(ServiceRequest):
    jobDefinition: String


class DeregisterJobDefinitionResponse(TypedDict, total=False):
    pass


class DescribeComputeEnvironmentsRequest(ServiceRequest):
    computeEnvironments: Optional[StringList]
    maxResults: Optional[Integer]
    nextToken: Optional[String]


class DescribeComputeEnvironmentsResponse(TypedDict, total=False):
    computeEnvironments: Optional[ComputeEnvironmentDetailList]
    nextToken: Optional[String]


class DescribeJobDefinitionsRequest(ServiceRequest):
    jobDefinitions: Optional[StringList]
    maxResults: Optional[Integer]
    jobDefinitionName: Optional[String]
    status: Optional[String]
    nextToken: Optional[String]


PlatformCapabilityList = List[PlatformCapability]


class NodeRangeProperty(TypedDict, total=False):
    targetNodes: String
    container: Optional[ContainerProperties]


NodeRangeProperties = List[NodeRangeProperty]


class NodeProperties(TypedDict, total=False):
    numNodes: Integer
    mainNode: Integer
    nodeRangeProperties: NodeRangeProperties


class JobTimeout(TypedDict, total=False):
    attemptDurationSeconds: Optional[Integer]


class EvaluateOnExit(TypedDict, total=False):
    onStatusReason: Optional[String]
    onReason: Optional[String]
    onExitCode: Optional[String]
    action: RetryAction


EvaluateOnExitList = List[EvaluateOnExit]


class RetryStrategy(TypedDict, total=False):
    attempts: Optional[Integer]
    evaluateOnExit: Optional[EvaluateOnExitList]


ParametersMap = Dict[String, String]
JobDefinition = TypedDict(
    "JobDefinition",
    {
        "jobDefinitionName": String,
        "jobDefinitionArn": String,
        "revision": Integer,
        "status": Optional[String],
        "type": String,
        "schedulingPriority": Optional[Integer],
        "parameters": Optional[ParametersMap],
        "retryStrategy": Optional[RetryStrategy],
        "containerProperties": Optional[ContainerProperties],
        "timeout": Optional[JobTimeout],
        "nodeProperties": Optional[NodeProperties],
        "tags": Optional[TagrisTagsMap],
        "propagateTags": Optional[Boolean],
        "platformCapabilities": Optional[PlatformCapabilityList],
    },
    total=False,
)
JobDefinitionList = List[JobDefinition]


class DescribeJobDefinitionsResponse(TypedDict, total=False):
    jobDefinitions: Optional[JobDefinitionList]
    nextToken: Optional[String]


class DescribeJobQueuesRequest(ServiceRequest):
    jobQueues: Optional[StringList]
    maxResults: Optional[Integer]
    nextToken: Optional[String]


class JobQueueDetail(TypedDict, total=False):
    jobQueueName: String
    jobQueueArn: String
    state: JQState
    schedulingPolicyArn: Optional[String]
    status: Optional[JQStatus]
    statusReason: Optional[String]
    priority: Integer
    computeEnvironmentOrder: ComputeEnvironmentOrders
    tags: Optional[TagrisTagsMap]


JobQueueDetailList = List[JobQueueDetail]


class DescribeJobQueuesResponse(TypedDict, total=False):
    jobQueues: Optional[JobQueueDetailList]
    nextToken: Optional[String]


class DescribeJobsRequest(ServiceRequest):
    jobs: StringList


class NodeDetails(TypedDict, total=False):
    nodeIndex: Optional[Integer]
    isMainNode: Optional[Boolean]


JobDependency = TypedDict(
    "JobDependency",
    {
        "jobId": Optional[String],
        "type": Optional[ArrayJobDependency],
    },
    total=False,
)
JobDependencyList = List[JobDependency]


class JobDetail(TypedDict, total=False):
    jobArn: Optional[String]
    jobName: String
    jobId: String
    jobQueue: String
    status: JobStatus
    shareIdentifier: Optional[String]
    schedulingPriority: Optional[Integer]
    attempts: Optional[AttemptDetails]
    statusReason: Optional[String]
    createdAt: Optional[Long]
    retryStrategy: Optional[RetryStrategy]
    startedAt: Long
    stoppedAt: Optional[Long]
    dependsOn: Optional[JobDependencyList]
    jobDefinition: String
    parameters: Optional[ParametersMap]
    container: Optional[ContainerDetail]
    nodeDetails: Optional[NodeDetails]
    nodeProperties: Optional[NodeProperties]
    arrayProperties: Optional[ArrayPropertiesDetail]
    timeout: Optional[JobTimeout]
    tags: Optional[TagrisTagsMap]
    propagateTags: Optional[Boolean]
    platformCapabilities: Optional[PlatformCapabilityList]


JobDetailList = List[JobDetail]


class DescribeJobsResponse(TypedDict, total=False):
    jobs: Optional[JobDetailList]


class DescribeSchedulingPoliciesRequest(ServiceRequest):
    arns: StringList


class SchedulingPolicyDetail(TypedDict, total=False):
    name: String
    arn: String
    fairsharePolicy: Optional[FairsharePolicy]
    tags: Optional[TagrisTagsMap]


SchedulingPolicyDetailList = List[SchedulingPolicyDetail]


class DescribeSchedulingPoliciesResponse(TypedDict, total=False):
    schedulingPolicies: Optional[SchedulingPolicyDetailList]


class NodePropertiesSummary(TypedDict, total=False):
    isMainNode: Optional[Boolean]
    numNodes: Optional[Integer]
    nodeIndex: Optional[Integer]


class JobSummary(TypedDict, total=False):
    jobArn: Optional[String]
    jobId: String
    jobName: String
    createdAt: Optional[Long]
    status: Optional[JobStatus]
    statusReason: Optional[String]
    startedAt: Optional[Long]
    stoppedAt: Optional[Long]
    container: Optional[ContainerSummary]
    arrayProperties: Optional[ArrayPropertiesSummary]
    nodeProperties: Optional[NodePropertiesSummary]
    jobDefinition: Optional[String]


JobSummaryList = List[JobSummary]


class KeyValuesPair(TypedDict, total=False):
    name: Optional[String]
    values: Optional[StringList]


ListJobsFilterList = List[KeyValuesPair]


class ListJobsRequest(ServiceRequest):
    jobQueue: Optional[String]
    arrayJobId: Optional[String]
    multiNodeJobId: Optional[String]
    jobStatus: Optional[JobStatus]
    maxResults: Optional[Integer]
    nextToken: Optional[String]
    filters: Optional[ListJobsFilterList]


class ListJobsResponse(TypedDict, total=False):
    jobSummaryList: JobSummaryList
    nextToken: Optional[String]


class ListSchedulingPoliciesRequest(ServiceRequest):
    maxResults: Optional[Integer]
    nextToken: Optional[String]


class SchedulingPolicyListingDetail(TypedDict, total=False):
    arn: String


SchedulingPolicyListingDetailList = List[SchedulingPolicyListingDetail]


class ListSchedulingPoliciesResponse(TypedDict, total=False):
    schedulingPolicies: Optional[SchedulingPolicyListingDetailList]
    nextToken: Optional[String]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: String


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagrisTagsMap]


class NodePropertyOverride(TypedDict, total=False):
    targetNodes: String
    containerOverrides: Optional[ContainerOverrides]


NodePropertyOverrides = List[NodePropertyOverride]


class NodeOverrides(TypedDict, total=False):
    numNodes: Optional[Integer]
    nodePropertyOverrides: Optional[NodePropertyOverrides]


RegisterJobDefinitionRequest = TypedDict(
    "RegisterJobDefinitionRequest",
    {
        "jobDefinitionName": String,
        "type": JobDefinitionType,
        "parameters": Optional[ParametersMap],
        "schedulingPriority": Optional[Integer],
        "containerProperties": Optional[ContainerProperties],
        "nodeProperties": Optional[NodeProperties],
        "retryStrategy": Optional[RetryStrategy],
        "propagateTags": Optional[Boolean],
        "timeout": Optional[JobTimeout],
        "tags": Optional[TagrisTagsMap],
        "platformCapabilities": Optional[PlatformCapabilityList],
    },
    total=False,
)


class RegisterJobDefinitionResponse(TypedDict, total=False):
    jobDefinitionName: String
    jobDefinitionArn: String
    revision: Integer


class SubmitJobRequest(ServiceRequest):
    jobName: String
    jobQueue: String
    shareIdentifier: Optional[String]
    schedulingPriorityOverride: Optional[Integer]
    arrayProperties: Optional[ArrayProperties]
    dependsOn: Optional[JobDependencyList]
    jobDefinition: String
    parameters: Optional[ParametersMap]
    containerOverrides: Optional[ContainerOverrides]
    nodeOverrides: Optional[NodeOverrides]
    retryStrategy: Optional[RetryStrategy]
    propagateTags: Optional[Boolean]
    timeout: Optional[JobTimeout]
    tags: Optional[TagrisTagsMap]


class SubmitJobResponse(TypedDict, total=False):
    jobArn: Optional[String]
    jobName: String
    jobId: String


TagKeysList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: String
    tags: TagrisTagsMap


class TagResourceResponse(TypedDict, total=False):
    pass


class TerminateJobRequest(ServiceRequest):
    jobId: String
    reason: String


class TerminateJobResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: String
    tagKeys: TagKeysList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateComputeEnvironmentRequest(ServiceRequest):
    computeEnvironment: String
    state: Optional[CEState]
    unmanagedvCpus: Optional[Integer]
    computeResources: Optional[ComputeResourceUpdate]
    serviceRole: Optional[String]


class UpdateComputeEnvironmentResponse(TypedDict, total=False):
    computeEnvironmentName: Optional[String]
    computeEnvironmentArn: Optional[String]


class UpdateJobQueueRequest(ServiceRequest):
    jobQueue: String
    state: Optional[JQState]
    schedulingPolicyArn: Optional[String]
    priority: Optional[Integer]
    computeEnvironmentOrder: Optional[ComputeEnvironmentOrders]


class UpdateJobQueueResponse(TypedDict, total=False):
    jobQueueName: Optional[String]
    jobQueueArn: Optional[String]


class UpdateSchedulingPolicyRequest(ServiceRequest):
    arn: String
    fairsharePolicy: Optional[FairsharePolicy]


class UpdateSchedulingPolicyResponse(TypedDict, total=False):
    pass


class BatchApi:

    service = "batch"
    version = "2016-08-10"

    @handler("CancelJob")
    def cancel_job(
        self, context: RequestContext, job_id: String, reason: String
    ) -> CancelJobResponse:
        raise NotImplementedError

    @handler("CreateComputeEnvironment", expand=False)
    def create_compute_environment(
        self, context: RequestContext, request: CreateComputeEnvironmentRequest
    ) -> CreateComputeEnvironmentResponse:
        raise NotImplementedError

    @handler("CreateJobQueue")
    def create_job_queue(
        self,
        context: RequestContext,
        job_queue_name: String,
        priority: Integer,
        compute_environment_order: ComputeEnvironmentOrders,
        state: JQState = None,
        scheduling_policy_arn: String = None,
        tags: TagrisTagsMap = None,
    ) -> CreateJobQueueResponse:
        raise NotImplementedError

    @handler("CreateSchedulingPolicy")
    def create_scheduling_policy(
        self,
        context: RequestContext,
        name: String,
        fairshare_policy: FairsharePolicy = None,
        tags: TagrisTagsMap = None,
    ) -> CreateSchedulingPolicyResponse:
        raise NotImplementedError

    @handler("DeleteComputeEnvironment")
    def delete_compute_environment(
        self, context: RequestContext, compute_environment: String
    ) -> DeleteComputeEnvironmentResponse:
        raise NotImplementedError

    @handler("DeleteJobQueue")
    def delete_job_queue(
        self, context: RequestContext, job_queue: String
    ) -> DeleteJobQueueResponse:
        raise NotImplementedError

    @handler("DeleteSchedulingPolicy")
    def delete_scheduling_policy(
        self, context: RequestContext, arn: String
    ) -> DeleteSchedulingPolicyResponse:
        raise NotImplementedError

    @handler("DeregisterJobDefinition")
    def deregister_job_definition(
        self, context: RequestContext, job_definition: String
    ) -> DeregisterJobDefinitionResponse:
        raise NotImplementedError

    @handler("DescribeComputeEnvironments")
    def describe_compute_environments(
        self,
        context: RequestContext,
        compute_environments: StringList = None,
        max_results: Integer = None,
        next_token: String = None,
    ) -> DescribeComputeEnvironmentsResponse:
        raise NotImplementedError

    @handler("DescribeJobDefinitions")
    def describe_job_definitions(
        self,
        context: RequestContext,
        job_definitions: StringList = None,
        max_results: Integer = None,
        job_definition_name: String = None,
        status: String = None,
        next_token: String = None,
    ) -> DescribeJobDefinitionsResponse:
        raise NotImplementedError

    @handler("DescribeJobQueues")
    def describe_job_queues(
        self,
        context: RequestContext,
        job_queues: StringList = None,
        max_results: Integer = None,
        next_token: String = None,
    ) -> DescribeJobQueuesResponse:
        raise NotImplementedError

    @handler("DescribeJobs")
    def describe_jobs(self, context: RequestContext, jobs: StringList) -> DescribeJobsResponse:
        raise NotImplementedError

    @handler("DescribeSchedulingPolicies")
    def describe_scheduling_policies(
        self, context: RequestContext, arns: StringList
    ) -> DescribeSchedulingPoliciesResponse:
        raise NotImplementedError

    @handler("ListJobs")
    def list_jobs(
        self,
        context: RequestContext,
        job_queue: String = None,
        array_job_id: String = None,
        multi_node_job_id: String = None,
        job_status: JobStatus = None,
        max_results: Integer = None,
        next_token: String = None,
        filters: ListJobsFilterList = None,
    ) -> ListJobsResponse:
        raise NotImplementedError

    @handler("ListSchedulingPolicies")
    def list_scheduling_policies(
        self, context: RequestContext, max_results: Integer = None, next_token: String = None
    ) -> ListSchedulingPoliciesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: String
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("RegisterJobDefinition", expand=False)
    def register_job_definition(
        self, context: RequestContext, request: RegisterJobDefinitionRequest
    ) -> RegisterJobDefinitionResponse:
        raise NotImplementedError

    @handler("SubmitJob")
    def submit_job(
        self,
        context: RequestContext,
        job_name: String,
        job_queue: String,
        job_definition: String,
        share_identifier: String = None,
        scheduling_priority_override: Integer = None,
        array_properties: ArrayProperties = None,
        depends_on: JobDependencyList = None,
        parameters: ParametersMap = None,
        container_overrides: ContainerOverrides = None,
        node_overrides: NodeOverrides = None,
        retry_strategy: RetryStrategy = None,
        propagate_tags: Boolean = None,
        timeout: JobTimeout = None,
        tags: TagrisTagsMap = None,
    ) -> SubmitJobResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: String, tags: TagrisTagsMap
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("TerminateJob")
    def terminate_job(
        self, context: RequestContext, job_id: String, reason: String
    ) -> TerminateJobResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: String, tag_keys: TagKeysList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateComputeEnvironment")
    def update_compute_environment(
        self,
        context: RequestContext,
        compute_environment: String,
        state: CEState = None,
        unmanagedv_cpus: Integer = None,
        compute_resources: ComputeResourceUpdate = None,
        service_role: String = None,
    ) -> UpdateComputeEnvironmentResponse:
        raise NotImplementedError

    @handler("UpdateJobQueue")
    def update_job_queue(
        self,
        context: RequestContext,
        job_queue: String,
        state: JQState = None,
        scheduling_policy_arn: String = None,
        priority: Integer = None,
        compute_environment_order: ComputeEnvironmentOrders = None,
    ) -> UpdateJobQueueResponse:
        raise NotImplementedError

    @handler("UpdateSchedulingPolicy")
    def update_scheduling_policy(
        self, context: RequestContext, arn: String, fairshare_policy: FairsharePolicy = None
    ) -> UpdateSchedulingPolicyResponse:
        raise NotImplementedError
