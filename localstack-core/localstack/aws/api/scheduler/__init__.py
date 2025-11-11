from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

CapacityProvider = str
CapacityProviderStrategyItemBase = int
CapacityProviderStrategyItemWeight = int
ClientToken = str
DeadLetterConfigArnString = str
Description = str
DetailType = str
EnableECSManagedTags = bool
EnableExecuteCommand = bool
Group = str
KmsKeyArn = str
MaxResults = int
MaximumEventAgeInSeconds = int
MaximumRetryAttempts = int
MaximumWindowInMinutes = int
MessageGroupId = str
Name = str
NamePrefix = str
NextToken = str
PlacementConstraintExpression = str
PlacementStrategyField = str
PlatformVersion = str
ReferenceId = str
RoleArn = str
SageMakerPipelineParameterName = str
SageMakerPipelineParameterValue = str
ScheduleArn = str
ScheduleExpression = str
ScheduleExpressionTimezone = str
ScheduleGroupArn = str
ScheduleGroupName = str
ScheduleGroupNamePrefix = str
SecurityGroup = str
Source = str
String = str
Subnet = str
TagKey = str
TagResourceArn = str
TagValue = str
TargetArn = str
TargetInput = str
TargetPartitionKey = str
TaskCount = int
TaskDefinitionArn = str


class ActionAfterCompletion(StrEnum):
    NONE = "NONE"
    DELETE = "DELETE"


class AssignPublicIp(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class FlexibleTimeWindowMode(StrEnum):
    OFF = "OFF"
    FLEXIBLE = "FLEXIBLE"


class LaunchType(StrEnum):
    EC2 = "EC2"
    FARGATE = "FARGATE"
    EXTERNAL = "EXTERNAL"


class PlacementConstraintType(StrEnum):
    distinctInstance = "distinctInstance"
    memberOf = "memberOf"


class PlacementStrategyType(StrEnum):
    random = "random"
    spread = "spread"
    binpack = "binpack"


class PropagateTags(StrEnum):
    TASK_DEFINITION = "TASK_DEFINITION"


class ScheduleGroupState(StrEnum):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class ScheduleState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = True
    status_code: int = 409


class InternalServerException(ServiceException):
    code: str = "InternalServerException"
    sender_fault: bool = False
    status_code: int = 500


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class ServiceQuotaExceededException(ServiceException):
    code: str = "ServiceQuotaExceededException"
    sender_fault: bool = True
    status_code: int = 402


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = True
    status_code: int = 429


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400


Subnets = list[Subnet]
SecurityGroups = list[SecurityGroup]


class AwsVpcConfiguration(TypedDict, total=False):
    AssignPublicIp: AssignPublicIp | None
    SecurityGroups: SecurityGroups | None
    Subnets: Subnets


class CapacityProviderStrategyItem(TypedDict, total=False):
    base: CapacityProviderStrategyItemBase | None
    capacityProvider: CapacityProvider
    weight: CapacityProviderStrategyItemWeight | None


CapacityProviderStrategy = list[CapacityProviderStrategyItem]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]


class CreateScheduleGroupInput(ServiceRequest):
    ClientToken: ClientToken | None
    Name: ScheduleGroupName
    Tags: TagList | None


class CreateScheduleGroupOutput(TypedDict, total=False):
    ScheduleGroupArn: ScheduleGroupArn


class SqsParameters(TypedDict, total=False):
    MessageGroupId: MessageGroupId | None


class SageMakerPipelineParameter(TypedDict, total=False):
    Name: SageMakerPipelineParameterName
    Value: SageMakerPipelineParameterValue


SageMakerPipelineParameterList = list[SageMakerPipelineParameter]


class SageMakerPipelineParameters(TypedDict, total=False):
    PipelineParameterList: SageMakerPipelineParameterList | None


class RetryPolicy(TypedDict, total=False):
    MaximumEventAgeInSeconds: MaximumEventAgeInSeconds | None
    MaximumRetryAttempts: MaximumRetryAttempts | None


class KinesisParameters(TypedDict, total=False):
    PartitionKey: TargetPartitionKey


class EventBridgeParameters(TypedDict, total=False):
    DetailType: DetailType
    Source: Source


TagMap = dict[TagKey, TagValue]
Tags = list[TagMap]


class PlacementStrategy(TypedDict, total=False):
    field: PlacementStrategyField | None
    type: PlacementStrategyType | None


PlacementStrategies = list[PlacementStrategy]


class PlacementConstraint(TypedDict, total=False):
    expression: PlacementConstraintExpression | None
    type: PlacementConstraintType | None


PlacementConstraints = list[PlacementConstraint]


class NetworkConfiguration(TypedDict, total=False):
    awsvpcConfiguration: AwsVpcConfiguration | None


class EcsParameters(TypedDict, total=False):
    CapacityProviderStrategy: CapacityProviderStrategy | None
    EnableECSManagedTags: EnableECSManagedTags | None
    EnableExecuteCommand: EnableExecuteCommand | None
    Group: Group | None
    LaunchType: LaunchType | None
    NetworkConfiguration: NetworkConfiguration | None
    PlacementConstraints: PlacementConstraints | None
    PlacementStrategy: PlacementStrategies | None
    PlatformVersion: PlatformVersion | None
    PropagateTags: PropagateTags | None
    ReferenceId: ReferenceId | None
    Tags: Tags | None
    TaskCount: TaskCount | None
    TaskDefinitionArn: TaskDefinitionArn


class DeadLetterConfig(TypedDict, total=False):
    Arn: DeadLetterConfigArnString | None


class Target(TypedDict, total=False):
    Arn: TargetArn
    DeadLetterConfig: DeadLetterConfig | None
    EcsParameters: EcsParameters | None
    EventBridgeParameters: EventBridgeParameters | None
    Input: TargetInput | None
    KinesisParameters: KinesisParameters | None
    RetryPolicy: RetryPolicy | None
    RoleArn: RoleArn
    SageMakerPipelineParameters: SageMakerPipelineParameters | None
    SqsParameters: SqsParameters | None


StartDate = datetime


class FlexibleTimeWindow(TypedDict, total=False):
    MaximumWindowInMinutes: MaximumWindowInMinutes | None
    Mode: FlexibleTimeWindowMode


EndDate = datetime


class CreateScheduleInput(ServiceRequest):
    ActionAfterCompletion: ActionAfterCompletion | None
    ClientToken: ClientToken | None
    Description: Description | None
    EndDate: EndDate | None
    FlexibleTimeWindow: FlexibleTimeWindow
    GroupName: ScheduleGroupName | None
    KmsKeyArn: KmsKeyArn | None
    Name: Name
    ScheduleExpression: ScheduleExpression
    ScheduleExpressionTimezone: ScheduleExpressionTimezone | None
    StartDate: StartDate | None
    State: ScheduleState | None
    Target: Target


class CreateScheduleOutput(TypedDict, total=False):
    ScheduleArn: ScheduleArn


CreationDate = datetime


class DeleteScheduleGroupInput(ServiceRequest):
    ClientToken: ClientToken | None
    Name: ScheduleGroupName


class DeleteScheduleGroupOutput(TypedDict, total=False):
    pass


class DeleteScheduleInput(ServiceRequest):
    ClientToken: ClientToken | None
    GroupName: ScheduleGroupName | None
    Name: Name


class DeleteScheduleOutput(TypedDict, total=False):
    pass


class GetScheduleGroupInput(ServiceRequest):
    Name: ScheduleGroupName


LastModificationDate = datetime


class GetScheduleGroupOutput(TypedDict, total=False):
    Arn: ScheduleGroupArn | None
    CreationDate: CreationDate | None
    LastModificationDate: LastModificationDate | None
    Name: ScheduleGroupName | None
    State: ScheduleGroupState | None


class GetScheduleInput(ServiceRequest):
    GroupName: ScheduleGroupName | None
    Name: Name


class GetScheduleOutput(TypedDict, total=False):
    ActionAfterCompletion: ActionAfterCompletion | None
    Arn: ScheduleArn | None
    CreationDate: CreationDate | None
    Description: Description | None
    EndDate: EndDate | None
    FlexibleTimeWindow: FlexibleTimeWindow | None
    GroupName: ScheduleGroupName | None
    KmsKeyArn: KmsKeyArn | None
    LastModificationDate: LastModificationDate | None
    Name: Name | None
    ScheduleExpression: ScheduleExpression | None
    ScheduleExpressionTimezone: ScheduleExpressionTimezone | None
    StartDate: StartDate | None
    State: ScheduleState | None
    Target: Target | None


class ListScheduleGroupsInput(ServiceRequest):
    MaxResults: MaxResults | None
    NamePrefix: ScheduleGroupNamePrefix | None
    NextToken: NextToken | None


class ScheduleGroupSummary(TypedDict, total=False):
    Arn: ScheduleGroupArn | None
    CreationDate: CreationDate | None
    LastModificationDate: LastModificationDate | None
    Name: ScheduleGroupName | None
    State: ScheduleGroupState | None


ScheduleGroupList = list[ScheduleGroupSummary]


class ListScheduleGroupsOutput(TypedDict, total=False):
    NextToken: NextToken | None
    ScheduleGroups: ScheduleGroupList


class ListSchedulesInput(ServiceRequest):
    GroupName: ScheduleGroupName | None
    MaxResults: MaxResults | None
    NamePrefix: NamePrefix | None
    NextToken: NextToken | None
    State: ScheduleState | None


class TargetSummary(TypedDict, total=False):
    Arn: TargetArn


class ScheduleSummary(TypedDict, total=False):
    Arn: ScheduleArn | None
    CreationDate: CreationDate | None
    GroupName: ScheduleGroupName | None
    LastModificationDate: LastModificationDate | None
    Name: Name | None
    State: ScheduleState | None
    Target: TargetSummary | None


ScheduleList = list[ScheduleSummary]


class ListSchedulesOutput(TypedDict, total=False):
    NextToken: NextToken | None
    Schedules: ScheduleList


class ListTagsForResourceInput(ServiceRequest):
    ResourceArn: TagResourceArn


class ListTagsForResourceOutput(TypedDict, total=False):
    Tags: TagList | None


TagKeyList = list[TagKey]


class TagResourceInput(ServiceRequest):
    ResourceArn: TagResourceArn
    Tags: TagList


class TagResourceOutput(TypedDict, total=False):
    pass


class UntagResourceInput(ServiceRequest):
    ResourceArn: TagResourceArn
    TagKeys: TagKeyList


class UntagResourceOutput(TypedDict, total=False):
    pass


class UpdateScheduleInput(ServiceRequest):
    ActionAfterCompletion: ActionAfterCompletion | None
    ClientToken: ClientToken | None
    Description: Description | None
    EndDate: EndDate | None
    FlexibleTimeWindow: FlexibleTimeWindow
    GroupName: ScheduleGroupName | None
    KmsKeyArn: KmsKeyArn | None
    Name: Name
    ScheduleExpression: ScheduleExpression
    ScheduleExpressionTimezone: ScheduleExpressionTimezone | None
    StartDate: StartDate | None
    State: ScheduleState | None
    Target: Target


class UpdateScheduleOutput(TypedDict, total=False):
    ScheduleArn: ScheduleArn


class SchedulerApi:
    service: str = "scheduler"
    version: str = "2021-06-30"

    @handler("CreateSchedule")
    def create_schedule(
        self,
        context: RequestContext,
        flexible_time_window: FlexibleTimeWindow,
        name: Name,
        schedule_expression: ScheduleExpression,
        target: Target,
        action_after_completion: ActionAfterCompletion | None = None,
        client_token: ClientToken | None = None,
        description: Description | None = None,
        end_date: EndDate | None = None,
        group_name: ScheduleGroupName | None = None,
        kms_key_arn: KmsKeyArn | None = None,
        schedule_expression_timezone: ScheduleExpressionTimezone | None = None,
        start_date: StartDate | None = None,
        state: ScheduleState | None = None,
        **kwargs,
    ) -> CreateScheduleOutput:
        raise NotImplementedError

    @handler("CreateScheduleGroup")
    def create_schedule_group(
        self,
        context: RequestContext,
        name: ScheduleGroupName,
        client_token: ClientToken | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateScheduleGroupOutput:
        raise NotImplementedError

    @handler("DeleteSchedule")
    def delete_schedule(
        self,
        context: RequestContext,
        name: Name,
        client_token: ClientToken | None = None,
        group_name: ScheduleGroupName | None = None,
        **kwargs,
    ) -> DeleteScheduleOutput:
        raise NotImplementedError

    @handler("DeleteScheduleGroup")
    def delete_schedule_group(
        self,
        context: RequestContext,
        name: ScheduleGroupName,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> DeleteScheduleGroupOutput:
        raise NotImplementedError

    @handler("GetSchedule")
    def get_schedule(
        self,
        context: RequestContext,
        name: Name,
        group_name: ScheduleGroupName | None = None,
        **kwargs,
    ) -> GetScheduleOutput:
        raise NotImplementedError

    @handler("GetScheduleGroup")
    def get_schedule_group(
        self, context: RequestContext, name: ScheduleGroupName, **kwargs
    ) -> GetScheduleGroupOutput:
        raise NotImplementedError

    @handler("ListScheduleGroups")
    def list_schedule_groups(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        name_prefix: ScheduleGroupNamePrefix | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListScheduleGroupsOutput:
        raise NotImplementedError

    @handler("ListSchedules")
    def list_schedules(
        self,
        context: RequestContext,
        group_name: ScheduleGroupName | None = None,
        max_results: MaxResults | None = None,
        name_prefix: NamePrefix | None = None,
        next_token: NextToken | None = None,
        state: ScheduleState | None = None,
        **kwargs,
    ) -> ListSchedulesOutput:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: TagResourceArn, **kwargs
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: TagResourceArn, tags: TagList, **kwargs
    ) -> TagResourceOutput:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: TagResourceArn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceOutput:
        raise NotImplementedError

    @handler("UpdateSchedule")
    def update_schedule(
        self,
        context: RequestContext,
        flexible_time_window: FlexibleTimeWindow,
        name: Name,
        schedule_expression: ScheduleExpression,
        target: Target,
        action_after_completion: ActionAfterCompletion | None = None,
        client_token: ClientToken | None = None,
        description: Description | None = None,
        end_date: EndDate | None = None,
        group_name: ScheduleGroupName | None = None,
        kms_key_arn: KmsKeyArn | None = None,
        schedule_expression_timezone: ScheduleExpressionTimezone | None = None,
        start_date: StartDate | None = None,
        state: ScheduleState | None = None,
        **kwargs,
    ) -> UpdateScheduleOutput:
        raise NotImplementedError
