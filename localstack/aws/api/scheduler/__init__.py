import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

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


class AssignPublicIp(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class FlexibleTimeWindowMode(str):
    OFF = "OFF"
    FLEXIBLE = "FLEXIBLE"


class LaunchType(str):
    EC2 = "EC2"
    FARGATE = "FARGATE"
    EXTERNAL = "EXTERNAL"


class PlacementConstraintType(str):
    distinctInstance = "distinctInstance"
    memberOf = "memberOf"


class PlacementStrategyType(str):
    random = "random"
    spread = "spread"
    binpack = "binpack"


class PropagateTags(str):
    TASK_DEFINITION = "TASK_DEFINITION"


class ScheduleGroupState(str):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class ScheduleState(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ConflictException(ServiceException):
    """Updating or deleting the resource can cause an inconsistent state."""

    code: str = "ConflictException"
    sender_fault: bool = True
    status_code: int = 409


class InternalServerException(ServiceException):
    """Unexpected error encountered while processing the request."""

    code: str = "InternalServerException"
    sender_fault: bool = False
    status_code: int = 500


class ResourceNotFoundException(ServiceException):
    """The request references a resource which does not exist."""

    code: str = "ResourceNotFoundException"
    sender_fault: bool = True
    status_code: int = 404


class ServiceQuotaExceededException(ServiceException):
    """The request exceeds a service quota."""

    code: str = "ServiceQuotaExceededException"
    sender_fault: bool = True
    status_code: int = 402


class ThrottlingException(ServiceException):
    """The request was denied due to request throttling."""

    code: str = "ThrottlingException"
    sender_fault: bool = True
    status_code: int = 429


class ValidationException(ServiceException):
    """The input fails to satisfy the constraints specified by an AWS service."""

    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400


Subnets = List[Subnet]
SecurityGroups = List[SecurityGroup]


class AwsVpcConfiguration(TypedDict, total=False):
    """This structure specifies the VPC subnets and security groups for the
    task, and whether a public IP address is to be used. This structure is
    relevant only for ECS tasks that use the awsvpc network mode.
    """

    AssignPublicIp: Optional[AssignPublicIp]
    SecurityGroups: Optional[SecurityGroups]
    Subnets: Subnets


class CapacityProviderStrategyItem(TypedDict, total=False):
    """The details of a capacity provider strategy."""

    base: Optional[CapacityProviderStrategyItemBase]
    capacityProvider: CapacityProvider
    weight: Optional[CapacityProviderStrategyItemWeight]


CapacityProviderStrategy = List[CapacityProviderStrategyItem]


class Tag(TypedDict, total=False):
    """Tag to associate with a schedule group."""

    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class CreateScheduleGroupInput(ServiceRequest):
    ClientToken: Optional[ClientToken]
    Name: ScheduleGroupName
    Tags: Optional[TagList]


class CreateScheduleGroupOutput(TypedDict, total=False):
    ScheduleGroupArn: ScheduleGroupArn


class SqsParameters(TypedDict, total=False):
    """The templated target type for the Amazon SQS
    ```SendMessage`` <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html>`__
    API operation. Contains the message group ID to use when the target is a
    FIFO queue. If you specify an Amazon SQS FIFO queue as a target, the
    queue must have content-based deduplication enabled. For more
    information, see `Using the Amazon SQS message deduplication
    ID <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-messagededuplicationid-property.html>`__
    in the *Amazon SQS Developer Guide*.
    """

    MessageGroupId: Optional[MessageGroupId]


class SageMakerPipelineParameter(TypedDict, total=False):
    """The name and value pair of a parameter to use to start execution of a
    SageMaker Model Building Pipeline.
    """

    Name: SageMakerPipelineParameterName
    Value: SageMakerPipelineParameterValue


SageMakerPipelineParameterList = List[SageMakerPipelineParameter]


class SageMakerPipelineParameters(TypedDict, total=False):
    """The templated target type for the Amazon SageMaker
    ```StartPipelineExecution`` <https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_StartPipelineExecution.html>`__
    API operation.
    """

    PipelineParameterList: Optional[SageMakerPipelineParameterList]


class RetryPolicy(TypedDict, total=False):
    """A ``RetryPolicy`` object that includes information about the retry
    policy settings, including the maximum age of an event, and the maximum
    number of times EventBridge Scheduler will try to deliver the event to a
    target.
    """

    MaximumEventAgeInSeconds: Optional[MaximumEventAgeInSeconds]
    MaximumRetryAttempts: Optional[MaximumRetryAttempts]


class KinesisParameters(TypedDict, total=False):
    """The templated target type for the Amazon Kinesis
    ```PutRecord`` <kinesis/latest/APIReference/API_PutRecord.html>`__ API
    operation.
    """

    PartitionKey: TargetPartitionKey


class EventBridgeParameters(TypedDict, total=False):
    """The templated target type for the EventBridge
    ```PutEvents`` <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html>`__
    API operation.
    """

    DetailType: DetailType
    Source: Source


TagMap = Dict[TagKey, TagValue]
Tags = List[TagMap]
PlacementStrategy = TypedDict(
    "PlacementStrategy",
    {
        "field": Optional[PlacementStrategyField],
        "type": Optional[PlacementStrategyType],
    },
    total=False,
)
PlacementStrategies = List[PlacementStrategy]
PlacementConstraint = TypedDict(
    "PlacementConstraint",
    {
        "expression": Optional[PlacementConstraintExpression],
        "type": Optional[PlacementConstraintType],
    },
    total=False,
)
PlacementConstraints = List[PlacementConstraint]


class NetworkConfiguration(TypedDict, total=False):
    """Specifies the network configuration for an ECS task."""

    awsvpcConfiguration: Optional[AwsVpcConfiguration]


class EcsParameters(TypedDict, total=False):
    """The templated target type for the Amazon ECS
    ```RunTask`` <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html>`__
    API operation.
    """

    CapacityProviderStrategy: Optional[CapacityProviderStrategy]
    EnableECSManagedTags: Optional[EnableECSManagedTags]
    EnableExecuteCommand: Optional[EnableExecuteCommand]
    Group: Optional[Group]
    LaunchType: Optional[LaunchType]
    NetworkConfiguration: Optional[NetworkConfiguration]
    PlacementConstraints: Optional[PlacementConstraints]
    PlacementStrategy: Optional[PlacementStrategies]
    PlatformVersion: Optional[PlatformVersion]
    PropagateTags: Optional[PropagateTags]
    ReferenceId: Optional[ReferenceId]
    Tags: Optional[Tags]
    TaskCount: Optional[TaskCount]
    TaskDefinitionArn: TaskDefinitionArn


class DeadLetterConfig(TypedDict, total=False):
    """An object that contains information about an Amazon SQS queue that
    EventBridge Scheduler uses as a dead-letter queue for your schedule. If
    specified, EventBridge Scheduler delivers failed events that could not
    be successfully delivered to a target to the queue.
    """

    Arn: Optional[DeadLetterConfigArnString]


class Target(TypedDict, total=False):
    """The schedule's target. EventBridge Scheduler supports templated target
    that invoke common API operations, as well as universal targets that you
    can customize to invoke over 6,000 API operations across more than 270
    services. You can only specify one templated or universal target for a
    schedule.
    """

    Arn: TargetArn
    DeadLetterConfig: Optional[DeadLetterConfig]
    EcsParameters: Optional[EcsParameters]
    EventBridgeParameters: Optional[EventBridgeParameters]
    Input: Optional[TargetInput]
    KinesisParameters: Optional[KinesisParameters]
    RetryPolicy: Optional[RetryPolicy]
    RoleArn: RoleArn
    SageMakerPipelineParameters: Optional[SageMakerPipelineParameters]
    SqsParameters: Optional[SqsParameters]


StartDate = datetime


class FlexibleTimeWindow(TypedDict, total=False):
    """Allows you to configure a time window during which EventBridge Scheduler
    invokes the schedule.
    """

    MaximumWindowInMinutes: Optional[MaximumWindowInMinutes]
    Mode: FlexibleTimeWindowMode


EndDate = datetime


class CreateScheduleInput(ServiceRequest):
    ClientToken: Optional[ClientToken]
    Description: Optional[Description]
    EndDate: Optional[EndDate]
    FlexibleTimeWindow: FlexibleTimeWindow
    GroupName: Optional[ScheduleGroupName]
    KmsKeyArn: Optional[KmsKeyArn]
    Name: Name
    ScheduleExpression: ScheduleExpression
    ScheduleExpressionTimezone: Optional[ScheduleExpressionTimezone]
    StartDate: Optional[StartDate]
    State: Optional[ScheduleState]
    Target: Target


class CreateScheduleOutput(TypedDict, total=False):
    ScheduleArn: ScheduleArn


CreationDate = datetime


class DeleteScheduleGroupInput(ServiceRequest):
    ClientToken: Optional[ClientToken]
    Name: ScheduleGroupName


class DeleteScheduleGroupOutput(TypedDict, total=False):
    pass


class DeleteScheduleInput(ServiceRequest):
    ClientToken: Optional[ClientToken]
    GroupName: Optional[ScheduleGroupName]
    Name: Name


class DeleteScheduleOutput(TypedDict, total=False):
    pass


class GetScheduleGroupInput(ServiceRequest):
    Name: ScheduleGroupName


LastModificationDate = datetime


class GetScheduleGroupOutput(TypedDict, total=False):
    Arn: Optional[ScheduleGroupArn]
    CreationDate: Optional[CreationDate]
    LastModificationDate: Optional[LastModificationDate]
    Name: Optional[ScheduleGroupName]
    State: Optional[ScheduleGroupState]


class GetScheduleInput(ServiceRequest):
    GroupName: Optional[ScheduleGroupName]
    Name: Name


class GetScheduleOutput(TypedDict, total=False):
    Arn: Optional[ScheduleArn]
    CreationDate: Optional[CreationDate]
    Description: Optional[Description]
    EndDate: Optional[EndDate]
    FlexibleTimeWindow: Optional[FlexibleTimeWindow]
    GroupName: Optional[ScheduleGroupName]
    KmsKeyArn: Optional[KmsKeyArn]
    LastModificationDate: Optional[LastModificationDate]
    Name: Optional[Name]
    ScheduleExpression: Optional[ScheduleExpression]
    ScheduleExpressionTimezone: Optional[ScheduleExpressionTimezone]
    StartDate: Optional[StartDate]
    State: Optional[ScheduleState]
    Target: Optional[Target]


class ListScheduleGroupsInput(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NamePrefix: Optional[ScheduleGroupNamePrefix]
    NextToken: Optional[NextToken]


class ScheduleGroupSummary(TypedDict, total=False):
    """The details of a schedule group."""

    Arn: Optional[ScheduleGroupArn]
    CreationDate: Optional[CreationDate]
    LastModificationDate: Optional[LastModificationDate]
    Name: Optional[ScheduleGroupName]
    State: Optional[ScheduleGroupState]


ScheduleGroupList = List[ScheduleGroupSummary]


class ListScheduleGroupsOutput(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ScheduleGroups: ScheduleGroupList


class ListSchedulesInput(ServiceRequest):
    GroupName: Optional[ScheduleGroupName]
    MaxResults: Optional[MaxResults]
    NamePrefix: Optional[NamePrefix]
    NextToken: Optional[NextToken]
    State: Optional[ScheduleState]


class TargetSummary(TypedDict, total=False):
    """The details of a target."""

    Arn: TargetArn


class ScheduleSummary(TypedDict, total=False):
    """The details of a schedule."""

    Arn: Optional[ScheduleArn]
    CreationDate: Optional[CreationDate]
    GroupName: Optional[ScheduleGroupName]
    LastModificationDate: Optional[LastModificationDate]
    Name: Optional[Name]
    State: Optional[ScheduleState]
    Target: Optional[TargetSummary]


ScheduleList = List[ScheduleSummary]


class ListSchedulesOutput(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Schedules: ScheduleList


class ListTagsForResourceInput(ServiceRequest):
    ResourceArn: TagResourceArn


class ListTagsForResourceOutput(TypedDict, total=False):
    Tags: Optional[TagList]


TagKeyList = List[TagKey]


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
    ClientToken: Optional[ClientToken]
    Description: Optional[Description]
    EndDate: Optional[EndDate]
    FlexibleTimeWindow: FlexibleTimeWindow
    GroupName: Optional[ScheduleGroupName]
    KmsKeyArn: Optional[KmsKeyArn]
    Name: Name
    ScheduleExpression: ScheduleExpression
    ScheduleExpressionTimezone: Optional[ScheduleExpressionTimezone]
    StartDate: Optional[StartDate]
    State: Optional[ScheduleState]
    Target: Target


class UpdateScheduleOutput(TypedDict, total=False):
    ScheduleArn: ScheduleArn


class SchedulerApi:

    service = "scheduler"
    version = "2021-06-30"

    @handler("CreateSchedule")
    def create_schedule(
        self,
        context: RequestContext,
        flexible_time_window: FlexibleTimeWindow,
        name: Name,
        schedule_expression: ScheduleExpression,
        target: Target,
        client_token: ClientToken = None,
        description: Description = None,
        end_date: EndDate = None,
        group_name: ScheduleGroupName = None,
        kms_key_arn: KmsKeyArn = None,
        schedule_expression_timezone: ScheduleExpressionTimezone = None,
        start_date: StartDate = None,
        state: ScheduleState = None,
    ) -> CreateScheduleOutput:
        """Creates the specified schedule.

        :param flexible_time_window: Allows you to configure a time window during which EventBridge Scheduler
        invokes the schedule.
        :param name: The name of the schedule that you are creating.
        :param schedule_expression: The expression that defines when the schedule runs.
        :param target: The schedule's target.
        :param client_token: Unique, case-sensitive identifier you provide to ensure the idempotency
        of the request.
        :param description: The description you specify for the schedule.
        :param end_date: The date, in UTC, before which the schedule can invoke its target.
        :param group_name: The name of the schedule group to associate with this schedule.
        :param kms_key_arn: The Amazon Resource Name (ARN) for the customer managed KMS key that
        EventBridge Scheduler will use to encrypt and decrypt your data.
        :param schedule_expression_timezone: The timezone in which the scheduling expression is evaluated.
        :param start_date: The date, in UTC, after which the schedule can begin invoking its
        target.
        :param state: Specifies whether the schedule is enabled or disabled.
        :returns: CreateScheduleOutput
        :raises ServiceQuotaExceededException:
        :raises ValidationException:
        :raises InternalServerException:
        :raises ConflictException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("CreateScheduleGroup")
    def create_schedule_group(
        self,
        context: RequestContext,
        name: ScheduleGroupName,
        client_token: ClientToken = None,
        tags: TagList = None,
    ) -> CreateScheduleGroupOutput:
        """Creates the specified schedule group.

        :param name: The name of the schedule group that you are creating.
        :param client_token: Unique, case-sensitive identifier you provide to ensure the idempotency
        of the request.
        :param tags: The list of tags to associate with the schedule group.
        :returns: CreateScheduleGroupOutput
        :raises ServiceQuotaExceededException:
        :raises ValidationException:
        :raises InternalServerException:
        :raises ConflictException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("DeleteSchedule")
    def delete_schedule(
        self,
        context: RequestContext,
        name: Name,
        client_token: ClientToken = None,
        group_name: ScheduleGroupName = None,
    ) -> DeleteScheduleOutput:
        """Deletes the specified schedule.

        :param name: The name of the schedule to delete.
        :param client_token: Unique, case-sensitive identifier you provide to ensure the idempotency
        of the request.
        :param group_name: The name of the schedule group associated with this schedule.
        :returns: DeleteScheduleOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ConflictException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("DeleteScheduleGroup")
    def delete_schedule_group(
        self, context: RequestContext, name: ScheduleGroupName, client_token: ClientToken = None
    ) -> DeleteScheduleGroupOutput:
        """Deletes the specified schedule group. Deleting a schedule group results
        in EventBridge Scheduler deleting all schedules associated with the
        group. When you delete a group, it remains in a ``DELETING`` state until
        all of its associated schedules are deleted. Schedules associated with
        the group that are set to run while the schedule group is in the process
        of being deleted might continue to invoke their targets until the
        schedule group and its associated schedules are deleted.

        This operation is eventually consistent.

        :param name: The name of the schedule group to delete.
        :param client_token: Unique, case-sensitive identifier you provide to ensure the idempotency
        of the request.
        :returns: DeleteScheduleGroupOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ConflictException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("GetSchedule")
    def get_schedule(
        self, context: RequestContext, name: Name, group_name: ScheduleGroupName = None
    ) -> GetScheduleOutput:
        """Retrieves the specified schedule.

        :param name: The name of the schedule to retrieve.
        :param group_name: The name of the schedule group associated with this schedule.
        :returns: GetScheduleOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("GetScheduleGroup")
    def get_schedule_group(
        self, context: RequestContext, name: ScheduleGroupName
    ) -> GetScheduleGroupOutput:
        """Retrieves the specified schedule group.

        :param name: The name of the schedule group to retrieve.
        :returns: GetScheduleGroupOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("ListScheduleGroups")
    def list_schedule_groups(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        name_prefix: ScheduleGroupNamePrefix = None,
        next_token: NextToken = None,
    ) -> ListScheduleGroupsOutput:
        """Returns a paginated list of your schedule groups.

        :param max_results: If specified, limits the number of results returned by this operation.
        :param name_prefix: The name prefix that you can use to return a filtered list of your
        schedule groups.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :returns: ListScheduleGroupsOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("ListSchedules")
    def list_schedules(
        self,
        context: RequestContext,
        group_name: ScheduleGroupName = None,
        max_results: MaxResults = None,
        name_prefix: NamePrefix = None,
        next_token: NextToken = None,
        state: ScheduleState = None,
    ) -> ListSchedulesOutput:
        """Returns a paginated list of your EventBridge Scheduler schedules.

        :param group_name: If specified, only lists the schedules whose associated schedule group
        matches the given filter.
        :param max_results: If specified, limits the number of results returned by this operation.
        :param name_prefix: Schedule name prefix to return the filtered list of resources.
        :param next_token: The token returned by a previous call to retrieve the next set of
        results.
        :param state: If specified, only lists the schedules whose current state matches the
        given filter.
        :returns: ListSchedulesOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: TagResourceArn
    ) -> ListTagsForResourceOutput:
        """Lists the tags associated with the Scheduler resource.

        :param resource_arn: The ARN of the EventBridge Scheduler resource for which you want to view
        tags.
        :returns: ListTagsForResourceOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: TagResourceArn, tags: TagList
    ) -> TagResourceOutput:
        """Assigns one or more tags (key-value pairs) to the specified EventBridge
        Scheduler resource. You can only assign tags to schedule groups.

        :param resource_arn: The Amazon Resource Name (ARN) of the schedule group that you are adding
        tags to.
        :param tags: The list of tags to associate with the schedule group.
        :returns: TagResourceOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ConflictException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: TagResourceArn, tag_keys: TagKeyList
    ) -> UntagResourceOutput:
        """Removes one or more tags from the specified EventBridge Scheduler
        schedule group.

        :param resource_arn: The Amazon Resource Name (ARN) of the schedule group from which you are
        removing tags.
        :param tag_keys: The list of tag keys to remove from the resource.
        :returns: UntagResourceOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ConflictException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError

    @handler("UpdateSchedule")
    def update_schedule(
        self,
        context: RequestContext,
        flexible_time_window: FlexibleTimeWindow,
        name: Name,
        schedule_expression: ScheduleExpression,
        target: Target,
        client_token: ClientToken = None,
        description: Description = None,
        end_date: EndDate = None,
        group_name: ScheduleGroupName = None,
        kms_key_arn: KmsKeyArn = None,
        schedule_expression_timezone: ScheduleExpressionTimezone = None,
        start_date: StartDate = None,
        state: ScheduleState = None,
    ) -> UpdateScheduleOutput:
        """Updates the specified schedule. When you call ``UpdateSchedule``,
        EventBridge Scheduler uses all values, including empty values, specified
        in the request and overrides the existing schedule. This is by design.
        This means that if you do not set an optional field in your request,
        that field will be set to its system-default value after the update.

        Before calling this operation, we recommend that you call the
        ``GetSchedule`` API operation and make a note of all optional parameters
        for your ``UpdateSchedule`` call.

        :param flexible_time_window: Allows you to configure a time window during which EventBridge Scheduler
        invokes the schedule.
        :param name: The name of the schedule that you are updating.
        :param schedule_expression: The expression that defines when the schedule runs.
        :param target: The schedule target.
        :param client_token: Unique, case-sensitive identifier you provide to ensure the idempotency
        of the request.
        :param description: The description you specify for the schedule.
        :param end_date: The date, in UTC, before which the schedule can invoke its target.
        :param group_name: The name of the schedule group with which the schedule is associated.
        :param kms_key_arn: The ARN for the customer managed KMS key that that you want EventBridge
        Scheduler to use to encrypt and decrypt your data.
        :param schedule_expression_timezone: The timezone in which the scheduling expression is evaluated.
        :param start_date: The date, in UTC, after which the schedule can begin invoking its
        target.
        :param state: Specifies whether the schedule is enabled or disabled.
        :returns: UpdateScheduleOutput
        :raises ValidationException:
        :raises InternalServerException:
        :raises ConflictException:
        :raises ResourceNotFoundException:
        :raises ThrottlingException:
        """
        raise NotImplementedError
