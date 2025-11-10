from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ApplicationArn = str
ApplicationTagKey = str
CreateGroupName = str
Criticality = int
Description = str
DisplayName = str
ErrorCode = str
ErrorMessage = str
GroupArn = str
GroupArnV2 = str
GroupConfigurationFailureReason = str
GroupConfigurationParameterName = str
GroupConfigurationParameterValue = str
GroupConfigurationType = str
GroupFilterValue = str
GroupLifecycleEventsStatusMessage = str
GroupName = str
GroupString = str
GroupStringV2 = str
ListGroupingStatusesFilterValue = str
MaxResults = int
NextToken = str
Owner = str
Query = str
QueryErrorMessage = str
ResourceArn = str
ResourceFilterValue = str
ResourceType = str
RoleArn = str
TagKey = str
TagSyncTaskArn = str
TagValue = str


class GroupConfigurationStatus(StrEnum):
    UPDATING = "UPDATING"
    UPDATE_COMPLETE = "UPDATE_COMPLETE"
    UPDATE_FAILED = "UPDATE_FAILED"


class GroupFilterName(StrEnum):
    resource_type = "resource-type"
    configuration_type = "configuration-type"
    owner = "owner"
    display_name = "display-name"
    criticality = "criticality"


class GroupLifecycleEventsDesiredStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class GroupLifecycleEventsStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    IN_PROGRESS = "IN_PROGRESS"
    ERROR = "ERROR"


class GroupingStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"
    SKIPPED = "SKIPPED"


class GroupingType(StrEnum):
    GROUP = "GROUP"
    UNGROUP = "UNGROUP"


class ListGroupingStatusesFilterName(StrEnum):
    status = "status"
    resource_arn = "resource-arn"


class QueryErrorCode(StrEnum):
    CLOUDFORMATION_STACK_INACTIVE = "CLOUDFORMATION_STACK_INACTIVE"
    CLOUDFORMATION_STACK_NOT_EXISTING = "CLOUDFORMATION_STACK_NOT_EXISTING"
    CLOUDFORMATION_STACK_UNASSUMABLE_ROLE = "CLOUDFORMATION_STACK_UNASSUMABLE_ROLE"
    RESOURCE_TYPE_NOT_SUPPORTED = "RESOURCE_TYPE_NOT_SUPPORTED"


class QueryType(StrEnum):
    TAG_FILTERS_1_0 = "TAG_FILTERS_1_0"
    CLOUDFORMATION_STACK_1_0 = "CLOUDFORMATION_STACK_1_0"


class ResourceFilterName(StrEnum):
    resource_type = "resource-type"


class ResourceStatusValue(StrEnum):
    PENDING = "PENDING"


class TagSyncTaskStatus(StrEnum):
    ACTIVE = "ACTIVE"
    ERROR = "ERROR"


class BadRequestException(ServiceException):
    code: str = "BadRequestException"
    sender_fault: bool = False
    status_code: int = 400


class ForbiddenException(ServiceException):
    code: str = "ForbiddenException"
    sender_fault: bool = False
    status_code: int = 403


class InternalServerErrorException(ServiceException):
    code: str = "InternalServerErrorException"
    sender_fault: bool = False
    status_code: int = 500


class MethodNotAllowedException(ServiceException):
    code: str = "MethodNotAllowedException"
    sender_fault: bool = False
    status_code: int = 405


class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 404


class TooManyRequestsException(ServiceException):
    code: str = "TooManyRequestsException"
    sender_fault: bool = False
    status_code: int = 429


class UnauthorizedException(ServiceException):
    code: str = "UnauthorizedException"
    sender_fault: bool = False
    status_code: int = 401


class AccountSettings(TypedDict, total=False):
    GroupLifecycleEventsDesiredStatus: GroupLifecycleEventsDesiredStatus | None
    GroupLifecycleEventsStatus: GroupLifecycleEventsStatus | None
    GroupLifecycleEventsStatusMessage: GroupLifecycleEventsStatusMessage | None


ApplicationTag = dict[ApplicationTagKey, ApplicationArn]


class CancelTagSyncTaskInput(ServiceRequest):
    TaskArn: TagSyncTaskArn


GroupConfigurationParameterValueList = list[GroupConfigurationParameterValue]


class GroupConfigurationParameter(TypedDict, total=False):
    Name: GroupConfigurationParameterName
    Values: GroupConfigurationParameterValueList | None


GroupParameterList = list[GroupConfigurationParameter]


class GroupConfigurationItem(TypedDict, total=False):
    Type: GroupConfigurationType
    Parameters: GroupParameterList | None


GroupConfigurationList = list[GroupConfigurationItem]
Tags = dict[TagKey, TagValue]


class ResourceQuery(TypedDict, total=False):
    Type: QueryType
    Query: Query


class CreateGroupInput(ServiceRequest):
    Name: CreateGroupName
    Description: Description | None
    ResourceQuery: ResourceQuery | None
    Tags: Tags | None
    Configuration: GroupConfigurationList | None
    Criticality: Criticality | None
    Owner: Owner | None
    DisplayName: DisplayName | None


class GroupConfiguration(TypedDict, total=False):
    Configuration: GroupConfigurationList | None
    ProposedConfiguration: GroupConfigurationList | None
    Status: GroupConfigurationStatus | None
    FailureReason: GroupConfigurationFailureReason | None


class Group(TypedDict, total=False):
    GroupArn: GroupArnV2
    Name: GroupName
    Description: Description | None
    Criticality: Criticality | None
    Owner: Owner | None
    DisplayName: DisplayName | None
    ApplicationTag: ApplicationTag | None


class CreateGroupOutput(TypedDict, total=False):
    Group: Group | None
    ResourceQuery: ResourceQuery | None
    Tags: Tags | None
    GroupConfiguration: GroupConfiguration | None


class DeleteGroupInput(ServiceRequest):
    GroupName: GroupName | None
    Group: GroupStringV2 | None


class DeleteGroupOutput(TypedDict, total=False):
    Group: Group | None


class FailedResource(TypedDict, total=False):
    ResourceArn: ResourceArn | None
    ErrorMessage: ErrorMessage | None
    ErrorCode: ErrorCode | None


FailedResourceList = list[FailedResource]


class GetAccountSettingsOutput(TypedDict, total=False):
    AccountSettings: AccountSettings | None


class GetGroupConfigurationInput(ServiceRequest):
    Group: GroupString | None


class GetGroupConfigurationOutput(TypedDict, total=False):
    GroupConfiguration: GroupConfiguration | None


class GetGroupInput(ServiceRequest):
    GroupName: GroupName | None
    Group: GroupStringV2 | None


class GetGroupOutput(TypedDict, total=False):
    Group: Group | None


class GetGroupQueryInput(ServiceRequest):
    GroupName: GroupName | None
    Group: GroupString | None


class GroupQuery(TypedDict, total=False):
    GroupName: GroupName
    ResourceQuery: ResourceQuery


class GetGroupQueryOutput(TypedDict, total=False):
    GroupQuery: GroupQuery | None


class GetTagSyncTaskInput(ServiceRequest):
    TaskArn: TagSyncTaskArn


timestamp = datetime


class GetTagSyncTaskOutput(TypedDict, total=False):
    GroupArn: GroupArnV2 | None
    GroupName: GroupName | None
    TaskArn: TagSyncTaskArn | None
    TagKey: TagKey | None
    TagValue: TagValue | None
    ResourceQuery: ResourceQuery | None
    RoleArn: RoleArn | None
    Status: TagSyncTaskStatus | None
    ErrorMessage: ErrorMessage | None
    CreatedAt: timestamp | None


class GetTagsInput(ServiceRequest):
    Arn: GroupArnV2


class GetTagsOutput(TypedDict, total=False):
    Arn: GroupArnV2 | None
    Tags: Tags | None


GroupFilterValues = list[GroupFilterValue]


class GroupFilter(TypedDict, total=False):
    Name: GroupFilterName
    Values: GroupFilterValues


GroupFilterList = list[GroupFilter]


class GroupIdentifier(TypedDict, total=False):
    GroupName: GroupName | None
    GroupArn: GroupArn | None
    Description: Description | None
    Criticality: Criticality | None
    Owner: Owner | None
    DisplayName: DisplayName | None


GroupIdentifierList = list[GroupIdentifier]
GroupList = list[Group]
ResourceArnList = list[ResourceArn]


class GroupResourcesInput(ServiceRequest):
    Group: GroupStringV2
    ResourceArns: ResourceArnList


class PendingResource(TypedDict, total=False):
    ResourceArn: ResourceArn | None


PendingResourceList = list[PendingResource]


class GroupResourcesOutput(TypedDict, total=False):
    Succeeded: ResourceArnList | None
    Failed: FailedResourceList | None
    Pending: PendingResourceList | None


class GroupingStatusesItem(TypedDict, total=False):
    ResourceArn: ResourceArn | None
    Action: GroupingType | None
    Status: GroupingStatus | None
    ErrorMessage: ErrorMessage | None
    ErrorCode: ErrorCode | None
    UpdatedAt: timestamp | None


GroupingStatusesList = list[GroupingStatusesItem]
ResourceFilterValues = list[ResourceFilterValue]


class ResourceFilter(TypedDict, total=False):
    Name: ResourceFilterName
    Values: ResourceFilterValues


ResourceFilterList = list[ResourceFilter]


class ListGroupResourcesInput(ServiceRequest):
    GroupName: GroupName | None
    Group: GroupStringV2 | None
    Filters: ResourceFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ResourceStatus(TypedDict, total=False):
    Name: ResourceStatusValue | None


class ResourceIdentifier(TypedDict, total=False):
    ResourceArn: ResourceArn | None
    ResourceType: ResourceType | None


class ListGroupResourcesItem(TypedDict, total=False):
    Identifier: ResourceIdentifier | None
    Status: ResourceStatus | None


ListGroupResourcesItemList = list[ListGroupResourcesItem]


class QueryError(TypedDict, total=False):
    ErrorCode: QueryErrorCode | None
    Message: QueryErrorMessage | None


QueryErrorList = list[QueryError]
ResourceIdentifierList = list[ResourceIdentifier]


class ListGroupResourcesOutput(TypedDict, total=False):
    Resources: ListGroupResourcesItemList | None
    ResourceIdentifiers: ResourceIdentifierList | None
    NextToken: NextToken | None
    QueryErrors: QueryErrorList | None


ListGroupingStatusesFilterValues = list[ListGroupingStatusesFilterValue]


class ListGroupingStatusesFilter(TypedDict, total=False):
    Name: ListGroupingStatusesFilterName
    Values: ListGroupingStatusesFilterValues


ListGroupingStatusesFilterList = list[ListGroupingStatusesFilter]


class ListGroupingStatusesInput(ServiceRequest):
    Group: GroupStringV2
    MaxResults: MaxResults | None
    Filters: ListGroupingStatusesFilterList | None
    NextToken: NextToken | None


class ListGroupingStatusesOutput(TypedDict, total=False):
    Group: GroupStringV2 | None
    GroupingStatuses: GroupingStatusesList | None
    NextToken: NextToken | None


class ListGroupsInput(ServiceRequest):
    Filters: GroupFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListGroupsOutput(TypedDict, total=False):
    GroupIdentifiers: GroupIdentifierList | None
    Groups: GroupList | None
    NextToken: NextToken | None


class ListTagSyncTasksFilter(TypedDict, total=False):
    GroupArn: GroupArnV2 | None
    GroupName: GroupName | None


ListTagSyncTasksFilterList = list[ListTagSyncTasksFilter]


class ListTagSyncTasksInput(ServiceRequest):
    Filters: ListTagSyncTasksFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class TagSyncTaskItem(TypedDict, total=False):
    GroupArn: GroupArnV2 | None
    GroupName: GroupName | None
    TaskArn: TagSyncTaskArn | None
    TagKey: TagKey | None
    TagValue: TagValue | None
    ResourceQuery: ResourceQuery | None
    RoleArn: RoleArn | None
    Status: TagSyncTaskStatus | None
    ErrorMessage: ErrorMessage | None
    CreatedAt: timestamp | None


TagSyncTaskList = list[TagSyncTaskItem]


class ListTagSyncTasksOutput(TypedDict, total=False):
    TagSyncTasks: TagSyncTaskList | None
    NextToken: NextToken | None


class PutGroupConfigurationInput(ServiceRequest):
    Group: GroupString | None
    Configuration: GroupConfigurationList | None


class PutGroupConfigurationOutput(TypedDict, total=False):
    pass


class SearchResourcesInput(ServiceRequest):
    ResourceQuery: ResourceQuery
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class SearchResourcesOutput(TypedDict, total=False):
    ResourceIdentifiers: ResourceIdentifierList | None
    NextToken: NextToken | None
    QueryErrors: QueryErrorList | None


class StartTagSyncTaskInput(ServiceRequest):
    Group: GroupStringV2
    TagKey: TagKey | None
    TagValue: TagValue | None
    ResourceQuery: ResourceQuery | None
    RoleArn: RoleArn


class StartTagSyncTaskOutput(TypedDict, total=False):
    GroupArn: GroupArnV2 | None
    GroupName: GroupName | None
    TaskArn: TagSyncTaskArn | None
    TagKey: TagKey | None
    TagValue: TagValue | None
    ResourceQuery: ResourceQuery | None
    RoleArn: RoleArn | None


class TagInput(ServiceRequest):
    Arn: GroupArnV2
    Tags: Tags


TagKeyList = list[TagKey]


class TagOutput(TypedDict, total=False):
    Arn: GroupArnV2 | None
    Tags: Tags | None


class UngroupResourcesInput(ServiceRequest):
    Group: GroupStringV2
    ResourceArns: ResourceArnList


class UngroupResourcesOutput(TypedDict, total=False):
    Succeeded: ResourceArnList | None
    Failed: FailedResourceList | None
    Pending: PendingResourceList | None


class UntagInput(ServiceRequest):
    Arn: GroupArnV2
    Keys: TagKeyList


class UntagOutput(TypedDict, total=False):
    Arn: GroupArnV2 | None
    Keys: TagKeyList | None


class UpdateAccountSettingsInput(ServiceRequest):
    GroupLifecycleEventsDesiredStatus: GroupLifecycleEventsDesiredStatus | None


class UpdateAccountSettingsOutput(TypedDict, total=False):
    AccountSettings: AccountSettings | None


class UpdateGroupInput(ServiceRequest):
    GroupName: GroupName | None
    Group: GroupStringV2 | None
    Description: Description | None
    Criticality: Criticality | None
    Owner: Owner | None
    DisplayName: DisplayName | None


class UpdateGroupOutput(TypedDict, total=False):
    Group: Group | None


class UpdateGroupQueryInput(ServiceRequest):
    GroupName: GroupName | None
    Group: GroupString | None
    ResourceQuery: ResourceQuery


class UpdateGroupQueryOutput(TypedDict, total=False):
    GroupQuery: GroupQuery | None


class ResourceGroupsApi:
    service: str = "resource-groups"
    version: str = "2017-11-27"

    @handler("CancelTagSyncTask")
    def cancel_tag_sync_task(
        self, context: RequestContext, task_arn: TagSyncTaskArn, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("CreateGroup")
    def create_group(
        self,
        context: RequestContext,
        name: CreateGroupName,
        description: Description | None = None,
        resource_query: ResourceQuery | None = None,
        tags: Tags | None = None,
        configuration: GroupConfigurationList | None = None,
        criticality: Criticality | None = None,
        owner: Owner | None = None,
        display_name: DisplayName | None = None,
        **kwargs,
    ) -> CreateGroupOutput:
        raise NotImplementedError

    @handler("DeleteGroup")
    def delete_group(
        self,
        context: RequestContext,
        group_name: GroupName | None = None,
        group: GroupStringV2 | None = None,
        **kwargs,
    ) -> DeleteGroupOutput:
        raise NotImplementedError

    @handler("GetAccountSettings")
    def get_account_settings(self, context: RequestContext, **kwargs) -> GetAccountSettingsOutput:
        raise NotImplementedError

    @handler("GetGroup")
    def get_group(
        self,
        context: RequestContext,
        group_name: GroupName | None = None,
        group: GroupStringV2 | None = None,
        **kwargs,
    ) -> GetGroupOutput:
        raise NotImplementedError

    @handler("GetGroupConfiguration")
    def get_group_configuration(
        self, context: RequestContext, group: GroupString | None = None, **kwargs
    ) -> GetGroupConfigurationOutput:
        raise NotImplementedError

    @handler("GetGroupQuery")
    def get_group_query(
        self,
        context: RequestContext,
        group_name: GroupName | None = None,
        group: GroupString | None = None,
        **kwargs,
    ) -> GetGroupQueryOutput:
        raise NotImplementedError

    @handler("GetTagSyncTask")
    def get_tag_sync_task(
        self, context: RequestContext, task_arn: TagSyncTaskArn, **kwargs
    ) -> GetTagSyncTaskOutput:
        raise NotImplementedError

    @handler("GetTags")
    def get_tags(self, context: RequestContext, arn: GroupArnV2, **kwargs) -> GetTagsOutput:
        raise NotImplementedError

    @handler("GroupResources")
    def group_resources(
        self,
        context: RequestContext,
        group: GroupStringV2,
        resource_arns: ResourceArnList,
        **kwargs,
    ) -> GroupResourcesOutput:
        raise NotImplementedError

    @handler("ListGroupResources")
    def list_group_resources(
        self,
        context: RequestContext,
        group_name: GroupName | None = None,
        group: GroupStringV2 | None = None,
        filters: ResourceFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListGroupResourcesOutput:
        raise NotImplementedError

    @handler("ListGroupingStatuses")
    def list_grouping_statuses(
        self,
        context: RequestContext,
        group: GroupStringV2,
        max_results: MaxResults | None = None,
        filters: ListGroupingStatusesFilterList | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListGroupingStatusesOutput:
        raise NotImplementedError

    @handler("ListGroups")
    def list_groups(
        self,
        context: RequestContext,
        filters: GroupFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListGroupsOutput:
        raise NotImplementedError

    @handler("ListTagSyncTasks")
    def list_tag_sync_tasks(
        self,
        context: RequestContext,
        filters: ListTagSyncTasksFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListTagSyncTasksOutput:
        raise NotImplementedError

    @handler("PutGroupConfiguration")
    def put_group_configuration(
        self,
        context: RequestContext,
        group: GroupString | None = None,
        configuration: GroupConfigurationList | None = None,
        **kwargs,
    ) -> PutGroupConfigurationOutput:
        raise NotImplementedError

    @handler("SearchResources")
    def search_resources(
        self,
        context: RequestContext,
        resource_query: ResourceQuery,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> SearchResourcesOutput:
        raise NotImplementedError

    @handler("StartTagSyncTask")
    def start_tag_sync_task(
        self,
        context: RequestContext,
        group: GroupStringV2,
        role_arn: RoleArn,
        tag_key: TagKey | None = None,
        tag_value: TagValue | None = None,
        resource_query: ResourceQuery | None = None,
        **kwargs,
    ) -> StartTagSyncTaskOutput:
        raise NotImplementedError

    @handler("Tag")
    def tag(self, context: RequestContext, arn: GroupArnV2, tags: Tags, **kwargs) -> TagOutput:
        raise NotImplementedError

    @handler("UngroupResources")
    def ungroup_resources(
        self,
        context: RequestContext,
        group: GroupStringV2,
        resource_arns: ResourceArnList,
        **kwargs,
    ) -> UngroupResourcesOutput:
        raise NotImplementedError

    @handler("Untag")
    def untag(
        self, context: RequestContext, arn: GroupArnV2, keys: TagKeyList, **kwargs
    ) -> UntagOutput:
        raise NotImplementedError

    @handler("UpdateAccountSettings")
    def update_account_settings(
        self,
        context: RequestContext,
        group_lifecycle_events_desired_status: GroupLifecycleEventsDesiredStatus | None = None,
        **kwargs,
    ) -> UpdateAccountSettingsOutput:
        raise NotImplementedError

    @handler("UpdateGroup")
    def update_group(
        self,
        context: RequestContext,
        group_name: GroupName | None = None,
        group: GroupStringV2 | None = None,
        description: Description | None = None,
        criticality: Criticality | None = None,
        owner: Owner | None = None,
        display_name: DisplayName | None = None,
        **kwargs,
    ) -> UpdateGroupOutput:
        raise NotImplementedError

    @handler("UpdateGroupQuery")
    def update_group_query(
        self,
        context: RequestContext,
        resource_query: ResourceQuery,
        group_name: GroupName | None = None,
        group: GroupString | None = None,
        **kwargs,
    ) -> UpdateGroupQueryOutput:
        raise NotImplementedError
