from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

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
    GroupLifecycleEventsDesiredStatus: Optional[GroupLifecycleEventsDesiredStatus]
    GroupLifecycleEventsStatus: Optional[GroupLifecycleEventsStatus]
    GroupLifecycleEventsStatusMessage: Optional[GroupLifecycleEventsStatusMessage]


ApplicationTag = Dict[ApplicationTagKey, ApplicationArn]


class CancelTagSyncTaskInput(ServiceRequest):
    TaskArn: TagSyncTaskArn


GroupConfigurationParameterValueList = List[GroupConfigurationParameterValue]


class GroupConfigurationParameter(TypedDict, total=False):
    Name: GroupConfigurationParameterName
    Values: Optional[GroupConfigurationParameterValueList]


GroupParameterList = List[GroupConfigurationParameter]


class GroupConfigurationItem(TypedDict, total=False):
    Type: GroupConfigurationType
    Parameters: Optional[GroupParameterList]


GroupConfigurationList = List[GroupConfigurationItem]
Tags = Dict[TagKey, TagValue]


class ResourceQuery(TypedDict, total=False):
    Type: QueryType
    Query: Query


class CreateGroupInput(ServiceRequest):
    Name: CreateGroupName
    Description: Optional[Description]
    ResourceQuery: Optional[ResourceQuery]
    Tags: Optional[Tags]
    Configuration: Optional[GroupConfigurationList]
    Criticality: Optional[Criticality]
    Owner: Optional[Owner]
    DisplayName: Optional[DisplayName]


class GroupConfiguration(TypedDict, total=False):
    Configuration: Optional[GroupConfigurationList]
    ProposedConfiguration: Optional[GroupConfigurationList]
    Status: Optional[GroupConfigurationStatus]
    FailureReason: Optional[GroupConfigurationFailureReason]


class Group(TypedDict, total=False):
    GroupArn: GroupArnV2
    Name: GroupName
    Description: Optional[Description]
    Criticality: Optional[Criticality]
    Owner: Optional[Owner]
    DisplayName: Optional[DisplayName]
    ApplicationTag: Optional[ApplicationTag]


class CreateGroupOutput(TypedDict, total=False):
    Group: Optional[Group]
    ResourceQuery: Optional[ResourceQuery]
    Tags: Optional[Tags]
    GroupConfiguration: Optional[GroupConfiguration]


class DeleteGroupInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupStringV2]


class DeleteGroupOutput(TypedDict, total=False):
    Group: Optional[Group]


class FailedResource(TypedDict, total=False):
    ResourceArn: Optional[ResourceArn]
    ErrorMessage: Optional[ErrorMessage]
    ErrorCode: Optional[ErrorCode]


FailedResourceList = List[FailedResource]


class GetAccountSettingsOutput(TypedDict, total=False):
    AccountSettings: Optional[AccountSettings]


class GetGroupConfigurationInput(ServiceRequest):
    Group: Optional[GroupString]


class GetGroupConfigurationOutput(TypedDict, total=False):
    GroupConfiguration: Optional[GroupConfiguration]


class GetGroupInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupStringV2]


class GetGroupOutput(TypedDict, total=False):
    Group: Optional[Group]


class GetGroupQueryInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupString]


class GroupQuery(TypedDict, total=False):
    GroupName: GroupName
    ResourceQuery: ResourceQuery


class GetGroupQueryOutput(TypedDict, total=False):
    GroupQuery: Optional[GroupQuery]


class GetTagSyncTaskInput(ServiceRequest):
    TaskArn: TagSyncTaskArn


timestamp = datetime


class GetTagSyncTaskOutput(TypedDict, total=False):
    GroupArn: Optional[GroupArnV2]
    GroupName: Optional[GroupName]
    TaskArn: Optional[TagSyncTaskArn]
    TagKey: Optional[TagKey]
    TagValue: Optional[TagValue]
    ResourceQuery: Optional[ResourceQuery]
    RoleArn: Optional[RoleArn]
    Status: Optional[TagSyncTaskStatus]
    ErrorMessage: Optional[ErrorMessage]
    CreatedAt: Optional[timestamp]


class GetTagsInput(ServiceRequest):
    Arn: GroupArnV2


class GetTagsOutput(TypedDict, total=False):
    Arn: Optional[GroupArnV2]
    Tags: Optional[Tags]


GroupFilterValues = List[GroupFilterValue]


class GroupFilter(TypedDict, total=False):
    Name: GroupFilterName
    Values: GroupFilterValues


GroupFilterList = List[GroupFilter]


class GroupIdentifier(TypedDict, total=False):
    GroupName: Optional[GroupName]
    GroupArn: Optional[GroupArn]
    Description: Optional[Description]
    Criticality: Optional[Criticality]
    Owner: Optional[Owner]
    DisplayName: Optional[DisplayName]


GroupIdentifierList = List[GroupIdentifier]
GroupList = List[Group]
ResourceArnList = List[ResourceArn]


class GroupResourcesInput(ServiceRequest):
    Group: GroupStringV2
    ResourceArns: ResourceArnList


class PendingResource(TypedDict, total=False):
    ResourceArn: Optional[ResourceArn]


PendingResourceList = List[PendingResource]


class GroupResourcesOutput(TypedDict, total=False):
    Succeeded: Optional[ResourceArnList]
    Failed: Optional[FailedResourceList]
    Pending: Optional[PendingResourceList]


class GroupingStatusesItem(TypedDict, total=False):
    ResourceArn: Optional[ResourceArn]
    Action: Optional[GroupingType]
    Status: Optional[GroupingStatus]
    ErrorMessage: Optional[ErrorMessage]
    ErrorCode: Optional[ErrorCode]
    UpdatedAt: Optional[timestamp]


GroupingStatusesList = List[GroupingStatusesItem]
ResourceFilterValues = List[ResourceFilterValue]


class ResourceFilter(TypedDict, total=False):
    Name: ResourceFilterName
    Values: ResourceFilterValues


ResourceFilterList = List[ResourceFilter]


class ListGroupResourcesInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupStringV2]
    Filters: Optional[ResourceFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ResourceStatus(TypedDict, total=False):
    Name: Optional[ResourceStatusValue]


class ResourceIdentifier(TypedDict, total=False):
    ResourceArn: Optional[ResourceArn]
    ResourceType: Optional[ResourceType]


class ListGroupResourcesItem(TypedDict, total=False):
    Identifier: Optional[ResourceIdentifier]
    Status: Optional[ResourceStatus]


ListGroupResourcesItemList = List[ListGroupResourcesItem]


class QueryError(TypedDict, total=False):
    ErrorCode: Optional[QueryErrorCode]
    Message: Optional[QueryErrorMessage]


QueryErrorList = List[QueryError]
ResourceIdentifierList = List[ResourceIdentifier]


class ListGroupResourcesOutput(TypedDict, total=False):
    Resources: Optional[ListGroupResourcesItemList]
    ResourceIdentifiers: Optional[ResourceIdentifierList]
    NextToken: Optional[NextToken]
    QueryErrors: Optional[QueryErrorList]


ListGroupingStatusesFilterValues = List[ListGroupingStatusesFilterValue]


class ListGroupingStatusesFilter(TypedDict, total=False):
    Name: ListGroupingStatusesFilterName
    Values: ListGroupingStatusesFilterValues


ListGroupingStatusesFilterList = List[ListGroupingStatusesFilter]


class ListGroupingStatusesInput(ServiceRequest):
    Group: GroupStringV2
    MaxResults: Optional[MaxResults]
    Filters: Optional[ListGroupingStatusesFilterList]
    NextToken: Optional[NextToken]


class ListGroupingStatusesOutput(TypedDict, total=False):
    Group: Optional[GroupStringV2]
    GroupingStatuses: Optional[GroupingStatusesList]
    NextToken: Optional[NextToken]


class ListGroupsInput(ServiceRequest):
    Filters: Optional[GroupFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListGroupsOutput(TypedDict, total=False):
    GroupIdentifiers: Optional[GroupIdentifierList]
    Groups: Optional[GroupList]
    NextToken: Optional[NextToken]


class ListTagSyncTasksFilter(TypedDict, total=False):
    GroupArn: Optional[GroupArnV2]
    GroupName: Optional[GroupName]


ListTagSyncTasksFilterList = List[ListTagSyncTasksFilter]


class ListTagSyncTasksInput(ServiceRequest):
    Filters: Optional[ListTagSyncTasksFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class TagSyncTaskItem(TypedDict, total=False):
    GroupArn: Optional[GroupArnV2]
    GroupName: Optional[GroupName]
    TaskArn: Optional[TagSyncTaskArn]
    TagKey: Optional[TagKey]
    TagValue: Optional[TagValue]
    ResourceQuery: Optional[ResourceQuery]
    RoleArn: Optional[RoleArn]
    Status: Optional[TagSyncTaskStatus]
    ErrorMessage: Optional[ErrorMessage]
    CreatedAt: Optional[timestamp]


TagSyncTaskList = List[TagSyncTaskItem]


class ListTagSyncTasksOutput(TypedDict, total=False):
    TagSyncTasks: Optional[TagSyncTaskList]
    NextToken: Optional[NextToken]


class PutGroupConfigurationInput(ServiceRequest):
    Group: Optional[GroupString]
    Configuration: Optional[GroupConfigurationList]


class PutGroupConfigurationOutput(TypedDict, total=False):
    pass


class SearchResourcesInput(ServiceRequest):
    ResourceQuery: ResourceQuery
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class SearchResourcesOutput(TypedDict, total=False):
    ResourceIdentifiers: Optional[ResourceIdentifierList]
    NextToken: Optional[NextToken]
    QueryErrors: Optional[QueryErrorList]


class StartTagSyncTaskInput(ServiceRequest):
    Group: GroupStringV2
    TagKey: Optional[TagKey]
    TagValue: Optional[TagValue]
    ResourceQuery: Optional[ResourceQuery]
    RoleArn: RoleArn


class StartTagSyncTaskOutput(TypedDict, total=False):
    GroupArn: Optional[GroupArnV2]
    GroupName: Optional[GroupName]
    TaskArn: Optional[TagSyncTaskArn]
    TagKey: Optional[TagKey]
    TagValue: Optional[TagValue]
    ResourceQuery: Optional[ResourceQuery]
    RoleArn: Optional[RoleArn]


class TagInput(ServiceRequest):
    Arn: GroupArnV2
    Tags: Tags


TagKeyList = List[TagKey]


class TagOutput(TypedDict, total=False):
    Arn: Optional[GroupArnV2]
    Tags: Optional[Tags]


class UngroupResourcesInput(ServiceRequest):
    Group: GroupStringV2
    ResourceArns: ResourceArnList


class UngroupResourcesOutput(TypedDict, total=False):
    Succeeded: Optional[ResourceArnList]
    Failed: Optional[FailedResourceList]
    Pending: Optional[PendingResourceList]


class UntagInput(ServiceRequest):
    Arn: GroupArnV2
    Keys: TagKeyList


class UntagOutput(TypedDict, total=False):
    Arn: Optional[GroupArnV2]
    Keys: Optional[TagKeyList]


class UpdateAccountSettingsInput(ServiceRequest):
    GroupLifecycleEventsDesiredStatus: Optional[GroupLifecycleEventsDesiredStatus]


class UpdateAccountSettingsOutput(TypedDict, total=False):
    AccountSettings: Optional[AccountSettings]


class UpdateGroupInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupStringV2]
    Description: Optional[Description]
    Criticality: Optional[Criticality]
    Owner: Optional[Owner]
    DisplayName: Optional[DisplayName]


class UpdateGroupOutput(TypedDict, total=False):
    Group: Optional[Group]


class UpdateGroupQueryInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupString]
    ResourceQuery: ResourceQuery


class UpdateGroupQueryOutput(TypedDict, total=False):
    GroupQuery: Optional[GroupQuery]


class ResourceGroupsApi:
    service = "resource-groups"
    version = "2017-11-27"

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
        description: Description = None,
        resource_query: ResourceQuery = None,
        tags: Tags = None,
        configuration: GroupConfigurationList = None,
        criticality: Criticality = None,
        owner: Owner = None,
        display_name: DisplayName = None,
        **kwargs,
    ) -> CreateGroupOutput:
        raise NotImplementedError

    @handler("DeleteGroup")
    def delete_group(
        self,
        context: RequestContext,
        group_name: GroupName = None,
        group: GroupStringV2 = None,
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
        group_name: GroupName = None,
        group: GroupStringV2 = None,
        **kwargs,
    ) -> GetGroupOutput:
        raise NotImplementedError

    @handler("GetGroupConfiguration")
    def get_group_configuration(
        self, context: RequestContext, group: GroupString = None, **kwargs
    ) -> GetGroupConfigurationOutput:
        raise NotImplementedError

    @handler("GetGroupQuery")
    def get_group_query(
        self,
        context: RequestContext,
        group_name: GroupName = None,
        group: GroupString = None,
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
        group_name: GroupName = None,
        group: GroupStringV2 = None,
        filters: ResourceFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListGroupResourcesOutput:
        raise NotImplementedError

    @handler("ListGroupingStatuses")
    def list_grouping_statuses(
        self,
        context: RequestContext,
        group: GroupStringV2,
        max_results: MaxResults = None,
        filters: ListGroupingStatusesFilterList = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListGroupingStatusesOutput:
        raise NotImplementedError

    @handler("ListGroups")
    def list_groups(
        self,
        context: RequestContext,
        filters: GroupFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListGroupsOutput:
        raise NotImplementedError

    @handler("ListTagSyncTasks")
    def list_tag_sync_tasks(
        self,
        context: RequestContext,
        filters: ListTagSyncTasksFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListTagSyncTasksOutput:
        raise NotImplementedError

    @handler("PutGroupConfiguration")
    def put_group_configuration(
        self,
        context: RequestContext,
        group: GroupString = None,
        configuration: GroupConfigurationList = None,
        **kwargs,
    ) -> PutGroupConfigurationOutput:
        raise NotImplementedError

    @handler("SearchResources")
    def search_resources(
        self,
        context: RequestContext,
        resource_query: ResourceQuery,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> SearchResourcesOutput:
        raise NotImplementedError

    @handler("StartTagSyncTask")
    def start_tag_sync_task(
        self,
        context: RequestContext,
        group: GroupStringV2,
        role_arn: RoleArn,
        tag_key: TagKey = None,
        tag_value: TagValue = None,
        resource_query: ResourceQuery = None,
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
        group_lifecycle_events_desired_status: GroupLifecycleEventsDesiredStatus = None,
        **kwargs,
    ) -> UpdateAccountSettingsOutput:
        raise NotImplementedError

    @handler("UpdateGroup")
    def update_group(
        self,
        context: RequestContext,
        group_name: GroupName = None,
        group: GroupStringV2 = None,
        description: Description = None,
        criticality: Criticality = None,
        owner: Owner = None,
        display_name: DisplayName = None,
        **kwargs,
    ) -> UpdateGroupOutput:
        raise NotImplementedError

    @handler("UpdateGroupQuery")
    def update_group_query(
        self,
        context: RequestContext,
        resource_query: ResourceQuery,
        group_name: GroupName = None,
        group: GroupString = None,
        **kwargs,
    ) -> UpdateGroupQueryOutput:
        raise NotImplementedError
