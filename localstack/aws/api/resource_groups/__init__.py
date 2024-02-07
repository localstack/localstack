from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Description = str
ErrorCode = str
ErrorMessage = str
GroupArn = str
GroupConfigurationFailureReason = str
GroupConfigurationParameterName = str
GroupConfigurationParameterValue = str
GroupConfigurationType = str
GroupFilterValue = str
GroupLifecycleEventsStatusMessage = str
GroupName = str
GroupString = str
MaxResults = int
NextToken = str
Query = str
QueryErrorMessage = str
ResourceArn = str
ResourceFilterValue = str
ResourceType = str
TagKey = str
TagValue = str


class GroupConfigurationStatus(str):
    UPDATING = "UPDATING"
    UPDATE_COMPLETE = "UPDATE_COMPLETE"
    UPDATE_FAILED = "UPDATE_FAILED"


class GroupFilterName(str):
    resource_type = "resource-type"
    configuration_type = "configuration-type"


class GroupLifecycleEventsDesiredStatus(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class GroupLifecycleEventsStatus(str):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    IN_PROGRESS = "IN_PROGRESS"
    ERROR = "ERROR"


class QueryErrorCode(str):
    CLOUDFORMATION_STACK_INACTIVE = "CLOUDFORMATION_STACK_INACTIVE"
    CLOUDFORMATION_STACK_NOT_EXISTING = "CLOUDFORMATION_STACK_NOT_EXISTING"
    CLOUDFORMATION_STACK_UNASSUMABLE_ROLE = "CLOUDFORMATION_STACK_UNASSUMABLE_ROLE"


class QueryType(str):
    TAG_FILTERS_1_0 = "TAG_FILTERS_1_0"
    CLOUDFORMATION_STACK_1_0 = "CLOUDFORMATION_STACK_1_0"


class ResourceFilterName(str):
    resource_type = "resource-type"


class ResourceStatusValue(str):
    PENDING = "PENDING"


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
    Name: GroupName
    Description: Optional[Description]
    ResourceQuery: Optional[ResourceQuery]
    Tags: Optional[Tags]
    Configuration: Optional[GroupConfigurationList]


class GroupConfiguration(TypedDict, total=False):
    Configuration: Optional[GroupConfigurationList]
    ProposedConfiguration: Optional[GroupConfigurationList]
    Status: Optional[GroupConfigurationStatus]
    FailureReason: Optional[GroupConfigurationFailureReason]


class Group(TypedDict, total=False):
    GroupArn: GroupArn
    Name: GroupName
    Description: Optional[Description]


class CreateGroupOutput(TypedDict, total=False):
    Group: Optional[Group]
    ResourceQuery: Optional[ResourceQuery]
    Tags: Optional[Tags]
    GroupConfiguration: Optional[GroupConfiguration]


class DeleteGroupInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupString]


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
    Group: Optional[GroupString]


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


class GetTagsInput(ServiceRequest):
    Arn: GroupArn


class GetTagsOutput(TypedDict, total=False):
    Arn: Optional[GroupArn]
    Tags: Optional[Tags]


GroupFilterValues = List[GroupFilterValue]


class GroupFilter(TypedDict, total=False):
    Name: GroupFilterName
    Values: GroupFilterValues


GroupFilterList = List[GroupFilter]


class GroupIdentifier(TypedDict, total=False):
    GroupName: Optional[GroupName]
    GroupArn: Optional[GroupArn]


GroupIdentifierList = List[GroupIdentifier]
GroupList = List[Group]
ResourceArnList = List[ResourceArn]


class GroupResourcesInput(ServiceRequest):
    Group: GroupString
    ResourceArns: ResourceArnList


class PendingResource(TypedDict, total=False):
    ResourceArn: Optional[ResourceArn]


PendingResourceList = List[PendingResource]


class GroupResourcesOutput(TypedDict, total=False):
    Succeeded: Optional[ResourceArnList]
    Failed: Optional[FailedResourceList]
    Pending: Optional[PendingResourceList]


ResourceFilterValues = List[ResourceFilterValue]


class ResourceFilter(TypedDict, total=False):
    Name: ResourceFilterName
    Values: ResourceFilterValues


ResourceFilterList = List[ResourceFilter]


class ListGroupResourcesInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupString]
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


class ListGroupsInput(ServiceRequest):
    Filters: Optional[GroupFilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListGroupsOutput(TypedDict, total=False):
    GroupIdentifiers: Optional[GroupIdentifierList]
    Groups: Optional[GroupList]
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


class TagInput(ServiceRequest):
    Arn: GroupArn
    Tags: Tags


TagKeyList = List[TagKey]


class TagOutput(TypedDict, total=False):
    Arn: Optional[GroupArn]
    Tags: Optional[Tags]


class UngroupResourcesInput(ServiceRequest):
    Group: GroupString
    ResourceArns: ResourceArnList


class UngroupResourcesOutput(TypedDict, total=False):
    Succeeded: Optional[ResourceArnList]
    Failed: Optional[FailedResourceList]
    Pending: Optional[PendingResourceList]


class UntagInput(ServiceRequest):
    Arn: GroupArn
    Keys: TagKeyList


class UntagOutput(TypedDict, total=False):
    Arn: Optional[GroupArn]
    Keys: Optional[TagKeyList]


class UpdateAccountSettingsInput(ServiceRequest):
    GroupLifecycleEventsDesiredStatus: Optional[GroupLifecycleEventsDesiredStatus]


class UpdateAccountSettingsOutput(TypedDict, total=False):
    AccountSettings: Optional[AccountSettings]


class UpdateGroupInput(ServiceRequest):
    GroupName: Optional[GroupName]
    Group: Optional[GroupString]
    Description: Optional[Description]


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

    @handler("CreateGroup")
    def create_group(
        self,
        context: RequestContext,
        name: GroupName,
        description: Description = None,
        resource_query: ResourceQuery = None,
        tags: Tags = None,
        configuration: GroupConfigurationList = None,
        **kwargs
    ) -> CreateGroupOutput:
        raise NotImplementedError

    @handler("DeleteGroup")
    def delete_group(
        self,
        context: RequestContext,
        group_name: GroupName = None,
        group: GroupString = None,
        **kwargs
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
        group: GroupString = None,
        **kwargs
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
        **kwargs
    ) -> GetGroupQueryOutput:
        raise NotImplementedError

    @handler("GetTags")
    def get_tags(self, context: RequestContext, arn: GroupArn, **kwargs) -> GetTagsOutput:
        raise NotImplementedError

    @handler("GroupResources")
    def group_resources(
        self, context: RequestContext, group: GroupString, resource_arns: ResourceArnList, **kwargs
    ) -> GroupResourcesOutput:
        raise NotImplementedError

    @handler("ListGroupResources")
    def list_group_resources(
        self,
        context: RequestContext,
        group_name: GroupName = None,
        group: GroupString = None,
        filters: ResourceFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs
    ) -> ListGroupResourcesOutput:
        raise NotImplementedError

    @handler("ListGroups")
    def list_groups(
        self,
        context: RequestContext,
        filters: GroupFilterList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs
    ) -> ListGroupsOutput:
        raise NotImplementedError

    @handler("PutGroupConfiguration")
    def put_group_configuration(
        self,
        context: RequestContext,
        group: GroupString = None,
        configuration: GroupConfigurationList = None,
        **kwargs
    ) -> PutGroupConfigurationOutput:
        raise NotImplementedError

    @handler("SearchResources")
    def search_resources(
        self,
        context: RequestContext,
        resource_query: ResourceQuery,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs
    ) -> SearchResourcesOutput:
        raise NotImplementedError

    @handler("Tag")
    def tag(self, context: RequestContext, arn: GroupArn, tags: Tags, **kwargs) -> TagOutput:
        raise NotImplementedError

    @handler("UngroupResources")
    def ungroup_resources(
        self, context: RequestContext, group: GroupString, resource_arns: ResourceArnList, **kwargs
    ) -> UngroupResourcesOutput:
        raise NotImplementedError

    @handler("Untag")
    def untag(
        self, context: RequestContext, arn: GroupArn, keys: TagKeyList, **kwargs
    ) -> UntagOutput:
        raise NotImplementedError

    @handler("UpdateAccountSettings")
    def update_account_settings(
        self,
        context: RequestContext,
        group_lifecycle_events_desired_status: GroupLifecycleEventsDesiredStatus = None,
        **kwargs
    ) -> UpdateAccountSettingsOutput:
        raise NotImplementedError

    @handler("UpdateGroup")
    def update_group(
        self,
        context: RequestContext,
        group_name: GroupName = None,
        group: GroupString = None,
        description: Description = None,
        **kwargs
    ) -> UpdateGroupOutput:
        raise NotImplementedError

    @handler("UpdateGroupQuery")
    def update_group_query(
        self,
        context: RequestContext,
        resource_query: ResourceQuery,
        group_name: GroupName = None,
        group: GroupString = None,
        **kwargs
    ) -> UpdateGroupQueryOutput:
        raise NotImplementedError
