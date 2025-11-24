from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AmazonResourceType = str
CloudFormationResourceType = str
ComplianceStatus = bool
ErrorMessage = str
ExceptionMessage = str
ExcludeCompliantResources = bool
IncludeComplianceDetails = bool
LastUpdated = str
MaxResultsForListRequiredTags = int
MaxResultsGetComplianceSummary = int
PaginationToken = str
Region = str
ResourceARN = str
ResourceType = str
ResourcesPerPage = int
S3Bucket = str
S3Location = str
Status = str
StatusCode = int
TagKey = str
TagValue = str
TagsPerPage = int
TargetId = str


class ErrorCode(StrEnum):
    InternalServiceException = "InternalServiceException"
    InvalidParameterException = "InvalidParameterException"


class GroupByAttribute(StrEnum):
    TARGET_ID = "TARGET_ID"
    REGION = "REGION"
    RESOURCE_TYPE = "RESOURCE_TYPE"


class TargetIdType(StrEnum):
    ACCOUNT = "ACCOUNT"
    OU = "OU"
    ROOT = "ROOT"


class ConcurrentModificationException(ServiceException):
    code: str = "ConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 400


class ConstraintViolationException(ServiceException):
    code: str = "ConstraintViolationException"
    sender_fault: bool = False
    status_code: int = 400


class InternalServiceException(ServiceException):
    code: str = "InternalServiceException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterException(ServiceException):
    code: str = "InvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400


class PaginationTokenExpiredException(ServiceException):
    code: str = "PaginationTokenExpiredException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottledException(ServiceException):
    code: str = "ThrottledException"
    sender_fault: bool = False
    status_code: int = 400


CloudFormationResourceTypes = list[CloudFormationResourceType]
TagKeyList = list[TagKey]


class ComplianceDetails(TypedDict, total=False):
    NoncompliantKeys: TagKeyList | None
    KeysWithNoncompliantValues: TagKeyList | None
    ComplianceStatus: ComplianceStatus | None


class DescribeReportCreationInput(ServiceRequest):
    pass


class DescribeReportCreationOutput(TypedDict, total=False):
    Status: Status | None
    S3Location: S3Location | None
    ErrorMessage: ErrorMessage | None


class FailureInfo(TypedDict, total=False):
    StatusCode: StatusCode | None
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None


FailedResourcesMap = dict[ResourceARN, FailureInfo]
GroupBy = list[GroupByAttribute]
TagKeyFilterList = list[TagKey]
ResourceTypeFilterList = list[AmazonResourceType]
RegionFilterList = list[Region]
TargetIdFilterList = list[TargetId]


class GetComplianceSummaryInput(ServiceRequest):
    TargetIdFilters: TargetIdFilterList | None
    RegionFilters: RegionFilterList | None
    ResourceTypeFilters: ResourceTypeFilterList | None
    TagKeyFilters: TagKeyFilterList | None
    GroupBy: GroupBy | None
    MaxResults: MaxResultsGetComplianceSummary | None
    PaginationToken: PaginationToken | None


NonCompliantResources = int


class Summary(TypedDict, total=False):
    LastUpdated: LastUpdated | None
    TargetId: TargetId | None
    TargetIdType: TargetIdType | None
    Region: Region | None
    ResourceType: AmazonResourceType | None
    NonCompliantResources: NonCompliantResources | None


SummaryList = list[Summary]


class GetComplianceSummaryOutput(TypedDict, total=False):
    SummaryList: SummaryList | None
    PaginationToken: PaginationToken | None


ResourceARNListForGet = list[ResourceARN]
TagValueList = list[TagValue]


class TagFilter(TypedDict, total=False):
    Key: TagKey | None
    Values: TagValueList | None


TagFilterList = list[TagFilter]


class GetResourcesInput(ServiceRequest):
    PaginationToken: PaginationToken | None
    TagFilters: TagFilterList | None
    ResourcesPerPage: ResourcesPerPage | None
    TagsPerPage: TagsPerPage | None
    ResourceTypeFilters: ResourceTypeFilterList | None
    IncludeComplianceDetails: IncludeComplianceDetails | None
    ExcludeCompliantResources: ExcludeCompliantResources | None
    ResourceARNList: ResourceARNListForGet | None


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]


class ResourceTagMapping(TypedDict, total=False):
    ResourceARN: ResourceARN | None
    Tags: TagList | None
    ComplianceDetails: ComplianceDetails | None


ResourceTagMappingList = list[ResourceTagMapping]


class GetResourcesOutput(TypedDict, total=False):
    PaginationToken: PaginationToken | None
    ResourceTagMappingList: ResourceTagMappingList | None


class GetTagKeysInput(ServiceRequest):
    PaginationToken: PaginationToken | None


class GetTagKeysOutput(TypedDict, total=False):
    PaginationToken: PaginationToken | None
    TagKeys: TagKeyList | None


class GetTagValuesInput(ServiceRequest):
    PaginationToken: PaginationToken | None
    Key: TagKey


TagValuesOutputList = list[TagValue]


class GetTagValuesOutput(TypedDict, total=False):
    PaginationToken: PaginationToken | None
    TagValues: TagValuesOutputList | None


class ListRequiredTagsInput(ServiceRequest):
    NextToken: PaginationToken | None
    MaxResults: MaxResultsForListRequiredTags | None


ReportingTagKeys = list[TagKey]


class RequiredTag(TypedDict, total=False):
    ResourceType: ResourceType | None
    CloudFormationResourceTypes: CloudFormationResourceTypes | None
    ReportingTagKeys: ReportingTagKeys | None


RequiredTagsForListRequiredTags = list[RequiredTag]


class ListRequiredTagsOutput(TypedDict, total=False):
    RequiredTags: RequiredTagsForListRequiredTags | None
    NextToken: PaginationToken | None


ResourceARNListForTagUntag = list[ResourceARN]


class StartReportCreationInput(ServiceRequest):
    S3Bucket: S3Bucket


class StartReportCreationOutput(TypedDict, total=False):
    pass


TagKeyListForUntag = list[TagKey]
TagMap = dict[TagKey, TagValue]


class TagResourcesInput(ServiceRequest):
    ResourceARNList: ResourceARNListForTagUntag
    Tags: TagMap


class TagResourcesOutput(TypedDict, total=False):
    FailedResourcesMap: FailedResourcesMap | None


class UntagResourcesInput(ServiceRequest):
    ResourceARNList: ResourceARNListForTagUntag
    TagKeys: TagKeyListForUntag


class UntagResourcesOutput(TypedDict, total=False):
    FailedResourcesMap: FailedResourcesMap | None


class ResourcegroupstaggingapiApi:
    service: str = "resourcegroupstaggingapi"
    version: str = "2017-01-26"

    @handler("DescribeReportCreation")
    def describe_report_creation(
        self, context: RequestContext, **kwargs
    ) -> DescribeReportCreationOutput:
        raise NotImplementedError

    @handler("GetComplianceSummary")
    def get_compliance_summary(
        self,
        context: RequestContext,
        target_id_filters: TargetIdFilterList | None = None,
        region_filters: RegionFilterList | None = None,
        resource_type_filters: ResourceTypeFilterList | None = None,
        tag_key_filters: TagKeyFilterList | None = None,
        group_by: GroupBy | None = None,
        max_results: MaxResultsGetComplianceSummary | None = None,
        pagination_token: PaginationToken | None = None,
        **kwargs,
    ) -> GetComplianceSummaryOutput:
        raise NotImplementedError

    @handler("GetResources")
    def get_resources(
        self,
        context: RequestContext,
        pagination_token: PaginationToken | None = None,
        tag_filters: TagFilterList | None = None,
        resources_per_page: ResourcesPerPage | None = None,
        tags_per_page: TagsPerPage | None = None,
        resource_type_filters: ResourceTypeFilterList | None = None,
        include_compliance_details: IncludeComplianceDetails | None = None,
        exclude_compliant_resources: ExcludeCompliantResources | None = None,
        resource_arn_list: ResourceARNListForGet | None = None,
        **kwargs,
    ) -> GetResourcesOutput:
        raise NotImplementedError

    @handler("GetTagKeys")
    def get_tag_keys(
        self, context: RequestContext, pagination_token: PaginationToken | None = None, **kwargs
    ) -> GetTagKeysOutput:
        raise NotImplementedError

    @handler("GetTagValues")
    def get_tag_values(
        self,
        context: RequestContext,
        key: TagKey,
        pagination_token: PaginationToken | None = None,
        **kwargs,
    ) -> GetTagValuesOutput:
        raise NotImplementedError

    @handler("ListRequiredTags")
    def list_required_tags(
        self,
        context: RequestContext,
        next_token: PaginationToken | None = None,
        max_results: MaxResultsForListRequiredTags | None = None,
        **kwargs,
    ) -> ListRequiredTagsOutput:
        raise NotImplementedError

    @handler("StartReportCreation")
    def start_report_creation(
        self, context: RequestContext, s3_bucket: S3Bucket, **kwargs
    ) -> StartReportCreationOutput:
        raise NotImplementedError

    @handler("TagResources")
    def tag_resources(
        self,
        context: RequestContext,
        resource_arn_list: ResourceARNListForTagUntag,
        tags: TagMap,
        **kwargs,
    ) -> TagResourcesOutput:
        raise NotImplementedError

    @handler("UntagResources")
    def untag_resources(
        self,
        context: RequestContext,
        resource_arn_list: ResourceARNListForTagUntag,
        tag_keys: TagKeyListForUntag,
        **kwargs,
    ) -> UntagResourcesOutput:
        raise NotImplementedError
