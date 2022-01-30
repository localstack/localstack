import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ContainerARN = str
ContainerAccessLoggingEnabled = bool
ContainerListLimit = int
ContainerName = str
ContainerPolicy = str
Endpoint = str
ErrorMessage = str
Header = str
LifecyclePolicy = str
MaxAgeSeconds = int
ObjectGroup = str
ObjectGroupName = str
Origin = str
PaginationToken = str
TagKey = str
TagValue = str


class ContainerLevelMetrics(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ContainerStatus(str):
    ACTIVE = "ACTIVE"
    CREATING = "CREATING"
    DELETING = "DELETING"


class MethodName(str):
    PUT = "PUT"
    GET = "GET"
    DELETE = "DELETE"
    HEAD = "HEAD"


class ContainerInUseException(ServiceException):
    Message: Optional[ErrorMessage]


class ContainerNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class CorsPolicyNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class InternalServerError(ServiceException):
    Message: Optional[ErrorMessage]


class LimitExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class PolicyNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


AllowedHeaders = List[Header]
AllowedMethods = List[MethodName]
AllowedOrigins = List[Origin]
TimeStamp = datetime


class Container(TypedDict, total=False):
    Endpoint: Optional[Endpoint]
    CreationTime: Optional[TimeStamp]
    ARN: Optional[ContainerARN]
    Name: Optional[ContainerName]
    Status: Optional[ContainerStatus]
    AccessLoggingEnabled: Optional[ContainerAccessLoggingEnabled]


ContainerList = List[Container]
ExposeHeaders = List[Header]


class CorsRule(TypedDict, total=False):
    AllowedOrigins: AllowedOrigins
    AllowedMethods: Optional[AllowedMethods]
    AllowedHeaders: AllowedHeaders
    MaxAgeSeconds: Optional[MaxAgeSeconds]
    ExposeHeaders: Optional[ExposeHeaders]


CorsPolicy = List[CorsRule]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]


class CreateContainerInput(ServiceRequest):
    ContainerName: ContainerName
    Tags: Optional[TagList]


class CreateContainerOutput(TypedDict, total=False):
    Container: Container


class DeleteContainerInput(ServiceRequest):
    ContainerName: ContainerName


class DeleteContainerOutput(TypedDict, total=False):
    pass


class DeleteContainerPolicyInput(ServiceRequest):
    ContainerName: ContainerName


class DeleteContainerPolicyOutput(TypedDict, total=False):
    pass


class DeleteCorsPolicyInput(ServiceRequest):
    ContainerName: ContainerName


class DeleteCorsPolicyOutput(TypedDict, total=False):
    pass


class DeleteLifecyclePolicyInput(ServiceRequest):
    ContainerName: ContainerName


class DeleteLifecyclePolicyOutput(TypedDict, total=False):
    pass


class DeleteMetricPolicyInput(ServiceRequest):
    ContainerName: ContainerName


class DeleteMetricPolicyOutput(TypedDict, total=False):
    pass


class DescribeContainerInput(ServiceRequest):
    ContainerName: Optional[ContainerName]


class DescribeContainerOutput(TypedDict, total=False):
    Container: Optional[Container]


class GetContainerPolicyInput(ServiceRequest):
    ContainerName: ContainerName


class GetContainerPolicyOutput(TypedDict, total=False):
    Policy: ContainerPolicy


class GetCorsPolicyInput(ServiceRequest):
    ContainerName: ContainerName


class GetCorsPolicyOutput(TypedDict, total=False):
    CorsPolicy: CorsPolicy


class GetLifecyclePolicyInput(ServiceRequest):
    ContainerName: ContainerName


class GetLifecyclePolicyOutput(TypedDict, total=False):
    LifecyclePolicy: LifecyclePolicy


class GetMetricPolicyInput(ServiceRequest):
    ContainerName: ContainerName


class MetricPolicyRule(TypedDict, total=False):
    ObjectGroup: ObjectGroup
    ObjectGroupName: ObjectGroupName


MetricPolicyRules = List[MetricPolicyRule]


class MetricPolicy(TypedDict, total=False):
    ContainerLevelMetrics: ContainerLevelMetrics
    MetricPolicyRules: Optional[MetricPolicyRules]


class GetMetricPolicyOutput(TypedDict, total=False):
    MetricPolicy: MetricPolicy


class ListContainersInput(ServiceRequest):
    NextToken: Optional[PaginationToken]
    MaxResults: Optional[ContainerListLimit]


class ListContainersOutput(TypedDict, total=False):
    Containers: ContainerList
    NextToken: Optional[PaginationToken]


class ListTagsForResourceInput(ServiceRequest):
    Resource: ContainerARN


class ListTagsForResourceOutput(TypedDict, total=False):
    Tags: Optional[TagList]


class PutContainerPolicyInput(ServiceRequest):
    ContainerName: ContainerName
    Policy: ContainerPolicy


class PutContainerPolicyOutput(TypedDict, total=False):
    pass


class PutCorsPolicyInput(ServiceRequest):
    ContainerName: ContainerName
    CorsPolicy: CorsPolicy


class PutCorsPolicyOutput(TypedDict, total=False):
    pass


class PutLifecyclePolicyInput(ServiceRequest):
    ContainerName: ContainerName
    LifecyclePolicy: LifecyclePolicy


class PutLifecyclePolicyOutput(TypedDict, total=False):
    pass


class PutMetricPolicyInput(ServiceRequest):
    ContainerName: ContainerName
    MetricPolicy: MetricPolicy


class PutMetricPolicyOutput(TypedDict, total=False):
    pass


class StartAccessLoggingInput(ServiceRequest):
    ContainerName: ContainerName


class StartAccessLoggingOutput(TypedDict, total=False):
    pass


class StopAccessLoggingInput(ServiceRequest):
    ContainerName: ContainerName


class StopAccessLoggingOutput(TypedDict, total=False):
    pass


TagKeyList = List[TagKey]


class TagResourceInput(ServiceRequest):
    Resource: ContainerARN
    Tags: TagList


class TagResourceOutput(TypedDict, total=False):
    pass


class UntagResourceInput(ServiceRequest):
    Resource: ContainerARN
    TagKeys: TagKeyList


class UntagResourceOutput(TypedDict, total=False):
    pass


class MediastoreApi:

    service = "mediastore"
    version = "2017-09-01"

    @handler("CreateContainer")
    def create_container(
        self, context: RequestContext, container_name: ContainerName, tags: TagList = None
    ) -> CreateContainerOutput:
        raise NotImplementedError

    @handler("DeleteContainer")
    def delete_container(
        self, context: RequestContext, container_name: ContainerName
    ) -> DeleteContainerOutput:
        raise NotImplementedError

    @handler("DeleteContainerPolicy")
    def delete_container_policy(
        self, context: RequestContext, container_name: ContainerName
    ) -> DeleteContainerPolicyOutput:
        raise NotImplementedError

    @handler("DeleteCorsPolicy")
    def delete_cors_policy(
        self, context: RequestContext, container_name: ContainerName
    ) -> DeleteCorsPolicyOutput:
        raise NotImplementedError

    @handler("DeleteLifecyclePolicy")
    def delete_lifecycle_policy(
        self, context: RequestContext, container_name: ContainerName
    ) -> DeleteLifecyclePolicyOutput:
        raise NotImplementedError

    @handler("DeleteMetricPolicy")
    def delete_metric_policy(
        self, context: RequestContext, container_name: ContainerName
    ) -> DeleteMetricPolicyOutput:
        raise NotImplementedError

    @handler("DescribeContainer")
    def describe_container(
        self, context: RequestContext, container_name: ContainerName = None
    ) -> DescribeContainerOutput:
        raise NotImplementedError

    @handler("GetContainerPolicy")
    def get_container_policy(
        self, context: RequestContext, container_name: ContainerName
    ) -> GetContainerPolicyOutput:
        raise NotImplementedError

    @handler("GetCorsPolicy")
    def get_cors_policy(
        self, context: RequestContext, container_name: ContainerName
    ) -> GetCorsPolicyOutput:
        raise NotImplementedError

    @handler("GetLifecyclePolicy")
    def get_lifecycle_policy(
        self, context: RequestContext, container_name: ContainerName
    ) -> GetLifecyclePolicyOutput:
        raise NotImplementedError

    @handler("GetMetricPolicy")
    def get_metric_policy(
        self, context: RequestContext, container_name: ContainerName
    ) -> GetMetricPolicyOutput:
        raise NotImplementedError

    @handler("ListContainers")
    def list_containers(
        self,
        context: RequestContext,
        next_token: PaginationToken = None,
        max_results: ContainerListLimit = None,
    ) -> ListContainersOutput:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource: ContainerARN
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("PutContainerPolicy")
    def put_container_policy(
        self, context: RequestContext, container_name: ContainerName, policy: ContainerPolicy
    ) -> PutContainerPolicyOutput:
        raise NotImplementedError

    @handler("PutCorsPolicy")
    def put_cors_policy(
        self, context: RequestContext, container_name: ContainerName, cors_policy: CorsPolicy
    ) -> PutCorsPolicyOutput:
        raise NotImplementedError

    @handler("PutLifecyclePolicy")
    def put_lifecycle_policy(
        self,
        context: RequestContext,
        container_name: ContainerName,
        lifecycle_policy: LifecyclePolicy,
    ) -> PutLifecyclePolicyOutput:
        raise NotImplementedError

    @handler("PutMetricPolicy")
    def put_metric_policy(
        self, context: RequestContext, container_name: ContainerName, metric_policy: MetricPolicy
    ) -> PutMetricPolicyOutput:
        raise NotImplementedError

    @handler("StartAccessLogging")
    def start_access_logging(
        self, context: RequestContext, container_name: ContainerName
    ) -> StartAccessLoggingOutput:
        raise NotImplementedError

    @handler("StopAccessLogging")
    def stop_access_logging(
        self, context: RequestContext, container_name: ContainerName
    ) -> StopAccessLoggingOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource: ContainerARN, tags: TagList
    ) -> TagResourceOutput:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource: ContainerARN, tag_keys: TagKeyList
    ) -> UntagResourceOutput:
        raise NotImplementedError
