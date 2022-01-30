import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AmazonResourceName = str
Arn = str
AttrKey = str
AttrValue = str
Code = str
DiscoverMaxResults = int
ErrorMessage = str
FailureThreshold = int
FilterValue = str
InstanceId = str
MaxResults = int
Message = str
NamespaceName = str
NamespaceNameHttp = str
NamespaceNamePrivate = str
NamespaceNamePublic = str
NextToken = str
OperationId = str
ResourceCount = int
ResourceDescription = str
ResourceId = str
ResourcePath = str
ServiceName = str
TagKey = str
TagValue = str


class CustomHealthStatus(str):
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"


class FilterCondition(str):
    EQ = "EQ"
    IN = "IN"
    BETWEEN = "BETWEEN"


class HealthCheckType(str):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TCP = "TCP"


class HealthStatus(str):
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


class HealthStatusFilter(str):
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    ALL = "ALL"
    HEALTHY_OR_ELSE_ALL = "HEALTHY_OR_ELSE_ALL"


class NamespaceFilterName(str):
    TYPE = "TYPE"


class NamespaceType(str):
    DNS_PUBLIC = "DNS_PUBLIC"
    DNS_PRIVATE = "DNS_PRIVATE"
    HTTP = "HTTP"


class OperationFilterName(str):
    NAMESPACE_ID = "NAMESPACE_ID"
    SERVICE_ID = "SERVICE_ID"
    STATUS = "STATUS"
    TYPE = "TYPE"
    UPDATE_DATE = "UPDATE_DATE"


class OperationStatus(str):
    SUBMITTED = "SUBMITTED"
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"


class OperationTargetType(str):
    NAMESPACE = "NAMESPACE"
    SERVICE = "SERVICE"
    INSTANCE = "INSTANCE"


class OperationType(str):
    CREATE_NAMESPACE = "CREATE_NAMESPACE"
    DELETE_NAMESPACE = "DELETE_NAMESPACE"
    UPDATE_NAMESPACE = "UPDATE_NAMESPACE"
    UPDATE_SERVICE = "UPDATE_SERVICE"
    REGISTER_INSTANCE = "REGISTER_INSTANCE"
    DEREGISTER_INSTANCE = "DEREGISTER_INSTANCE"


class RecordType(str):
    SRV = "SRV"
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"


class RoutingPolicy(str):
    MULTIVALUE = "MULTIVALUE"
    WEIGHTED = "WEIGHTED"


class ServiceFilterName(str):
    NAMESPACE_ID = "NAMESPACE_ID"


class ServiceType(str):
    HTTP = "HTTP"
    DNS_HTTP = "DNS_HTTP"
    DNS = "DNS"


class ServiceTypeOption(str):
    HTTP = "HTTP"


class CustomHealthNotFound(ServiceException):
    Message: Optional[ErrorMessage]


class DuplicateRequest(ServiceException):
    Message: Optional[ErrorMessage]
    DuplicateOperationId: Optional[ResourceId]


class InstanceNotFound(ServiceException):
    Message: Optional[ErrorMessage]


class InvalidInput(ServiceException):
    Message: Optional[ErrorMessage]


class NamespaceAlreadyExists(ServiceException):
    Message: Optional[ErrorMessage]
    CreatorRequestId: Optional[ResourceId]
    NamespaceId: Optional[ResourceId]


class NamespaceNotFound(ServiceException):
    Message: Optional[ErrorMessage]


class OperationNotFound(ServiceException):
    Message: Optional[ErrorMessage]


class RequestLimitExceeded(ServiceException):
    Message: Optional[ErrorMessage]


class ResourceInUse(ServiceException):
    Message: Optional[ErrorMessage]


class ResourceLimitExceeded(ServiceException):
    Message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class ServiceAlreadyExists(ServiceException):
    Message: Optional[ErrorMessage]
    CreatorRequestId: Optional[ResourceId]
    ServiceId: Optional[ResourceId]


class ServiceNotFound(ServiceException):
    Message: Optional[ErrorMessage]


class TooManyTagsException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceName: Optional[AmazonResourceName]


Attributes = Dict[AttrKey, AttrValue]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class CreateHttpNamespaceRequest(ServiceRequest):
    Name: NamespaceNameHttp
    CreatorRequestId: Optional[ResourceId]
    Description: Optional[ResourceDescription]
    Tags: Optional[TagList]


class CreateHttpNamespaceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


RecordTTL = int


class SOA(TypedDict, total=False):
    TTL: RecordTTL


class PrivateDnsPropertiesMutable(TypedDict, total=False):
    SOA: SOA


class PrivateDnsNamespaceProperties(TypedDict, total=False):
    DnsProperties: PrivateDnsPropertiesMutable


class CreatePrivateDnsNamespaceRequest(ServiceRequest):
    Name: NamespaceNamePrivate
    CreatorRequestId: Optional[ResourceId]
    Description: Optional[ResourceDescription]
    Vpc: ResourceId
    Tags: Optional[TagList]
    Properties: Optional[PrivateDnsNamespaceProperties]


class CreatePrivateDnsNamespaceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class PublicDnsPropertiesMutable(TypedDict, total=False):
    SOA: SOA


class PublicDnsNamespaceProperties(TypedDict, total=False):
    DnsProperties: PublicDnsPropertiesMutable


class CreatePublicDnsNamespaceRequest(ServiceRequest):
    Name: NamespaceNamePublic
    CreatorRequestId: Optional[ResourceId]
    Description: Optional[ResourceDescription]
    Tags: Optional[TagList]
    Properties: Optional[PublicDnsNamespaceProperties]


class CreatePublicDnsNamespaceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class HealthCheckCustomConfig(TypedDict, total=False):
    FailureThreshold: Optional[FailureThreshold]


class HealthCheckConfig(TypedDict, total=False):
    Type: HealthCheckType
    ResourcePath: Optional[ResourcePath]
    FailureThreshold: Optional[FailureThreshold]


class DnsRecord(TypedDict, total=False):
    Type: RecordType
    TTL: RecordTTL


DnsRecordList = List[DnsRecord]


class DnsConfig(TypedDict, total=False):
    NamespaceId: Optional[ResourceId]
    RoutingPolicy: Optional[RoutingPolicy]
    DnsRecords: DnsRecordList


class CreateServiceRequest(ServiceRequest):
    Name: ServiceName
    NamespaceId: Optional[ResourceId]
    CreatorRequestId: Optional[ResourceId]
    Description: Optional[ResourceDescription]
    DnsConfig: Optional[DnsConfig]
    HealthCheckConfig: Optional[HealthCheckConfig]
    HealthCheckCustomConfig: Optional[HealthCheckCustomConfig]
    Tags: Optional[TagList]
    Type: Optional[ServiceTypeOption]


Timestamp = datetime


class Service(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    Name: Optional[ServiceName]
    NamespaceId: Optional[ResourceId]
    Description: Optional[ResourceDescription]
    InstanceCount: Optional[ResourceCount]
    DnsConfig: Optional[DnsConfig]
    Type: Optional[ServiceType]
    HealthCheckConfig: Optional[HealthCheckConfig]
    HealthCheckCustomConfig: Optional[HealthCheckCustomConfig]
    CreateDate: Optional[Timestamp]
    CreatorRequestId: Optional[ResourceId]


class CreateServiceResponse(TypedDict, total=False):
    Service: Optional[Service]


class DeleteNamespaceRequest(ServiceRequest):
    Id: ResourceId


class DeleteNamespaceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class DeleteServiceRequest(ServiceRequest):
    Id: ResourceId


class DeleteServiceResponse(TypedDict, total=False):
    pass


class DeregisterInstanceRequest(ServiceRequest):
    ServiceId: ResourceId
    InstanceId: ResourceId


class DeregisterInstanceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class DiscoverInstancesRequest(ServiceRequest):
    NamespaceName: NamespaceName
    ServiceName: ServiceName
    MaxResults: Optional[DiscoverMaxResults]
    QueryParameters: Optional[Attributes]
    OptionalParameters: Optional[Attributes]
    HealthStatus: Optional[HealthStatusFilter]


class HttpInstanceSummary(TypedDict, total=False):
    InstanceId: Optional[ResourceId]
    NamespaceName: Optional[NamespaceNameHttp]
    ServiceName: Optional[ServiceName]
    HealthStatus: Optional[HealthStatus]
    Attributes: Optional[Attributes]


HttpInstanceSummaryList = List[HttpInstanceSummary]


class DiscoverInstancesResponse(TypedDict, total=False):
    Instances: Optional[HttpInstanceSummaryList]


class DnsConfigChange(TypedDict, total=False):
    DnsRecords: DnsRecordList


class DnsProperties(TypedDict, total=False):
    HostedZoneId: Optional[ResourceId]
    SOA: Optional[SOA]


FilterValues = List[FilterValue]


class GetInstanceRequest(ServiceRequest):
    ServiceId: ResourceId
    InstanceId: ResourceId


class Instance(TypedDict, total=False):
    Id: ResourceId
    CreatorRequestId: Optional[ResourceId]
    Attributes: Optional[Attributes]


class GetInstanceResponse(TypedDict, total=False):
    Instance: Optional[Instance]


InstanceIdList = List[ResourceId]


class GetInstancesHealthStatusRequest(ServiceRequest):
    ServiceId: ResourceId
    Instances: Optional[InstanceIdList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


InstanceHealthStatusMap = Dict[ResourceId, HealthStatus]


class GetInstancesHealthStatusResponse(TypedDict, total=False):
    Status: Optional[InstanceHealthStatusMap]
    NextToken: Optional[NextToken]


class GetNamespaceRequest(ServiceRequest):
    Id: ResourceId


class HttpProperties(TypedDict, total=False):
    HttpName: Optional[NamespaceName]


class NamespaceProperties(TypedDict, total=False):
    DnsProperties: Optional[DnsProperties]
    HttpProperties: Optional[HttpProperties]


class Namespace(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    Name: Optional[NamespaceName]
    Type: Optional[NamespaceType]
    Description: Optional[ResourceDescription]
    ServiceCount: Optional[ResourceCount]
    Properties: Optional[NamespaceProperties]
    CreateDate: Optional[Timestamp]
    CreatorRequestId: Optional[ResourceId]


class GetNamespaceResponse(TypedDict, total=False):
    Namespace: Optional[Namespace]


class GetOperationRequest(ServiceRequest):
    OperationId: ResourceId


OperationTargetsMap = Dict[OperationTargetType, ResourceId]


class Operation(TypedDict, total=False):
    Id: Optional[OperationId]
    Type: Optional[OperationType]
    Status: Optional[OperationStatus]
    ErrorMessage: Optional[Message]
    ErrorCode: Optional[Code]
    CreateDate: Optional[Timestamp]
    UpdateDate: Optional[Timestamp]
    Targets: Optional[OperationTargetsMap]


class GetOperationResponse(TypedDict, total=False):
    Operation: Optional[Operation]


class GetServiceRequest(ServiceRequest):
    Id: ResourceId


class GetServiceResponse(TypedDict, total=False):
    Service: Optional[Service]


class HttpNamespaceChange(TypedDict, total=False):
    Description: ResourceDescription


class InstanceSummary(TypedDict, total=False):
    Id: Optional[ResourceId]
    Attributes: Optional[Attributes]


InstanceSummaryList = List[InstanceSummary]


class ListInstancesRequest(ServiceRequest):
    ServiceId: ResourceId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListInstancesResponse(TypedDict, total=False):
    Instances: Optional[InstanceSummaryList]
    NextToken: Optional[NextToken]


class NamespaceFilter(TypedDict, total=False):
    Name: NamespaceFilterName
    Values: FilterValues
    Condition: Optional[FilterCondition]


NamespaceFilters = List[NamespaceFilter]


class ListNamespacesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    Filters: Optional[NamespaceFilters]


class NamespaceSummary(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    Name: Optional[NamespaceName]
    Type: Optional[NamespaceType]
    Description: Optional[ResourceDescription]
    ServiceCount: Optional[ResourceCount]
    Properties: Optional[NamespaceProperties]
    CreateDate: Optional[Timestamp]


NamespaceSummariesList = List[NamespaceSummary]


class ListNamespacesResponse(TypedDict, total=False):
    Namespaces: Optional[NamespaceSummariesList]
    NextToken: Optional[NextToken]


class OperationFilter(TypedDict, total=False):
    Name: OperationFilterName
    Values: FilterValues
    Condition: Optional[FilterCondition]


OperationFilters = List[OperationFilter]


class ListOperationsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    Filters: Optional[OperationFilters]


class OperationSummary(TypedDict, total=False):
    Id: Optional[OperationId]
    Status: Optional[OperationStatus]


OperationSummaryList = List[OperationSummary]


class ListOperationsResponse(TypedDict, total=False):
    Operations: Optional[OperationSummaryList]
    NextToken: Optional[NextToken]


class ServiceFilter(TypedDict, total=False):
    Name: ServiceFilterName
    Values: FilterValues
    Condition: Optional[FilterCondition]


ServiceFilters = List[ServiceFilter]


class ListServicesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    Filters: Optional[ServiceFilters]


class ServiceSummary(TypedDict, total=False):
    Id: Optional[ResourceId]
    Arn: Optional[Arn]
    Name: Optional[ServiceName]
    Type: Optional[ServiceType]
    Description: Optional[ResourceDescription]
    InstanceCount: Optional[ResourceCount]
    DnsConfig: Optional[DnsConfig]
    HealthCheckConfig: Optional[HealthCheckConfig]
    HealthCheckCustomConfig: Optional[HealthCheckCustomConfig]
    CreateDate: Optional[Timestamp]


ServiceSummariesList = List[ServiceSummary]


class ListServicesResponse(TypedDict, total=False):
    Services: Optional[ServiceSummariesList]
    NextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[TagList]


class SOAChange(TypedDict, total=False):
    TTL: RecordTTL


class PrivateDnsPropertiesMutableChange(TypedDict, total=False):
    SOA: SOAChange


class PrivateDnsNamespacePropertiesChange(TypedDict, total=False):
    DnsProperties: PrivateDnsPropertiesMutableChange


class PrivateDnsNamespaceChange(TypedDict, total=False):
    Description: Optional[ResourceDescription]
    Properties: Optional[PrivateDnsNamespacePropertiesChange]


class PublicDnsPropertiesMutableChange(TypedDict, total=False):
    SOA: SOAChange


class PublicDnsNamespacePropertiesChange(TypedDict, total=False):
    DnsProperties: PublicDnsPropertiesMutableChange


class PublicDnsNamespaceChange(TypedDict, total=False):
    Description: Optional[ResourceDescription]
    Properties: Optional[PublicDnsNamespacePropertiesChange]


class RegisterInstanceRequest(ServiceRequest):
    ServiceId: ResourceId
    InstanceId: InstanceId
    CreatorRequestId: Optional[ResourceId]
    Attributes: Attributes


class RegisterInstanceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class ServiceChange(TypedDict, total=False):
    Description: Optional[ResourceDescription]
    DnsConfig: Optional[DnsConfigChange]
    HealthCheckConfig: Optional[HealthCheckConfig]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateHttpNamespaceRequest(ServiceRequest):
    Id: ResourceId
    UpdaterRequestId: Optional[ResourceId]
    Namespace: HttpNamespaceChange


class UpdateHttpNamespaceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class UpdateInstanceCustomHealthStatusRequest(ServiceRequest):
    ServiceId: ResourceId
    InstanceId: ResourceId
    Status: CustomHealthStatus


class UpdatePrivateDnsNamespaceRequest(ServiceRequest):
    Id: ResourceId
    UpdaterRequestId: Optional[ResourceId]
    Namespace: PrivateDnsNamespaceChange


class UpdatePrivateDnsNamespaceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class UpdatePublicDnsNamespaceRequest(ServiceRequest):
    Id: ResourceId
    UpdaterRequestId: Optional[ResourceId]
    Namespace: PublicDnsNamespaceChange


class UpdatePublicDnsNamespaceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class UpdateServiceRequest(ServiceRequest):
    Id: ResourceId
    Service: ServiceChange


class UpdateServiceResponse(TypedDict, total=False):
    OperationId: Optional[OperationId]


class ServicediscoveryApi:

    service = "servicediscovery"
    version = "2017-03-14"

    @handler("CreateHttpNamespace")
    def create_http_namespace(
        self,
        context: RequestContext,
        name: NamespaceNameHttp,
        creator_request_id: ResourceId = None,
        description: ResourceDescription = None,
        tags: TagList = None,
    ) -> CreateHttpNamespaceResponse:
        raise NotImplementedError

    @handler("CreatePrivateDnsNamespace")
    def create_private_dns_namespace(
        self,
        context: RequestContext,
        name: NamespaceNamePrivate,
        vpc: ResourceId,
        creator_request_id: ResourceId = None,
        description: ResourceDescription = None,
        tags: TagList = None,
        properties: PrivateDnsNamespaceProperties = None,
    ) -> CreatePrivateDnsNamespaceResponse:
        raise NotImplementedError

    @handler("CreatePublicDnsNamespace")
    def create_public_dns_namespace(
        self,
        context: RequestContext,
        name: NamespaceNamePublic,
        creator_request_id: ResourceId = None,
        description: ResourceDescription = None,
        tags: TagList = None,
        properties: PublicDnsNamespaceProperties = None,
    ) -> CreatePublicDnsNamespaceResponse:
        raise NotImplementedError

    @handler("CreateService", expand=False)
    def create_service(
        self, context: RequestContext, request: CreateServiceRequest
    ) -> CreateServiceResponse:
        raise NotImplementedError

    @handler("DeleteNamespace")
    def delete_namespace(self, context: RequestContext, id: ResourceId) -> DeleteNamespaceResponse:
        raise NotImplementedError

    @handler("DeleteService")
    def delete_service(self, context: RequestContext, id: ResourceId) -> DeleteServiceResponse:
        raise NotImplementedError

    @handler("DeregisterInstance")
    def deregister_instance(
        self, context: RequestContext, service_id: ResourceId, instance_id: ResourceId
    ) -> DeregisterInstanceResponse:
        raise NotImplementedError

    @handler("DiscoverInstances")
    def discover_instances(
        self,
        context: RequestContext,
        namespace_name: NamespaceName,
        service_name: ServiceName,
        max_results: DiscoverMaxResults = None,
        query_parameters: Attributes = None,
        optional_parameters: Attributes = None,
        health_status: HealthStatusFilter = None,
    ) -> DiscoverInstancesResponse:
        raise NotImplementedError

    @handler("GetInstance")
    def get_instance(
        self, context: RequestContext, service_id: ResourceId, instance_id: ResourceId
    ) -> GetInstanceResponse:
        raise NotImplementedError

    @handler("GetInstancesHealthStatus")
    def get_instances_health_status(
        self,
        context: RequestContext,
        service_id: ResourceId,
        instances: InstanceIdList = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> GetInstancesHealthStatusResponse:
        raise NotImplementedError

    @handler("GetNamespace")
    def get_namespace(self, context: RequestContext, id: ResourceId) -> GetNamespaceResponse:
        raise NotImplementedError

    @handler("GetOperation")
    def get_operation(
        self, context: RequestContext, operation_id: ResourceId
    ) -> GetOperationResponse:
        raise NotImplementedError

    @handler("GetService")
    def get_service(self, context: RequestContext, id: ResourceId) -> GetServiceResponse:
        raise NotImplementedError

    @handler("ListInstances")
    def list_instances(
        self,
        context: RequestContext,
        service_id: ResourceId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListInstancesResponse:
        raise NotImplementedError

    @handler("ListNamespaces")
    def list_namespaces(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        filters: NamespaceFilters = None,
    ) -> ListNamespacesResponse:
        raise NotImplementedError

    @handler("ListOperations")
    def list_operations(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        filters: OperationFilters = None,
    ) -> ListOperationsResponse:
        raise NotImplementedError

    @handler("ListServices")
    def list_services(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        filters: ServiceFilters = None,
    ) -> ListServicesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("RegisterInstance")
    def register_instance(
        self,
        context: RequestContext,
        service_id: ResourceId,
        instance_id: InstanceId,
        attributes: Attributes,
        creator_request_id: ResourceId = None,
    ) -> RegisterInstanceResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateHttpNamespace")
    def update_http_namespace(
        self,
        context: RequestContext,
        id: ResourceId,
        namespace: HttpNamespaceChange,
        updater_request_id: ResourceId = None,
    ) -> UpdateHttpNamespaceResponse:
        raise NotImplementedError

    @handler("UpdateInstanceCustomHealthStatus")
    def update_instance_custom_health_status(
        self,
        context: RequestContext,
        service_id: ResourceId,
        instance_id: ResourceId,
        status: CustomHealthStatus,
    ) -> None:
        raise NotImplementedError

    @handler("UpdatePrivateDnsNamespace")
    def update_private_dns_namespace(
        self,
        context: RequestContext,
        id: ResourceId,
        namespace: PrivateDnsNamespaceChange,
        updater_request_id: ResourceId = None,
    ) -> UpdatePrivateDnsNamespaceResponse:
        raise NotImplementedError

    @handler("UpdatePublicDnsNamespace")
    def update_public_dns_namespace(
        self,
        context: RequestContext,
        id: ResourceId,
        namespace: PublicDnsNamespaceChange,
        updater_request_id: ResourceId = None,
    ) -> UpdatePublicDnsNamespaceResponse:
        raise NotImplementedError

    @handler("UpdateService")
    def update_service(
        self, context: RequestContext, id: ResourceId, service: ServiceChange
    ) -> UpdateServiceResponse:
        raise NotImplementedError
