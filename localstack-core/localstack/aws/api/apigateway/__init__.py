from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from typing import IO, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
DocumentationPartLocationStatusCode = str
Double = float
Integer = int
NullableBoolean = bool
NullableInteger = int
ProviderARN = str
StatusCode = str
String = str


class AccessAssociationSourceType(StrEnum):
    VPCE = "VPCE"


class ApiKeySourceType(StrEnum):
    HEADER = "HEADER"
    AUTHORIZER = "AUTHORIZER"


class ApiKeysFormat(StrEnum):
    csv = "csv"


class ApiStatus(StrEnum):
    UPDATING = "UPDATING"
    AVAILABLE = "AVAILABLE"
    PENDING = "PENDING"
    FAILED = "FAILED"


class AuthorizerType(StrEnum):
    TOKEN = "TOKEN"
    REQUEST = "REQUEST"
    COGNITO_USER_POOLS = "COGNITO_USER_POOLS"


class CacheClusterSize(StrEnum):
    i_0_5 = "0.5"
    i_1_6 = "1.6"
    i_6_1 = "6.1"
    i_13_5 = "13.5"
    i_28_4 = "28.4"
    i_58_2 = "58.2"
    i_118 = "118"
    i_237 = "237"


class CacheClusterStatus(StrEnum):
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    AVAILABLE = "AVAILABLE"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    FLUSH_IN_PROGRESS = "FLUSH_IN_PROGRESS"


class ConnectionType(StrEnum):
    INTERNET = "INTERNET"
    VPC_LINK = "VPC_LINK"


class ContentHandlingStrategy(StrEnum):
    CONVERT_TO_BINARY = "CONVERT_TO_BINARY"
    CONVERT_TO_TEXT = "CONVERT_TO_TEXT"


class DocumentationPartType(StrEnum):
    API = "API"
    AUTHORIZER = "AUTHORIZER"
    MODEL = "MODEL"
    RESOURCE = "RESOURCE"
    METHOD = "METHOD"
    PATH_PARAMETER = "PATH_PARAMETER"
    QUERY_PARAMETER = "QUERY_PARAMETER"
    REQUEST_HEADER = "REQUEST_HEADER"
    REQUEST_BODY = "REQUEST_BODY"
    RESPONSE = "RESPONSE"
    RESPONSE_HEADER = "RESPONSE_HEADER"
    RESPONSE_BODY = "RESPONSE_BODY"


class DomainNameStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    UPDATING = "UPDATING"
    PENDING = "PENDING"
    PENDING_CERTIFICATE_REIMPORT = "PENDING_CERTIFICATE_REIMPORT"
    PENDING_OWNERSHIP_VERIFICATION = "PENDING_OWNERSHIP_VERIFICATION"
    FAILED = "FAILED"


class EndpointAccessMode(StrEnum):
    BASIC = "BASIC"
    STRICT = "STRICT"


class EndpointType(StrEnum):
    REGIONAL = "REGIONAL"
    EDGE = "EDGE"
    PRIVATE = "PRIVATE"


class GatewayResponseType(StrEnum):
    DEFAULT_4XX = "DEFAULT_4XX"
    DEFAULT_5XX = "DEFAULT_5XX"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    UNAUTHORIZED = "UNAUTHORIZED"
    INVALID_API_KEY = "INVALID_API_KEY"
    ACCESS_DENIED = "ACCESS_DENIED"
    AUTHORIZER_FAILURE = "AUTHORIZER_FAILURE"
    AUTHORIZER_CONFIGURATION_ERROR = "AUTHORIZER_CONFIGURATION_ERROR"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    EXPIRED_TOKEN = "EXPIRED_TOKEN"
    MISSING_AUTHENTICATION_TOKEN = "MISSING_AUTHENTICATION_TOKEN"
    INTEGRATION_FAILURE = "INTEGRATION_FAILURE"
    INTEGRATION_TIMEOUT = "INTEGRATION_TIMEOUT"
    API_CONFIGURATION_ERROR = "API_CONFIGURATION_ERROR"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    BAD_REQUEST_PARAMETERS = "BAD_REQUEST_PARAMETERS"
    BAD_REQUEST_BODY = "BAD_REQUEST_BODY"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    THROTTLED = "THROTTLED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    WAF_FILTERED = "WAF_FILTERED"


class IntegrationType(StrEnum):
    HTTP = "HTTP"
    AWS = "AWS"
    MOCK = "MOCK"
    HTTP_PROXY = "HTTP_PROXY"
    AWS_PROXY = "AWS_PROXY"


class IpAddressType(StrEnum):
    ipv4 = "ipv4"
    dualstack = "dualstack"


class LocationStatusType(StrEnum):
    DOCUMENTED = "DOCUMENTED"
    UNDOCUMENTED = "UNDOCUMENTED"


class Op(StrEnum):
    add = "add"
    remove = "remove"
    replace = "replace"
    move = "move"
    copy = "copy"
    test = "test"


class PutMode(StrEnum):
    merge = "merge"
    overwrite = "overwrite"


class QuotaPeriodType(StrEnum):
    DAY = "DAY"
    WEEK = "WEEK"
    MONTH = "MONTH"


class ResourceOwner(StrEnum):
    SELF = "SELF"
    OTHER_ACCOUNTS = "OTHER_ACCOUNTS"


class ResponseTransferMode(StrEnum):
    BUFFERED = "BUFFERED"
    STREAM = "STREAM"


class RoutingMode(StrEnum):
    BASE_PATH_MAPPING_ONLY = "BASE_PATH_MAPPING_ONLY"
    ROUTING_RULE_ONLY = "ROUTING_RULE_ONLY"
    ROUTING_RULE_THEN_BASE_PATH_MAPPING = "ROUTING_RULE_THEN_BASE_PATH_MAPPING"


class SecurityPolicy(StrEnum):
    TLS_1_0 = "TLS_1_0"
    TLS_1_2 = "TLS_1_2"
    SecurityPolicy_TLS13_1_3_2025_09 = "SecurityPolicy_TLS13_1_3_2025_09"
    SecurityPolicy_TLS13_1_3_FIPS_2025_09 = "SecurityPolicy_TLS13_1_3_FIPS_2025_09"
    SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09 = "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09"
    SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09 = "SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09"
    SecurityPolicy_TLS13_1_2_PQ_2025_09 = "SecurityPolicy_TLS13_1_2_PQ_2025_09"
    SecurityPolicy_TLS13_1_2_2021_06 = "SecurityPolicy_TLS13_1_2_2021_06"
    SecurityPolicy_TLS13_2025_EDGE = "SecurityPolicy_TLS13_2025_EDGE"
    SecurityPolicy_TLS12_PFS_2025_EDGE = "SecurityPolicy_TLS12_PFS_2025_EDGE"
    SecurityPolicy_TLS12_2018_EDGE = "SecurityPolicy_TLS12_2018_EDGE"


class UnauthorizedCacheControlHeaderStrategy(StrEnum):
    FAIL_WITH_403 = "FAIL_WITH_403"
    SUCCEED_WITH_RESPONSE_HEADER = "SUCCEED_WITH_RESPONSE_HEADER"
    SUCCEED_WITHOUT_RESPONSE_HEADER = "SUCCEED_WITHOUT_RESPONSE_HEADER"


class VpcLinkStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    PENDING = "PENDING"
    DELETING = "DELETING"
    FAILED = "FAILED"


class BadRequestException(ServiceException):
    code: str = "BadRequestException"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 409


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 429
    retryAfterSeconds: String | None


class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 404


class ServiceUnavailableException(ServiceException):
    code: str = "ServiceUnavailableException"
    sender_fault: bool = False
    status_code: int = 503
    retryAfterSeconds: String | None


class TooManyRequestsException(ServiceException):
    code: str = "TooManyRequestsException"
    sender_fault: bool = False
    status_code: int = 429
    retryAfterSeconds: String | None


class UnauthorizedException(ServiceException):
    code: str = "UnauthorizedException"
    sender_fault: bool = False
    status_code: int = 401


class AccessLogSettings(TypedDict, total=False):
    format: String | None
    destinationArn: String | None


ListOfString = list[String]


class ThrottleSettings(TypedDict, total=False):
    burstLimit: Integer | None
    rateLimit: Double | None


class Account(TypedDict, total=False):
    cloudwatchRoleArn: String | None
    throttleSettings: ThrottleSettings | None
    features: ListOfString | None
    apiKeyVersion: String | None


MapOfStringToString = dict[String, String]
Timestamp = datetime


class ApiKey(TypedDict, total=False):
    id: String | None
    value: String | None
    name: String | None
    customerId: String | None
    description: String | None
    enabled: Boolean | None
    createdDate: Timestamp | None
    lastUpdatedDate: Timestamp | None
    stageKeys: ListOfString | None
    tags: MapOfStringToString | None


class ApiKeyIds(TypedDict, total=False):
    ids: ListOfString | None
    warnings: ListOfString | None


ListOfApiKey = list[ApiKey]


class ApiKeys(TypedDict, total=False):
    warnings: ListOfString | None
    position: String | None
    items: ListOfApiKey | None


MapOfApiStageThrottleSettings = dict[String, ThrottleSettings]


class ApiStage(TypedDict, total=False):
    apiId: String | None
    stage: String | None
    throttle: MapOfApiStageThrottleSettings | None


ListOfARNs = list[ProviderARN]


class Authorizer(TypedDict, total=False):
    id: String | None
    name: String | None
    type: AuthorizerType | None
    providerARNs: ListOfARNs | None
    authType: String | None
    authorizerUri: String | None
    authorizerCredentials: String | None
    identitySource: String | None
    identityValidationExpression: String | None
    authorizerResultTtlInSeconds: NullableInteger | None


ListOfAuthorizer = list[Authorizer]


class Authorizers(TypedDict, total=False):
    position: String | None
    items: ListOfAuthorizer | None


class BasePathMapping(TypedDict, total=False):
    basePath: String | None
    restApiId: String | None
    stage: String | None


ListOfBasePathMapping = list[BasePathMapping]


class BasePathMappings(TypedDict, total=False):
    position: String | None
    items: ListOfBasePathMapping | None


Blob = bytes


class CanarySettings(TypedDict, total=False):
    percentTraffic: Double | None
    deploymentId: String | None
    stageVariableOverrides: MapOfStringToString | None
    useStageCache: Boolean | None


class ClientCertificate(TypedDict, total=False):
    clientCertificateId: String | None
    description: String | None
    pemEncodedCertificate: String | None
    createdDate: Timestamp | None
    expirationDate: Timestamp | None
    tags: MapOfStringToString | None


ListOfClientCertificate = list[ClientCertificate]


class ClientCertificates(TypedDict, total=False):
    position: String | None
    items: ListOfClientCertificate | None


class StageKey(TypedDict, total=False):
    restApiId: String | None
    stageName: String | None


ListOfStageKeys = list[StageKey]


class CreateApiKeyRequest(ServiceRequest):
    name: String | None
    description: String | None
    enabled: Boolean | None
    generateDistinctId: Boolean | None
    value: String | None
    stageKeys: ListOfStageKeys | None
    customerId: String | None
    tags: MapOfStringToString | None


class CreateAuthorizerRequest(TypedDict, total=False):
    restApiId: String
    name: String
    type: AuthorizerType
    providerARNs: ListOfARNs | None
    authType: String | None
    authorizerUri: String | None
    authorizerCredentials: String | None
    identitySource: String | None
    identityValidationExpression: String | None
    authorizerResultTtlInSeconds: NullableInteger | None


class CreateBasePathMappingRequest(ServiceRequest):
    domainName: String
    domainNameId: String | None
    basePath: String | None
    restApiId: String
    stage: String | None


class DeploymentCanarySettings(TypedDict, total=False):
    percentTraffic: Double | None
    stageVariableOverrides: MapOfStringToString | None
    useStageCache: Boolean | None


class CreateDeploymentRequest(ServiceRequest):
    restApiId: String
    stageName: String | None
    stageDescription: String | None
    description: String | None
    cacheClusterEnabled: NullableBoolean | None
    cacheClusterSize: CacheClusterSize | None
    variables: MapOfStringToString | None
    canarySettings: DeploymentCanarySettings | None
    tracingEnabled: NullableBoolean | None


class DocumentationPartLocation(TypedDict, total=False):
    type: DocumentationPartType
    path: String | None
    method: String | None
    statusCode: DocumentationPartLocationStatusCode | None
    name: String | None


class CreateDocumentationPartRequest(ServiceRequest):
    restApiId: String
    location: DocumentationPartLocation
    properties: String


class CreateDocumentationVersionRequest(ServiceRequest):
    restApiId: String
    documentationVersion: String
    stageName: String | None
    description: String | None


class CreateDomainNameAccessAssociationRequest(ServiceRequest):
    domainNameArn: String
    accessAssociationSourceType: AccessAssociationSourceType
    accessAssociationSource: String
    tags: MapOfStringToString | None


class MutualTlsAuthenticationInput(TypedDict, total=False):
    truststoreUri: String | None
    truststoreVersion: String | None


ListOfEndpointType = list[EndpointType]


class EndpointConfiguration(TypedDict, total=False):
    types: ListOfEndpointType | None
    ipAddressType: IpAddressType | None
    vpcEndpointIds: ListOfString | None


class CreateDomainNameRequest(ServiceRequest):
    domainName: String
    certificateName: String | None
    certificateBody: String | None
    certificatePrivateKey: String | None
    certificateChain: String | None
    certificateArn: String | None
    regionalCertificateName: String | None
    regionalCertificateArn: String | None
    endpointConfiguration: EndpointConfiguration | None
    tags: MapOfStringToString | None
    securityPolicy: SecurityPolicy | None
    endpointAccessMode: EndpointAccessMode | None
    mutualTlsAuthentication: MutualTlsAuthenticationInput | None
    ownershipVerificationCertificateArn: String | None
    policy: String | None
    routingMode: RoutingMode | None


class CreateModelRequest(ServiceRequest):
    restApiId: String
    name: String
    description: String | None
    schema: String | None
    contentType: String


class CreateRequestValidatorRequest(ServiceRequest):
    restApiId: String
    name: String | None
    validateRequestBody: Boolean | None
    validateRequestParameters: Boolean | None


class CreateResourceRequest(ServiceRequest):
    restApiId: String
    parentId: String
    pathPart: String


class CreateRestApiRequest(ServiceRequest):
    name: String
    description: String | None
    version: String | None
    cloneFrom: String | None
    binaryMediaTypes: ListOfString | None
    minimumCompressionSize: NullableInteger | None
    apiKeySource: ApiKeySourceType | None
    endpointConfiguration: EndpointConfiguration | None
    policy: String | None
    tags: MapOfStringToString | None
    disableExecuteApiEndpoint: Boolean | None
    securityPolicy: SecurityPolicy | None
    endpointAccessMode: EndpointAccessMode | None


class CreateStageRequest(ServiceRequest):
    restApiId: String
    stageName: String
    deploymentId: String
    description: String | None
    cacheClusterEnabled: Boolean | None
    cacheClusterSize: CacheClusterSize | None
    variables: MapOfStringToString | None
    documentationVersion: String | None
    canarySettings: CanarySettings | None
    tracingEnabled: Boolean | None
    tags: MapOfStringToString | None


class CreateUsagePlanKeyRequest(ServiceRequest):
    usagePlanId: String
    keyId: String
    keyType: String


class QuotaSettings(TypedDict, total=False):
    limit: Integer | None
    offset: Integer | None
    period: QuotaPeriodType | None


ListOfApiStage = list[ApiStage]


class CreateUsagePlanRequest(ServiceRequest):
    name: String
    description: String | None
    apiStages: ListOfApiStage | None
    throttle: ThrottleSettings | None
    quota: QuotaSettings | None
    tags: MapOfStringToString | None


class CreateVpcLinkRequest(ServiceRequest):
    name: String
    description: String | None
    targetArns: ListOfString
    tags: MapOfStringToString | None


class DeleteApiKeyRequest(ServiceRequest):
    apiKey: String


class DeleteAuthorizerRequest(ServiceRequest):
    restApiId: String
    authorizerId: String


class DeleteBasePathMappingRequest(ServiceRequest):
    domainName: String
    domainNameId: String | None
    basePath: String


class DeleteClientCertificateRequest(ServiceRequest):
    clientCertificateId: String


class DeleteDeploymentRequest(ServiceRequest):
    restApiId: String
    deploymentId: String


class DeleteDocumentationPartRequest(ServiceRequest):
    restApiId: String
    documentationPartId: String


class DeleteDocumentationVersionRequest(ServiceRequest):
    restApiId: String
    documentationVersion: String


class DeleteDomainNameAccessAssociationRequest(ServiceRequest):
    domainNameAccessAssociationArn: String


class DeleteDomainNameRequest(ServiceRequest):
    domainName: String
    domainNameId: String | None


class DeleteGatewayResponseRequest(ServiceRequest):
    restApiId: String
    responseType: GatewayResponseType


class DeleteIntegrationRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String


class DeleteIntegrationResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode


class DeleteMethodRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String


class DeleteMethodResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode


class DeleteModelRequest(ServiceRequest):
    restApiId: String
    modelName: String


class DeleteRequestValidatorRequest(ServiceRequest):
    restApiId: String
    requestValidatorId: String


class DeleteResourceRequest(ServiceRequest):
    restApiId: String
    resourceId: String


class DeleteRestApiRequest(ServiceRequest):
    restApiId: String


class DeleteStageRequest(ServiceRequest):
    restApiId: String
    stageName: String


class DeleteUsagePlanKeyRequest(ServiceRequest):
    usagePlanId: String
    keyId: String


class DeleteUsagePlanRequest(ServiceRequest):
    usagePlanId: String


class DeleteVpcLinkRequest(ServiceRequest):
    vpcLinkId: String


class MethodSnapshot(TypedDict, total=False):
    authorizationType: String | None
    apiKeyRequired: Boolean | None


MapOfMethodSnapshot = dict[String, MethodSnapshot]
PathToMapOfMethodSnapshot = dict[String, MapOfMethodSnapshot]


class Deployment(TypedDict, total=False):
    id: String | None
    description: String | None
    createdDate: Timestamp | None
    apiSummary: PathToMapOfMethodSnapshot | None


ListOfDeployment = list[Deployment]


class Deployments(TypedDict, total=False):
    position: String | None
    items: ListOfDeployment | None


class DocumentationPart(TypedDict, total=False):
    id: String | None
    location: DocumentationPartLocation | None
    properties: String | None


class DocumentationPartIds(TypedDict, total=False):
    ids: ListOfString | None
    warnings: ListOfString | None


ListOfDocumentationPart = list[DocumentationPart]


class DocumentationParts(TypedDict, total=False):
    position: String | None
    items: ListOfDocumentationPart | None


class DocumentationVersion(TypedDict, total=False):
    version: String | None
    createdDate: Timestamp | None
    description: String | None


ListOfDocumentationVersion = list[DocumentationVersion]


class DocumentationVersions(TypedDict, total=False):
    position: String | None
    items: ListOfDocumentationVersion | None


class MutualTlsAuthentication(TypedDict, total=False):
    truststoreUri: String | None
    truststoreVersion: String | None
    truststoreWarnings: ListOfString | None


class DomainName(TypedDict, total=False):
    domainName: String | None
    domainNameId: String | None
    domainNameArn: String | None
    certificateName: String | None
    certificateArn: String | None
    certificateUploadDate: Timestamp | None
    regionalDomainName: String | None
    regionalHostedZoneId: String | None
    regionalCertificateName: String | None
    regionalCertificateArn: String | None
    distributionDomainName: String | None
    distributionHostedZoneId: String | None
    endpointConfiguration: EndpointConfiguration | None
    domainNameStatus: DomainNameStatus | None
    domainNameStatusMessage: String | None
    securityPolicy: SecurityPolicy | None
    endpointAccessMode: EndpointAccessMode | None
    tags: MapOfStringToString | None
    mutualTlsAuthentication: MutualTlsAuthentication | None
    ownershipVerificationCertificateArn: String | None
    managementPolicy: String | None
    policy: String | None
    routingMode: RoutingMode | None


class DomainNameAccessAssociation(TypedDict, total=False):
    domainNameAccessAssociationArn: String | None
    domainNameArn: String | None
    accessAssociationSourceType: AccessAssociationSourceType | None
    accessAssociationSource: String | None
    tags: MapOfStringToString | None


ListOfDomainNameAccessAssociation = list[DomainNameAccessAssociation]


class DomainNameAccessAssociations(TypedDict, total=False):
    position: String | None
    items: ListOfDomainNameAccessAssociation | None


ListOfDomainName = list[DomainName]


class DomainNames(TypedDict, total=False):
    position: String | None
    items: ListOfDomainName | None


class ExportResponse(TypedDict, total=False):
    body: Blob | IO[Blob] | Iterable[Blob] | None
    contentType: String | None
    contentDisposition: String | None


class FlushStageAuthorizersCacheRequest(ServiceRequest):
    restApiId: String
    stageName: String


class FlushStageCacheRequest(ServiceRequest):
    restApiId: String
    stageName: String


class GatewayResponse(TypedDict, total=False):
    responseType: GatewayResponseType | None
    statusCode: StatusCode | None
    responseParameters: MapOfStringToString | None
    responseTemplates: MapOfStringToString | None
    defaultResponse: Boolean | None


ListOfGatewayResponse = list[GatewayResponse]


class GatewayResponses(TypedDict, total=False):
    position: String | None
    items: ListOfGatewayResponse | None


class GenerateClientCertificateRequest(ServiceRequest):
    description: String | None
    tags: MapOfStringToString | None


class GetAccountRequest(ServiceRequest):
    pass


class GetApiKeyRequest(ServiceRequest):
    apiKey: String
    includeValue: NullableBoolean | None


class GetApiKeysRequest(ServiceRequest):
    position: String | None
    limit: NullableInteger | None
    nameQuery: String | None
    customerId: String | None
    includeValues: NullableBoolean | None


class GetAuthorizerRequest(ServiceRequest):
    restApiId: String
    authorizerId: String


class GetAuthorizersRequest(ServiceRequest):
    restApiId: String
    position: String | None
    limit: NullableInteger | None


class GetBasePathMappingRequest(ServiceRequest):
    domainName: String
    domainNameId: String | None
    basePath: String


class GetBasePathMappingsRequest(ServiceRequest):
    domainName: String
    domainNameId: String | None
    position: String | None
    limit: NullableInteger | None


class GetClientCertificateRequest(ServiceRequest):
    clientCertificateId: String


class GetClientCertificatesRequest(ServiceRequest):
    position: String | None
    limit: NullableInteger | None


class GetDeploymentRequest(ServiceRequest):
    restApiId: String
    deploymentId: String
    embed: ListOfString | None


class GetDeploymentsRequest(ServiceRequest):
    restApiId: String
    position: String | None
    limit: NullableInteger | None


class GetDocumentationPartRequest(ServiceRequest):
    restApiId: String
    documentationPartId: String


class GetDocumentationPartsRequest(TypedDict, total=False):
    restApiId: String
    type: DocumentationPartType | None
    nameQuery: String | None
    path: String | None
    position: String | None
    limit: NullableInteger | None
    locationStatus: LocationStatusType | None


class GetDocumentationVersionRequest(ServiceRequest):
    restApiId: String
    documentationVersion: String


class GetDocumentationVersionsRequest(ServiceRequest):
    restApiId: String
    position: String | None
    limit: NullableInteger | None


class GetDomainNameAccessAssociationsRequest(ServiceRequest):
    position: String | None
    limit: NullableInteger | None
    resourceOwner: ResourceOwner | None


class GetDomainNameRequest(ServiceRequest):
    domainName: String
    domainNameId: String | None


class GetDomainNamesRequest(ServiceRequest):
    position: String | None
    limit: NullableInteger | None
    resourceOwner: ResourceOwner | None


class GetExportRequest(ServiceRequest):
    restApiId: String
    stageName: String
    exportType: String
    parameters: MapOfStringToString | None
    accepts: String | None


class GetGatewayResponseRequest(ServiceRequest):
    restApiId: String
    responseType: GatewayResponseType


class GetGatewayResponsesRequest(ServiceRequest):
    restApiId: String
    position: String | None
    limit: NullableInteger | None


class GetIntegrationRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String


class GetIntegrationResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode


class GetMethodRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String


class GetMethodResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode


class GetModelRequest(ServiceRequest):
    restApiId: String
    modelName: String
    flatten: Boolean | None


class GetModelTemplateRequest(ServiceRequest):
    restApiId: String
    modelName: String


class GetModelsRequest(ServiceRequest):
    restApiId: String
    position: String | None
    limit: NullableInteger | None


class GetRequestValidatorRequest(ServiceRequest):
    restApiId: String
    requestValidatorId: String


class GetRequestValidatorsRequest(ServiceRequest):
    restApiId: String
    position: String | None
    limit: NullableInteger | None


class GetResourceRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    embed: ListOfString | None


class GetResourcesRequest(ServiceRequest):
    restApiId: String
    position: String | None
    limit: NullableInteger | None
    embed: ListOfString | None


class GetRestApiRequest(ServiceRequest):
    restApiId: String


class GetRestApisRequest(ServiceRequest):
    position: String | None
    limit: NullableInteger | None


class GetSdkRequest(ServiceRequest):
    restApiId: String
    stageName: String
    sdkType: String
    parameters: MapOfStringToString | None


class GetSdkTypeRequest(ServiceRequest):
    id: String


class GetSdkTypesRequest(ServiceRequest):
    position: String | None
    limit: NullableInteger | None


class GetStageRequest(ServiceRequest):
    restApiId: String
    stageName: String


class GetStagesRequest(ServiceRequest):
    restApiId: String
    deploymentId: String | None


class GetTagsRequest(ServiceRequest):
    resourceArn: String
    position: String | None
    limit: NullableInteger | None


class GetUsagePlanKeyRequest(ServiceRequest):
    usagePlanId: String
    keyId: String


class GetUsagePlanKeysRequest(ServiceRequest):
    usagePlanId: String
    position: String | None
    limit: NullableInteger | None
    nameQuery: String | None


class GetUsagePlanRequest(ServiceRequest):
    usagePlanId: String


class GetUsagePlansRequest(ServiceRequest):
    position: String | None
    keyId: String | None
    limit: NullableInteger | None


class GetUsageRequest(ServiceRequest):
    usagePlanId: String
    keyId: String | None
    startDate: String
    endDate: String
    position: String | None
    limit: NullableInteger | None


class GetVpcLinkRequest(ServiceRequest):
    vpcLinkId: String


class GetVpcLinksRequest(ServiceRequest):
    position: String | None
    limit: NullableInteger | None


class ImportApiKeysRequest(ServiceRequest):
    body: IO[Blob]
    format: ApiKeysFormat
    failOnWarnings: Boolean | None


class ImportDocumentationPartsRequest(ServiceRequest):
    body: IO[Blob]
    restApiId: String
    mode: PutMode | None
    failOnWarnings: Boolean | None


class ImportRestApiRequest(ServiceRequest):
    body: IO[Blob]
    failOnWarnings: Boolean | None
    parameters: MapOfStringToString | None


class TlsConfig(TypedDict, total=False):
    insecureSkipVerification: Boolean | None


class IntegrationResponse(TypedDict, total=False):
    statusCode: StatusCode | None
    selectionPattern: String | None
    responseParameters: MapOfStringToString | None
    responseTemplates: MapOfStringToString | None
    contentHandling: ContentHandlingStrategy | None


MapOfIntegrationResponse = dict[String, IntegrationResponse]


class Integration(TypedDict, total=False):
    type: IntegrationType | None
    httpMethod: String | None
    uri: String | None
    connectionType: ConnectionType | None
    connectionId: String | None
    credentials: String | None
    requestParameters: MapOfStringToString | None
    requestTemplates: MapOfStringToString | None
    passthroughBehavior: String | None
    contentHandling: ContentHandlingStrategy | None
    timeoutInMillis: Integer | None
    cacheNamespace: String | None
    cacheKeyParameters: ListOfString | None
    integrationResponses: MapOfIntegrationResponse | None
    tlsConfig: TlsConfig | None
    responseTransferMode: ResponseTransferMode | None
    integrationTarget: String | None


Long = int
ListOfLong = list[Long]


class Model(TypedDict, total=False):
    id: String | None
    name: String | None
    description: String | None
    schema: String | None
    contentType: String | None


ListOfModel = list[Model]
PatchOperation = TypedDict(
    "PatchOperation",
    {
        "op": Op | None,
        "path": String | None,
        "value": String | None,
        "from": String | None,
    },
    total=False,
)
ListOfPatchOperation = list[PatchOperation]


class RequestValidator(TypedDict, total=False):
    id: String | None
    name: String | None
    validateRequestBody: Boolean | None
    validateRequestParameters: Boolean | None


ListOfRequestValidator = list[RequestValidator]
MapOfStringToBoolean = dict[String, NullableBoolean]


class MethodResponse(TypedDict, total=False):
    statusCode: StatusCode | None
    responseParameters: MapOfStringToBoolean | None
    responseModels: MapOfStringToString | None


MapOfMethodResponse = dict[String, MethodResponse]


class Method(TypedDict, total=False):
    httpMethod: String | None
    authorizationType: String | None
    authorizerId: String | None
    apiKeyRequired: NullableBoolean | None
    requestValidatorId: String | None
    operationName: String | None
    requestParameters: MapOfStringToBoolean | None
    requestModels: MapOfStringToString | None
    methodResponses: MapOfMethodResponse | None
    methodIntegration: Integration | None
    authorizationScopes: ListOfString | None


MapOfMethod = dict[String, Method]


class Resource(TypedDict, total=False):
    id: String | None
    parentId: String | None
    pathPart: String | None
    path: String | None
    resourceMethods: MapOfMethod | None


ListOfResource = list[Resource]


class RestApi(TypedDict, total=False):
    id: String | None
    name: String | None
    description: String | None
    createdDate: Timestamp | None
    version: String | None
    warnings: ListOfString | None
    binaryMediaTypes: ListOfString | None
    minimumCompressionSize: NullableInteger | None
    apiKeySource: ApiKeySourceType | None
    endpointConfiguration: EndpointConfiguration | None
    policy: String | None
    tags: MapOfStringToString | None
    disableExecuteApiEndpoint: Boolean | None
    rootResourceId: String | None
    securityPolicy: SecurityPolicy | None
    endpointAccessMode: EndpointAccessMode | None
    apiStatus: ApiStatus | None
    apiStatusMessage: String | None


ListOfRestApi = list[RestApi]


class SdkConfigurationProperty(TypedDict, total=False):
    name: String | None
    friendlyName: String | None
    description: String | None
    required: Boolean | None
    defaultValue: String | None


ListOfSdkConfigurationProperty = list[SdkConfigurationProperty]


class SdkType(TypedDict, total=False):
    id: String | None
    friendlyName: String | None
    description: String | None
    configurationProperties: ListOfSdkConfigurationProperty | None


ListOfSdkType = list[SdkType]


class MethodSetting(TypedDict, total=False):
    metricsEnabled: Boolean | None
    loggingLevel: String | None
    dataTraceEnabled: Boolean | None
    throttlingBurstLimit: Integer | None
    throttlingRateLimit: Double | None
    cachingEnabled: Boolean | None
    cacheTtlInSeconds: Integer | None
    cacheDataEncrypted: Boolean | None
    requireAuthorizationForCacheControl: Boolean | None
    unauthorizedCacheControlHeaderStrategy: UnauthorizedCacheControlHeaderStrategy | None


MapOfMethodSettings = dict[String, MethodSetting]


class Stage(TypedDict, total=False):
    deploymentId: String | None
    clientCertificateId: String | None
    stageName: String | None
    description: String | None
    cacheClusterEnabled: Boolean | None
    cacheClusterSize: CacheClusterSize | None
    cacheClusterStatus: CacheClusterStatus | None
    methodSettings: MapOfMethodSettings | None
    variables: MapOfStringToString | None
    documentationVersion: String | None
    accessLogSettings: AccessLogSettings | None
    canarySettings: CanarySettings | None
    tracingEnabled: Boolean | None
    webAclArn: String | None
    tags: MapOfStringToString | None
    createdDate: Timestamp | None
    lastUpdatedDate: Timestamp | None


ListOfStage = list[Stage]
ListOfUsage = list[ListOfLong]


class UsagePlan(TypedDict, total=False):
    id: String | None
    name: String | None
    description: String | None
    apiStages: ListOfApiStage | None
    throttle: ThrottleSettings | None
    quota: QuotaSettings | None
    productCode: String | None
    tags: MapOfStringToString | None


ListOfUsagePlan = list[UsagePlan]


class UsagePlanKey(TypedDict, total=False):
    id: String | None
    type: String | None
    value: String | None
    name: String | None


ListOfUsagePlanKey = list[UsagePlanKey]


class VpcLink(TypedDict, total=False):
    id: String | None
    name: String | None
    description: String | None
    targetArns: ListOfString | None
    status: VpcLinkStatus | None
    statusMessage: String | None
    tags: MapOfStringToString | None


ListOfVpcLink = list[VpcLink]
MapOfKeyUsages = dict[String, ListOfUsage]
MapOfStringToList = dict[String, ListOfString]


class Models(TypedDict, total=False):
    position: String | None
    items: ListOfModel | None


class PutGatewayResponseRequest(ServiceRequest):
    restApiId: String
    responseType: GatewayResponseType
    statusCode: StatusCode | None
    responseParameters: MapOfStringToString | None
    responseTemplates: MapOfStringToString | None


class PutIntegrationRequest(TypedDict, total=False):
    restApiId: String
    resourceId: String
    httpMethod: String
    type: IntegrationType
    integrationHttpMethod: String | None
    uri: String | None
    connectionType: ConnectionType | None
    connectionId: String | None
    credentials: String | None
    requestParameters: MapOfStringToString | None
    requestTemplates: MapOfStringToString | None
    passthroughBehavior: String | None
    cacheNamespace: String | None
    cacheKeyParameters: ListOfString | None
    contentHandling: ContentHandlingStrategy | None
    timeoutInMillis: NullableInteger | None
    tlsConfig: TlsConfig | None
    responseTransferMode: ResponseTransferMode | None
    integrationTarget: String | None


class PutIntegrationResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode
    selectionPattern: String | None
    responseParameters: MapOfStringToString | None
    responseTemplates: MapOfStringToString | None
    contentHandling: ContentHandlingStrategy | None


class PutMethodRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    authorizationType: String
    authorizerId: String | None
    apiKeyRequired: Boolean | None
    operationName: String | None
    requestParameters: MapOfStringToBoolean | None
    requestModels: MapOfStringToString | None
    requestValidatorId: String | None
    authorizationScopes: ListOfString | None


class PutMethodResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode
    responseParameters: MapOfStringToBoolean | None
    responseModels: MapOfStringToString | None


class PutRestApiRequest(ServiceRequest):
    body: IO[Blob]
    restApiId: String
    mode: PutMode | None
    failOnWarnings: Boolean | None
    parameters: MapOfStringToString | None


class RejectDomainNameAccessAssociationRequest(ServiceRequest):
    domainNameAccessAssociationArn: String
    domainNameArn: String


class RequestValidators(TypedDict, total=False):
    position: String | None
    items: ListOfRequestValidator | None


class Resources(TypedDict, total=False):
    position: String | None
    items: ListOfResource | None


class RestApis(TypedDict, total=False):
    position: String | None
    items: ListOfRestApi | None


class SdkResponse(TypedDict, total=False):
    body: Blob | IO[Blob] | Iterable[Blob] | None
    contentType: String | None
    contentDisposition: String | None


class SdkTypes(TypedDict, total=False):
    position: String | None
    items: ListOfSdkType | None


class Stages(TypedDict, total=False):
    item: ListOfStage | None


class TagResourceRequest(ServiceRequest):
    resourceArn: String
    tags: MapOfStringToString


class Tags(TypedDict, total=False):
    tags: MapOfStringToString | None


class Template(TypedDict, total=False):
    value: String | None


class TestInvokeAuthorizerRequest(ServiceRequest):
    restApiId: String
    authorizerId: String
    headers: MapOfStringToString | None
    multiValueHeaders: MapOfStringToList | None
    pathWithQueryString: String | None
    body: String | None
    stageVariables: MapOfStringToString | None
    additionalContext: MapOfStringToString | None


class TestInvokeAuthorizerResponse(TypedDict, total=False):
    clientStatus: Integer | None
    log: String | None
    latency: Long | None
    principalId: String | None
    policy: String | None
    authorization: MapOfStringToList | None
    claims: MapOfStringToString | None


class TestInvokeMethodRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    pathWithQueryString: String | None
    body: String | None
    headers: MapOfStringToString | None
    multiValueHeaders: MapOfStringToList | None
    clientCertificateId: String | None
    stageVariables: MapOfStringToString | None


class TestInvokeMethodResponse(TypedDict, total=False):
    status: Integer | None
    body: String | None
    headers: MapOfStringToString | None
    multiValueHeaders: MapOfStringToList | None
    log: String | None
    latency: Long | None


class UntagResourceRequest(ServiceRequest):
    resourceArn: String
    tagKeys: ListOfString


class UpdateAccountRequest(ServiceRequest):
    patchOperations: ListOfPatchOperation | None


class UpdateApiKeyRequest(ServiceRequest):
    apiKey: String
    patchOperations: ListOfPatchOperation | None


class UpdateAuthorizerRequest(ServiceRequest):
    restApiId: String
    authorizerId: String
    patchOperations: ListOfPatchOperation | None


class UpdateBasePathMappingRequest(ServiceRequest):
    domainName: String
    domainNameId: String | None
    basePath: String
    patchOperations: ListOfPatchOperation | None


class UpdateClientCertificateRequest(ServiceRequest):
    clientCertificateId: String
    patchOperations: ListOfPatchOperation | None


class UpdateDeploymentRequest(ServiceRequest):
    restApiId: String
    deploymentId: String
    patchOperations: ListOfPatchOperation | None


class UpdateDocumentationPartRequest(ServiceRequest):
    restApiId: String
    documentationPartId: String
    patchOperations: ListOfPatchOperation | None


class UpdateDocumentationVersionRequest(ServiceRequest):
    restApiId: String
    documentationVersion: String
    patchOperations: ListOfPatchOperation | None


class UpdateDomainNameRequest(ServiceRequest):
    domainName: String
    domainNameId: String | None
    patchOperations: ListOfPatchOperation | None


class UpdateGatewayResponseRequest(ServiceRequest):
    restApiId: String
    responseType: GatewayResponseType
    patchOperations: ListOfPatchOperation | None


class UpdateIntegrationRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    patchOperations: ListOfPatchOperation | None


class UpdateIntegrationResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode
    patchOperations: ListOfPatchOperation | None


class UpdateMethodRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    patchOperations: ListOfPatchOperation | None


class UpdateMethodResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode
    patchOperations: ListOfPatchOperation | None


class UpdateModelRequest(ServiceRequest):
    restApiId: String
    modelName: String
    patchOperations: ListOfPatchOperation | None


class UpdateRequestValidatorRequest(ServiceRequest):
    restApiId: String
    requestValidatorId: String
    patchOperations: ListOfPatchOperation | None


class UpdateResourceRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    patchOperations: ListOfPatchOperation | None


class UpdateRestApiRequest(ServiceRequest):
    restApiId: String
    patchOperations: ListOfPatchOperation | None


class UpdateStageRequest(ServiceRequest):
    restApiId: String
    stageName: String
    patchOperations: ListOfPatchOperation | None


class UpdateUsagePlanRequest(ServiceRequest):
    usagePlanId: String
    patchOperations: ListOfPatchOperation | None


class UpdateUsageRequest(ServiceRequest):
    usagePlanId: String
    keyId: String
    patchOperations: ListOfPatchOperation | None


class UpdateVpcLinkRequest(ServiceRequest):
    vpcLinkId: String
    patchOperations: ListOfPatchOperation | None


class Usage(TypedDict, total=False):
    usagePlanId: String | None
    startDate: String | None
    endDate: String | None
    position: String | None
    items: MapOfKeyUsages | None


class UsagePlanKeys(TypedDict, total=False):
    position: String | None
    items: ListOfUsagePlanKey | None


class UsagePlans(TypedDict, total=False):
    position: String | None
    items: ListOfUsagePlan | None


class VpcLinks(TypedDict, total=False):
    position: String | None
    items: ListOfVpcLink | None


class ApigatewayApi:
    service: str = "apigateway"
    version: str = "2015-07-09"

    @handler("CreateApiKey")
    def create_api_key(
        self,
        context: RequestContext,
        name: String | None = None,
        description: String | None = None,
        enabled: Boolean | None = None,
        generate_distinct_id: Boolean | None = None,
        value: String | None = None,
        stage_keys: ListOfStageKeys | None = None,
        customer_id: String | None = None,
        tags: MapOfStringToString | None = None,
        **kwargs,
    ) -> ApiKey:
        raise NotImplementedError

    @handler("CreateAuthorizer", expand=False)
    def create_authorizer(
        self, context: RequestContext, request: CreateAuthorizerRequest, **kwargs
    ) -> Authorizer:
        raise NotImplementedError

    @handler("CreateBasePathMapping")
    def create_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        rest_api_id: String,
        domain_name_id: String | None = None,
        base_path: String | None = None,
        stage: String | None = None,
        **kwargs,
    ) -> BasePathMapping:
        raise NotImplementedError

    @handler("CreateDeployment")
    def create_deployment(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String | None = None,
        stage_description: String | None = None,
        description: String | None = None,
        cache_cluster_enabled: NullableBoolean | None = None,
        cache_cluster_size: CacheClusterSize | None = None,
        variables: MapOfStringToString | None = None,
        canary_settings: DeploymentCanarySettings | None = None,
        tracing_enabled: NullableBoolean | None = None,
        **kwargs,
    ) -> Deployment:
        raise NotImplementedError

    @handler("CreateDocumentationPart")
    def create_documentation_part(
        self,
        context: RequestContext,
        rest_api_id: String,
        location: DocumentationPartLocation,
        properties: String,
        **kwargs,
    ) -> DocumentationPart:
        raise NotImplementedError

    @handler("CreateDocumentationVersion")
    def create_documentation_version(
        self,
        context: RequestContext,
        rest_api_id: String,
        documentation_version: String,
        stage_name: String | None = None,
        description: String | None = None,
        **kwargs,
    ) -> DocumentationVersion:
        raise NotImplementedError

    @handler("CreateDomainName")
    def create_domain_name(
        self,
        context: RequestContext,
        domain_name: String,
        certificate_name: String | None = None,
        certificate_body: String | None = None,
        certificate_private_key: String | None = None,
        certificate_chain: String | None = None,
        certificate_arn: String | None = None,
        regional_certificate_name: String | None = None,
        regional_certificate_arn: String | None = None,
        endpoint_configuration: EndpointConfiguration | None = None,
        tags: MapOfStringToString | None = None,
        security_policy: SecurityPolicy | None = None,
        endpoint_access_mode: EndpointAccessMode | None = None,
        mutual_tls_authentication: MutualTlsAuthenticationInput | None = None,
        ownership_verification_certificate_arn: String | None = None,
        policy: String | None = None,
        routing_mode: RoutingMode | None = None,
        **kwargs,
    ) -> DomainName:
        raise NotImplementedError

    @handler("CreateDomainNameAccessAssociation")
    def create_domain_name_access_association(
        self,
        context: RequestContext,
        domain_name_arn: String,
        access_association_source_type: AccessAssociationSourceType,
        access_association_source: String,
        tags: MapOfStringToString | None = None,
        **kwargs,
    ) -> DomainNameAccessAssociation:
        raise NotImplementedError

    @handler("CreateModel")
    def create_model(
        self,
        context: RequestContext,
        rest_api_id: String,
        name: String,
        content_type: String,
        description: String | None = None,
        schema: String | None = None,
        **kwargs,
    ) -> Model:
        raise NotImplementedError

    @handler("CreateRequestValidator")
    def create_request_validator(
        self,
        context: RequestContext,
        rest_api_id: String,
        name: String | None = None,
        validate_request_body: Boolean | None = None,
        validate_request_parameters: Boolean | None = None,
        **kwargs,
    ) -> RequestValidator:
        raise NotImplementedError

    @handler("CreateResource")
    def create_resource(
        self,
        context: RequestContext,
        rest_api_id: String,
        parent_id: String,
        path_part: String,
        **kwargs,
    ) -> Resource:
        raise NotImplementedError

    @handler("CreateRestApi")
    def create_rest_api(
        self,
        context: RequestContext,
        name: String,
        description: String | None = None,
        version: String | None = None,
        clone_from: String | None = None,
        binary_media_types: ListOfString | None = None,
        minimum_compression_size: NullableInteger | None = None,
        api_key_source: ApiKeySourceType | None = None,
        endpoint_configuration: EndpointConfiguration | None = None,
        policy: String | None = None,
        tags: MapOfStringToString | None = None,
        disable_execute_api_endpoint: Boolean | None = None,
        security_policy: SecurityPolicy | None = None,
        endpoint_access_mode: EndpointAccessMode | None = None,
        **kwargs,
    ) -> RestApi:
        raise NotImplementedError

    @handler("CreateStage")
    def create_stage(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String,
        deployment_id: String,
        description: String | None = None,
        cache_cluster_enabled: Boolean | None = None,
        cache_cluster_size: CacheClusterSize | None = None,
        variables: MapOfStringToString | None = None,
        documentation_version: String | None = None,
        canary_settings: CanarySettings | None = None,
        tracing_enabled: Boolean | None = None,
        tags: MapOfStringToString | None = None,
        **kwargs,
    ) -> Stage:
        raise NotImplementedError

    @handler("CreateUsagePlan")
    def create_usage_plan(
        self,
        context: RequestContext,
        name: String,
        description: String | None = None,
        api_stages: ListOfApiStage | None = None,
        throttle: ThrottleSettings | None = None,
        quota: QuotaSettings | None = None,
        tags: MapOfStringToString | None = None,
        **kwargs,
    ) -> UsagePlan:
        raise NotImplementedError

    @handler("CreateUsagePlanKey")
    def create_usage_plan_key(
        self,
        context: RequestContext,
        usage_plan_id: String,
        key_id: String,
        key_type: String,
        **kwargs,
    ) -> UsagePlanKey:
        raise NotImplementedError

    @handler("CreateVpcLink")
    def create_vpc_link(
        self,
        context: RequestContext,
        name: String,
        target_arns: ListOfString,
        description: String | None = None,
        tags: MapOfStringToString | None = None,
        **kwargs,
    ) -> VpcLink:
        raise NotImplementedError

    @handler("DeleteApiKey")
    def delete_api_key(self, context: RequestContext, api_key: String, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteAuthorizer")
    def delete_authorizer(
        self, context: RequestContext, rest_api_id: String, authorizer_id: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBasePathMapping")
    def delete_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        base_path: String,
        domain_name_id: String | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteClientCertificate")
    def delete_client_certificate(
        self, context: RequestContext, client_certificate_id: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDeployment")
    def delete_deployment(
        self, context: RequestContext, rest_api_id: String, deployment_id: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDocumentationPart")
    def delete_documentation_part(
        self, context: RequestContext, rest_api_id: String, documentation_part_id: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDocumentationVersion")
    def delete_documentation_version(
        self, context: RequestContext, rest_api_id: String, documentation_version: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDomainName")
    def delete_domain_name(
        self,
        context: RequestContext,
        domain_name: String,
        domain_name_id: String | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDomainNameAccessAssociation")
    def delete_domain_name_access_association(
        self, context: RequestContext, domain_name_access_association_arn: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteGatewayResponse")
    def delete_gateway_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        response_type: GatewayResponseType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteIntegration")
    def delete_integration(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteIntegrationResponse")
    def delete_integration_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        status_code: StatusCode,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMethod")
    def delete_method(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMethodResponse")
    def delete_method_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        status_code: StatusCode,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteModel")
    def delete_model(
        self, context: RequestContext, rest_api_id: String, model_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRequestValidator")
    def delete_request_validator(
        self, context: RequestContext, rest_api_id: String, request_validator_id: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteResource")
    def delete_resource(
        self, context: RequestContext, rest_api_id: String, resource_id: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRestApi")
    def delete_rest_api(self, context: RequestContext, rest_api_id: String, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteStage")
    def delete_stage(
        self, context: RequestContext, rest_api_id: String, stage_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUsagePlan")
    def delete_usage_plan(self, context: RequestContext, usage_plan_id: String, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteUsagePlanKey")
    def delete_usage_plan_key(
        self, context: RequestContext, usage_plan_id: String, key_id: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVpcLink")
    def delete_vpc_link(self, context: RequestContext, vpc_link_id: String, **kwargs) -> None:
        raise NotImplementedError

    @handler("FlushStageAuthorizersCache")
    def flush_stage_authorizers_cache(
        self, context: RequestContext, rest_api_id: String, stage_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("FlushStageCache")
    def flush_stage_cache(
        self, context: RequestContext, rest_api_id: String, stage_name: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("GenerateClientCertificate")
    def generate_client_certificate(
        self,
        context: RequestContext,
        description: String | None = None,
        tags: MapOfStringToString | None = None,
        **kwargs,
    ) -> ClientCertificate:
        raise NotImplementedError

    @handler("GetAccount")
    def get_account(self, context: RequestContext, **kwargs) -> Account:
        raise NotImplementedError

    @handler("GetApiKey")
    def get_api_key(
        self,
        context: RequestContext,
        api_key: String,
        include_value: NullableBoolean | None = None,
        **kwargs,
    ) -> ApiKey:
        raise NotImplementedError

    @handler("GetApiKeys")
    def get_api_keys(
        self,
        context: RequestContext,
        position: String | None = None,
        limit: NullableInteger | None = None,
        name_query: String | None = None,
        customer_id: String | None = None,
        include_values: NullableBoolean | None = None,
        **kwargs,
    ) -> ApiKeys:
        raise NotImplementedError

    @handler("GetAuthorizer")
    def get_authorizer(
        self, context: RequestContext, rest_api_id: String, authorizer_id: String, **kwargs
    ) -> Authorizer:
        raise NotImplementedError

    @handler("GetAuthorizers")
    def get_authorizers(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> Authorizers:
        raise NotImplementedError

    @handler("GetBasePathMapping")
    def get_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        base_path: String,
        domain_name_id: String | None = None,
        **kwargs,
    ) -> BasePathMapping:
        raise NotImplementedError

    @handler("GetBasePathMappings")
    def get_base_path_mappings(
        self,
        context: RequestContext,
        domain_name: String,
        domain_name_id: String | None = None,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> BasePathMappings:
        raise NotImplementedError

    @handler("GetClientCertificate")
    def get_client_certificate(
        self, context: RequestContext, client_certificate_id: String, **kwargs
    ) -> ClientCertificate:
        raise NotImplementedError

    @handler("GetClientCertificates")
    def get_client_certificates(
        self,
        context: RequestContext,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> ClientCertificates:
        raise NotImplementedError

    @handler("GetDeployment")
    def get_deployment(
        self,
        context: RequestContext,
        rest_api_id: String,
        deployment_id: String,
        embed: ListOfString | None = None,
        **kwargs,
    ) -> Deployment:
        raise NotImplementedError

    @handler("GetDeployments")
    def get_deployments(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> Deployments:
        raise NotImplementedError

    @handler("GetDocumentationPart")
    def get_documentation_part(
        self, context: RequestContext, rest_api_id: String, documentation_part_id: String, **kwargs
    ) -> DocumentationPart:
        raise NotImplementedError

    @handler("GetDocumentationParts", expand=False)
    def get_documentation_parts(
        self, context: RequestContext, request: GetDocumentationPartsRequest, **kwargs
    ) -> DocumentationParts:
        raise NotImplementedError

    @handler("GetDocumentationVersion")
    def get_documentation_version(
        self, context: RequestContext, rest_api_id: String, documentation_version: String, **kwargs
    ) -> DocumentationVersion:
        raise NotImplementedError

    @handler("GetDocumentationVersions")
    def get_documentation_versions(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> DocumentationVersions:
        raise NotImplementedError

    @handler("GetDomainName")
    def get_domain_name(
        self,
        context: RequestContext,
        domain_name: String,
        domain_name_id: String | None = None,
        **kwargs,
    ) -> DomainName:
        raise NotImplementedError

    @handler("GetDomainNameAccessAssociations")
    def get_domain_name_access_associations(
        self,
        context: RequestContext,
        position: String | None = None,
        limit: NullableInteger | None = None,
        resource_owner: ResourceOwner | None = None,
        **kwargs,
    ) -> DomainNameAccessAssociations:
        raise NotImplementedError

    @handler("GetDomainNames")
    def get_domain_names(
        self,
        context: RequestContext,
        position: String | None = None,
        limit: NullableInteger | None = None,
        resource_owner: ResourceOwner | None = None,
        **kwargs,
    ) -> DomainNames:
        raise NotImplementedError

    @handler("GetExport")
    def get_export(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String,
        export_type: String,
        parameters: MapOfStringToString | None = None,
        accepts: String | None = None,
        **kwargs,
    ) -> ExportResponse:
        raise NotImplementedError

    @handler("GetGatewayResponse")
    def get_gateway_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        response_type: GatewayResponseType,
        **kwargs,
    ) -> GatewayResponse:
        raise NotImplementedError

    @handler("GetGatewayResponses")
    def get_gateway_responses(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> GatewayResponses:
        raise NotImplementedError

    @handler("GetIntegration")
    def get_integration(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        **kwargs,
    ) -> Integration:
        raise NotImplementedError

    @handler("GetIntegrationResponse")
    def get_integration_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        status_code: StatusCode,
        **kwargs,
    ) -> IntegrationResponse:
        raise NotImplementedError

    @handler("GetMethod")
    def get_method(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        **kwargs,
    ) -> Method:
        raise NotImplementedError

    @handler("GetMethodResponse")
    def get_method_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        status_code: StatusCode,
        **kwargs,
    ) -> MethodResponse:
        raise NotImplementedError

    @handler("GetModel")
    def get_model(
        self,
        context: RequestContext,
        rest_api_id: String,
        model_name: String,
        flatten: Boolean | None = None,
        **kwargs,
    ) -> Model:
        raise NotImplementedError

    @handler("GetModelTemplate")
    def get_model_template(
        self, context: RequestContext, rest_api_id: String, model_name: String, **kwargs
    ) -> Template:
        raise NotImplementedError

    @handler("GetModels")
    def get_models(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> Models:
        raise NotImplementedError

    @handler("GetRequestValidator")
    def get_request_validator(
        self, context: RequestContext, rest_api_id: String, request_validator_id: String, **kwargs
    ) -> RequestValidator:
        raise NotImplementedError

    @handler("GetRequestValidators")
    def get_request_validators(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> RequestValidators:
        raise NotImplementedError

    @handler("GetResource")
    def get_resource(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        embed: ListOfString | None = None,
        **kwargs,
    ) -> Resource:
        raise NotImplementedError

    @handler("GetResources")
    def get_resources(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        embed: ListOfString | None = None,
        **kwargs,
    ) -> Resources:
        raise NotImplementedError

    @handler("GetRestApi")
    def get_rest_api(self, context: RequestContext, rest_api_id: String, **kwargs) -> RestApi:
        raise NotImplementedError

    @handler("GetRestApis")
    def get_rest_apis(
        self,
        context: RequestContext,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> RestApis:
        raise NotImplementedError

    @handler("GetSdk")
    def get_sdk(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String,
        sdk_type: String,
        parameters: MapOfStringToString | None = None,
        **kwargs,
    ) -> SdkResponse:
        raise NotImplementedError

    @handler("GetSdkType")
    def get_sdk_type(self, context: RequestContext, id: String, **kwargs) -> SdkType:
        raise NotImplementedError

    @handler("GetSdkTypes")
    def get_sdk_types(
        self,
        context: RequestContext,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> SdkTypes:
        raise NotImplementedError

    @handler("GetStage")
    def get_stage(
        self, context: RequestContext, rest_api_id: String, stage_name: String, **kwargs
    ) -> Stage:
        raise NotImplementedError

    @handler("GetStages")
    def get_stages(
        self,
        context: RequestContext,
        rest_api_id: String,
        deployment_id: String | None = None,
        **kwargs,
    ) -> Stages:
        raise NotImplementedError

    @handler("GetTags")
    def get_tags(
        self,
        context: RequestContext,
        resource_arn: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> Tags:
        raise NotImplementedError

    @handler("GetUsage")
    def get_usage(
        self,
        context: RequestContext,
        usage_plan_id: String,
        start_date: String,
        end_date: String,
        key_id: String | None = None,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> Usage:
        raise NotImplementedError

    @handler("GetUsagePlan")
    def get_usage_plan(self, context: RequestContext, usage_plan_id: String, **kwargs) -> UsagePlan:
        raise NotImplementedError

    @handler("GetUsagePlanKey")
    def get_usage_plan_key(
        self, context: RequestContext, usage_plan_id: String, key_id: String, **kwargs
    ) -> UsagePlanKey:
        raise NotImplementedError

    @handler("GetUsagePlanKeys")
    def get_usage_plan_keys(
        self,
        context: RequestContext,
        usage_plan_id: String,
        position: String | None = None,
        limit: NullableInteger | None = None,
        name_query: String | None = None,
        **kwargs,
    ) -> UsagePlanKeys:
        raise NotImplementedError

    @handler("GetUsagePlans")
    def get_usage_plans(
        self,
        context: RequestContext,
        position: String | None = None,
        key_id: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> UsagePlans:
        raise NotImplementedError

    @handler("GetVpcLink")
    def get_vpc_link(self, context: RequestContext, vpc_link_id: String, **kwargs) -> VpcLink:
        raise NotImplementedError

    @handler("GetVpcLinks")
    def get_vpc_links(
        self,
        context: RequestContext,
        position: String | None = None,
        limit: NullableInteger | None = None,
        **kwargs,
    ) -> VpcLinks:
        raise NotImplementedError

    @handler("ImportApiKeys")
    def import_api_keys(
        self,
        context: RequestContext,
        body: IO[Blob],
        format: ApiKeysFormat,
        fail_on_warnings: Boolean | None = None,
        **kwargs,
    ) -> ApiKeyIds:
        raise NotImplementedError

    @handler("ImportDocumentationParts")
    def import_documentation_parts(
        self,
        context: RequestContext,
        rest_api_id: String,
        body: IO[Blob],
        mode: PutMode | None = None,
        fail_on_warnings: Boolean | None = None,
        **kwargs,
    ) -> DocumentationPartIds:
        raise NotImplementedError

    @handler("ImportRestApi")
    def import_rest_api(
        self,
        context: RequestContext,
        body: IO[Blob],
        fail_on_warnings: Boolean | None = None,
        parameters: MapOfStringToString | None = None,
        **kwargs,
    ) -> RestApi:
        raise NotImplementedError

    @handler("PutGatewayResponse")
    def put_gateway_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        response_type: GatewayResponseType,
        status_code: StatusCode | None = None,
        response_parameters: MapOfStringToString | None = None,
        response_templates: MapOfStringToString | None = None,
        **kwargs,
    ) -> GatewayResponse:
        raise NotImplementedError

    @handler("PutIntegration", expand=False)
    def put_integration(
        self, context: RequestContext, request: PutIntegrationRequest, **kwargs
    ) -> Integration:
        raise NotImplementedError

    @handler("PutIntegrationResponse")
    def put_integration_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        status_code: StatusCode,
        selection_pattern: String | None = None,
        response_parameters: MapOfStringToString | None = None,
        response_templates: MapOfStringToString | None = None,
        content_handling: ContentHandlingStrategy | None = None,
        **kwargs,
    ) -> IntegrationResponse:
        raise NotImplementedError

    @handler("PutMethod")
    def put_method(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        authorization_type: String,
        authorizer_id: String | None = None,
        api_key_required: Boolean | None = None,
        operation_name: String | None = None,
        request_parameters: MapOfStringToBoolean | None = None,
        request_models: MapOfStringToString | None = None,
        request_validator_id: String | None = None,
        authorization_scopes: ListOfString | None = None,
        **kwargs,
    ) -> Method:
        raise NotImplementedError

    @handler("PutMethodResponse")
    def put_method_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        status_code: StatusCode,
        response_parameters: MapOfStringToBoolean | None = None,
        response_models: MapOfStringToString | None = None,
        **kwargs,
    ) -> MethodResponse:
        raise NotImplementedError

    @handler("PutRestApi")
    def put_rest_api(
        self,
        context: RequestContext,
        rest_api_id: String,
        body: IO[Blob],
        mode: PutMode | None = None,
        fail_on_warnings: Boolean | None = None,
        parameters: MapOfStringToString | None = None,
        **kwargs,
    ) -> RestApi:
        raise NotImplementedError

    @handler("RejectDomainNameAccessAssociation")
    def reject_domain_name_access_association(
        self,
        context: RequestContext,
        domain_name_access_association_arn: String,
        domain_name_arn: String,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: String, tags: MapOfStringToString, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TestInvokeAuthorizer")
    def test_invoke_authorizer(
        self,
        context: RequestContext,
        rest_api_id: String,
        authorizer_id: String,
        headers: MapOfStringToString | None = None,
        multi_value_headers: MapOfStringToList | None = None,
        path_with_query_string: String | None = None,
        body: String | None = None,
        stage_variables: MapOfStringToString | None = None,
        additional_context: MapOfStringToString | None = None,
        **kwargs,
    ) -> TestInvokeAuthorizerResponse:
        raise NotImplementedError

    @handler("TestInvokeMethod")
    def test_invoke_method(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        path_with_query_string: String | None = None,
        body: String | None = None,
        headers: MapOfStringToString | None = None,
        multi_value_headers: MapOfStringToList | None = None,
        client_certificate_id: String | None = None,
        stage_variables: MapOfStringToString | None = None,
        **kwargs,
    ) -> TestInvokeMethodResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: String, tag_keys: ListOfString, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAccount")
    def update_account(
        self,
        context: RequestContext,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Account:
        raise NotImplementedError

    @handler("UpdateApiKey")
    def update_api_key(
        self,
        context: RequestContext,
        api_key: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> ApiKey:
        raise NotImplementedError

    @handler("UpdateAuthorizer")
    def update_authorizer(
        self,
        context: RequestContext,
        rest_api_id: String,
        authorizer_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Authorizer:
        raise NotImplementedError

    @handler("UpdateBasePathMapping")
    def update_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        base_path: String,
        domain_name_id: String | None = None,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> BasePathMapping:
        raise NotImplementedError

    @handler("UpdateClientCertificate")
    def update_client_certificate(
        self,
        context: RequestContext,
        client_certificate_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> ClientCertificate:
        raise NotImplementedError

    @handler("UpdateDeployment")
    def update_deployment(
        self,
        context: RequestContext,
        rest_api_id: String,
        deployment_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Deployment:
        raise NotImplementedError

    @handler("UpdateDocumentationPart")
    def update_documentation_part(
        self,
        context: RequestContext,
        rest_api_id: String,
        documentation_part_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> DocumentationPart:
        raise NotImplementedError

    @handler("UpdateDocumentationVersion")
    def update_documentation_version(
        self,
        context: RequestContext,
        rest_api_id: String,
        documentation_version: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> DocumentationVersion:
        raise NotImplementedError

    @handler("UpdateDomainName")
    def update_domain_name(
        self,
        context: RequestContext,
        domain_name: String,
        domain_name_id: String | None = None,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> DomainName:
        raise NotImplementedError

    @handler("UpdateGatewayResponse")
    def update_gateway_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        response_type: GatewayResponseType,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> GatewayResponse:
        raise NotImplementedError

    @handler("UpdateIntegration")
    def update_integration(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Integration:
        raise NotImplementedError

    @handler("UpdateIntegrationResponse")
    def update_integration_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        status_code: StatusCode,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> IntegrationResponse:
        raise NotImplementedError

    @handler("UpdateMethod")
    def update_method(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Method:
        raise NotImplementedError

    @handler("UpdateMethodResponse")
    def update_method_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        http_method: String,
        status_code: StatusCode,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> MethodResponse:
        raise NotImplementedError

    @handler("UpdateModel")
    def update_model(
        self,
        context: RequestContext,
        rest_api_id: String,
        model_name: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Model:
        raise NotImplementedError

    @handler("UpdateRequestValidator")
    def update_request_validator(
        self,
        context: RequestContext,
        rest_api_id: String,
        request_validator_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> RequestValidator:
        raise NotImplementedError

    @handler("UpdateResource")
    def update_resource(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Resource:
        raise NotImplementedError

    @handler("UpdateRestApi")
    def update_rest_api(
        self,
        context: RequestContext,
        rest_api_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> RestApi:
        raise NotImplementedError

    @handler("UpdateStage")
    def update_stage(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Stage:
        raise NotImplementedError

    @handler("UpdateUsage")
    def update_usage(
        self,
        context: RequestContext,
        usage_plan_id: String,
        key_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> Usage:
        raise NotImplementedError

    @handler("UpdateUsagePlan")
    def update_usage_plan(
        self,
        context: RequestContext,
        usage_plan_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> UsagePlan:
        raise NotImplementedError

    @handler("UpdateVpcLink")
    def update_vpc_link(
        self,
        context: RequestContext,
        vpc_link_id: String,
        patch_operations: ListOfPatchOperation | None = None,
        **kwargs,
    ) -> VpcLink:
        raise NotImplementedError
