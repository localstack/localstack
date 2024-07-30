from datetime import datetime
from enum import StrEnum
from typing import IO, Dict, Iterable, List, Optional, TypedDict, Union

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


class ApiKeySourceType(StrEnum):
    HEADER = "HEADER"
    AUTHORIZER = "AUTHORIZER"


class ApiKeysFormat(StrEnum):
    csv = "csv"


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


class SecurityPolicy(StrEnum):
    TLS_1_0 = "TLS_1_0"
    TLS_1_2 = "TLS_1_2"


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
    retryAfterSeconds: Optional[String]


class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 404


class ServiceUnavailableException(ServiceException):
    code: str = "ServiceUnavailableException"
    sender_fault: bool = False
    status_code: int = 503
    retryAfterSeconds: Optional[String]


class TooManyRequestsException(ServiceException):
    code: str = "TooManyRequestsException"
    sender_fault: bool = False
    status_code: int = 429
    retryAfterSeconds: Optional[String]


class UnauthorizedException(ServiceException):
    code: str = "UnauthorizedException"
    sender_fault: bool = False
    status_code: int = 401


class AccessLogSettings(TypedDict, total=False):
    format: Optional[String]
    destinationArn: Optional[String]


ListOfString = List[String]


class ThrottleSettings(TypedDict, total=False):
    burstLimit: Optional[Integer]
    rateLimit: Optional[Double]


class Account(TypedDict, total=False):
    cloudwatchRoleArn: Optional[String]
    throttleSettings: Optional[ThrottleSettings]
    features: Optional[ListOfString]
    apiKeyVersion: Optional[String]


MapOfStringToString = Dict[String, String]
Timestamp = datetime


class ApiKey(TypedDict, total=False):
    id: Optional[String]
    value: Optional[String]
    name: Optional[String]
    customerId: Optional[String]
    description: Optional[String]
    enabled: Optional[Boolean]
    createdDate: Optional[Timestamp]
    lastUpdatedDate: Optional[Timestamp]
    stageKeys: Optional[ListOfString]
    tags: Optional[MapOfStringToString]


class ApiKeyIds(TypedDict, total=False):
    ids: Optional[ListOfString]
    warnings: Optional[ListOfString]


ListOfApiKey = List[ApiKey]


class ApiKeys(TypedDict, total=False):
    warnings: Optional[ListOfString]
    position: Optional[String]
    items: Optional[ListOfApiKey]


MapOfApiStageThrottleSettings = Dict[String, ThrottleSettings]


class ApiStage(TypedDict, total=False):
    apiId: Optional[String]
    stage: Optional[String]
    throttle: Optional[MapOfApiStageThrottleSettings]


ListOfARNs = List[ProviderARN]
Authorizer = TypedDict(
    "Authorizer",
    {
        "id": Optional[String],
        "name": Optional[String],
        "type": Optional[AuthorizerType],
        "providerARNs": Optional[ListOfARNs],
        "authType": Optional[String],
        "authorizerUri": Optional[String],
        "authorizerCredentials": Optional[String],
        "identitySource": Optional[String],
        "identityValidationExpression": Optional[String],
        "authorizerResultTtlInSeconds": Optional[NullableInteger],
    },
    total=False,
)
ListOfAuthorizer = List[Authorizer]


class Authorizers(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfAuthorizer]


class BasePathMapping(TypedDict, total=False):
    basePath: Optional[String]
    restApiId: Optional[String]
    stage: Optional[String]


ListOfBasePathMapping = List[BasePathMapping]


class BasePathMappings(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfBasePathMapping]


Blob = bytes


class CanarySettings(TypedDict, total=False):
    percentTraffic: Optional[Double]
    deploymentId: Optional[String]
    stageVariableOverrides: Optional[MapOfStringToString]
    useStageCache: Optional[Boolean]


class ClientCertificate(TypedDict, total=False):
    clientCertificateId: Optional[String]
    description: Optional[String]
    pemEncodedCertificate: Optional[String]
    createdDate: Optional[Timestamp]
    expirationDate: Optional[Timestamp]
    tags: Optional[MapOfStringToString]


ListOfClientCertificate = List[ClientCertificate]


class ClientCertificates(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfClientCertificate]


class StageKey(TypedDict, total=False):
    restApiId: Optional[String]
    stageName: Optional[String]


ListOfStageKeys = List[StageKey]


class CreateApiKeyRequest(ServiceRequest):
    name: Optional[String]
    description: Optional[String]
    enabled: Optional[Boolean]
    generateDistinctId: Optional[Boolean]
    value: Optional[String]
    stageKeys: Optional[ListOfStageKeys]
    customerId: Optional[String]
    tags: Optional[MapOfStringToString]


CreateAuthorizerRequest = TypedDict(
    "CreateAuthorizerRequest",
    {
        "restApiId": String,
        "name": String,
        "type": AuthorizerType,
        "providerARNs": Optional[ListOfARNs],
        "authType": Optional[String],
        "authorizerUri": Optional[String],
        "authorizerCredentials": Optional[String],
        "identitySource": Optional[String],
        "identityValidationExpression": Optional[String],
        "authorizerResultTtlInSeconds": Optional[NullableInteger],
    },
    total=False,
)


class CreateBasePathMappingRequest(ServiceRequest):
    domainName: String
    basePath: Optional[String]
    restApiId: String
    stage: Optional[String]


class DeploymentCanarySettings(TypedDict, total=False):
    percentTraffic: Optional[Double]
    stageVariableOverrides: Optional[MapOfStringToString]
    useStageCache: Optional[Boolean]


class CreateDeploymentRequest(ServiceRequest):
    restApiId: String
    stageName: Optional[String]
    stageDescription: Optional[String]
    description: Optional[String]
    cacheClusterEnabled: Optional[NullableBoolean]
    cacheClusterSize: Optional[CacheClusterSize]
    variables: Optional[MapOfStringToString]
    canarySettings: Optional[DeploymentCanarySettings]
    tracingEnabled: Optional[NullableBoolean]


DocumentationPartLocation = TypedDict(
    "DocumentationPartLocation",
    {
        "type": DocumentationPartType,
        "path": Optional[String],
        "method": Optional[String],
        "statusCode": Optional[DocumentationPartLocationStatusCode],
        "name": Optional[String],
    },
    total=False,
)


class CreateDocumentationPartRequest(ServiceRequest):
    restApiId: String
    location: DocumentationPartLocation
    properties: String


class CreateDocumentationVersionRequest(ServiceRequest):
    restApiId: String
    documentationVersion: String
    stageName: Optional[String]
    description: Optional[String]


class MutualTlsAuthenticationInput(TypedDict, total=False):
    truststoreUri: Optional[String]
    truststoreVersion: Optional[String]


ListOfEndpointType = List[EndpointType]


class EndpointConfiguration(TypedDict, total=False):
    types: Optional[ListOfEndpointType]
    vpcEndpointIds: Optional[ListOfString]


class CreateDomainNameRequest(ServiceRequest):
    domainName: String
    certificateName: Optional[String]
    certificateBody: Optional[String]
    certificatePrivateKey: Optional[String]
    certificateChain: Optional[String]
    certificateArn: Optional[String]
    regionalCertificateName: Optional[String]
    regionalCertificateArn: Optional[String]
    endpointConfiguration: Optional[EndpointConfiguration]
    tags: Optional[MapOfStringToString]
    securityPolicy: Optional[SecurityPolicy]
    mutualTlsAuthentication: Optional[MutualTlsAuthenticationInput]
    ownershipVerificationCertificateArn: Optional[String]


class CreateModelRequest(ServiceRequest):
    restApiId: String
    name: String
    description: Optional[String]
    schema: Optional[String]
    contentType: String


class CreateRequestValidatorRequest(ServiceRequest):
    restApiId: String
    name: Optional[String]
    validateRequestBody: Optional[Boolean]
    validateRequestParameters: Optional[Boolean]


class CreateResourceRequest(ServiceRequest):
    restApiId: String
    parentId: String
    pathPart: String


class CreateRestApiRequest(ServiceRequest):
    name: String
    description: Optional[String]
    version: Optional[String]
    cloneFrom: Optional[String]
    binaryMediaTypes: Optional[ListOfString]
    minimumCompressionSize: Optional[NullableInteger]
    apiKeySource: Optional[ApiKeySourceType]
    endpointConfiguration: Optional[EndpointConfiguration]
    policy: Optional[String]
    tags: Optional[MapOfStringToString]
    disableExecuteApiEndpoint: Optional[Boolean]


class CreateStageRequest(ServiceRequest):
    restApiId: String
    stageName: String
    deploymentId: String
    description: Optional[String]
    cacheClusterEnabled: Optional[Boolean]
    cacheClusterSize: Optional[CacheClusterSize]
    variables: Optional[MapOfStringToString]
    documentationVersion: Optional[String]
    canarySettings: Optional[CanarySettings]
    tracingEnabled: Optional[Boolean]
    tags: Optional[MapOfStringToString]


class CreateUsagePlanKeyRequest(ServiceRequest):
    usagePlanId: String
    keyId: String
    keyType: String


class QuotaSettings(TypedDict, total=False):
    limit: Optional[Integer]
    offset: Optional[Integer]
    period: Optional[QuotaPeriodType]


ListOfApiStage = List[ApiStage]


class CreateUsagePlanRequest(ServiceRequest):
    name: String
    description: Optional[String]
    apiStages: Optional[ListOfApiStage]
    throttle: Optional[ThrottleSettings]
    quota: Optional[QuotaSettings]
    tags: Optional[MapOfStringToString]


class CreateVpcLinkRequest(ServiceRequest):
    name: String
    description: Optional[String]
    targetArns: ListOfString
    tags: Optional[MapOfStringToString]


class DeleteApiKeyRequest(ServiceRequest):
    apiKey: String


class DeleteAuthorizerRequest(ServiceRequest):
    restApiId: String
    authorizerId: String


class DeleteBasePathMappingRequest(ServiceRequest):
    domainName: String
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


class DeleteDomainNameRequest(ServiceRequest):
    domainName: String


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
    authorizationType: Optional[String]
    apiKeyRequired: Optional[Boolean]


MapOfMethodSnapshot = Dict[String, MethodSnapshot]
PathToMapOfMethodSnapshot = Dict[String, MapOfMethodSnapshot]


class Deployment(TypedDict, total=False):
    id: Optional[String]
    description: Optional[String]
    createdDate: Optional[Timestamp]
    apiSummary: Optional[PathToMapOfMethodSnapshot]


ListOfDeployment = List[Deployment]


class Deployments(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfDeployment]


class DocumentationPart(TypedDict, total=False):
    id: Optional[String]
    location: Optional[DocumentationPartLocation]
    properties: Optional[String]


class DocumentationPartIds(TypedDict, total=False):
    ids: Optional[ListOfString]
    warnings: Optional[ListOfString]


ListOfDocumentationPart = List[DocumentationPart]


class DocumentationParts(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfDocumentationPart]


class DocumentationVersion(TypedDict, total=False):
    version: Optional[String]
    createdDate: Optional[Timestamp]
    description: Optional[String]


ListOfDocumentationVersion = List[DocumentationVersion]


class DocumentationVersions(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfDocumentationVersion]


class MutualTlsAuthentication(TypedDict, total=False):
    truststoreUri: Optional[String]
    truststoreVersion: Optional[String]
    truststoreWarnings: Optional[ListOfString]


class DomainName(TypedDict, total=False):
    domainName: Optional[String]
    certificateName: Optional[String]
    certificateArn: Optional[String]
    certificateUploadDate: Optional[Timestamp]
    regionalDomainName: Optional[String]
    regionalHostedZoneId: Optional[String]
    regionalCertificateName: Optional[String]
    regionalCertificateArn: Optional[String]
    distributionDomainName: Optional[String]
    distributionHostedZoneId: Optional[String]
    endpointConfiguration: Optional[EndpointConfiguration]
    domainNameStatus: Optional[DomainNameStatus]
    domainNameStatusMessage: Optional[String]
    securityPolicy: Optional[SecurityPolicy]
    tags: Optional[MapOfStringToString]
    mutualTlsAuthentication: Optional[MutualTlsAuthentication]
    ownershipVerificationCertificateArn: Optional[String]


ListOfDomainName = List[DomainName]


class DomainNames(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfDomainName]


class ExportResponse(TypedDict, total=False):
    body: Optional[Union[Blob, IO[Blob], Iterable[Blob]]]
    contentType: Optional[String]
    contentDisposition: Optional[String]


class FlushStageAuthorizersCacheRequest(ServiceRequest):
    restApiId: String
    stageName: String


class FlushStageCacheRequest(ServiceRequest):
    restApiId: String
    stageName: String


class GatewayResponse(TypedDict, total=False):
    responseType: Optional[GatewayResponseType]
    statusCode: Optional[StatusCode]
    responseParameters: Optional[MapOfStringToString]
    responseTemplates: Optional[MapOfStringToString]
    defaultResponse: Optional[Boolean]


ListOfGatewayResponse = List[GatewayResponse]


class GatewayResponses(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfGatewayResponse]


class GenerateClientCertificateRequest(ServiceRequest):
    description: Optional[String]
    tags: Optional[MapOfStringToString]


class GetAccountRequest(ServiceRequest):
    pass


class GetApiKeyRequest(ServiceRequest):
    apiKey: String
    includeValue: Optional[NullableBoolean]


class GetApiKeysRequest(ServiceRequest):
    position: Optional[String]
    limit: Optional[NullableInteger]
    nameQuery: Optional[String]
    customerId: Optional[String]
    includeValues: Optional[NullableBoolean]


class GetAuthorizerRequest(ServiceRequest):
    restApiId: String
    authorizerId: String


class GetAuthorizersRequest(ServiceRequest):
    restApiId: String
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetBasePathMappingRequest(ServiceRequest):
    domainName: String
    basePath: String


class GetBasePathMappingsRequest(ServiceRequest):
    domainName: String
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetClientCertificateRequest(ServiceRequest):
    clientCertificateId: String


class GetClientCertificatesRequest(ServiceRequest):
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetDeploymentRequest(ServiceRequest):
    restApiId: String
    deploymentId: String
    embed: Optional[ListOfString]


class GetDeploymentsRequest(ServiceRequest):
    restApiId: String
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetDocumentationPartRequest(ServiceRequest):
    restApiId: String
    documentationPartId: String


GetDocumentationPartsRequest = TypedDict(
    "GetDocumentationPartsRequest",
    {
        "restApiId": String,
        "type": Optional[DocumentationPartType],
        "nameQuery": Optional[String],
        "path": Optional[String],
        "position": Optional[String],
        "limit": Optional[NullableInteger],
        "locationStatus": Optional[LocationStatusType],
    },
    total=False,
)


class GetDocumentationVersionRequest(ServiceRequest):
    restApiId: String
    documentationVersion: String


class GetDocumentationVersionsRequest(ServiceRequest):
    restApiId: String
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetDomainNameRequest(ServiceRequest):
    domainName: String


class GetDomainNamesRequest(ServiceRequest):
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetExportRequest(ServiceRequest):
    restApiId: String
    stageName: String
    exportType: String
    parameters: Optional[MapOfStringToString]
    accepts: Optional[String]


class GetGatewayResponseRequest(ServiceRequest):
    restApiId: String
    responseType: GatewayResponseType


class GetGatewayResponsesRequest(ServiceRequest):
    restApiId: String
    position: Optional[String]
    limit: Optional[NullableInteger]


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
    flatten: Optional[Boolean]


class GetModelTemplateRequest(ServiceRequest):
    restApiId: String
    modelName: String


class GetModelsRequest(ServiceRequest):
    restApiId: String
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetRequestValidatorRequest(ServiceRequest):
    restApiId: String
    requestValidatorId: String


class GetRequestValidatorsRequest(ServiceRequest):
    restApiId: String
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetResourceRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    embed: Optional[ListOfString]


class GetResourcesRequest(ServiceRequest):
    restApiId: String
    position: Optional[String]
    limit: Optional[NullableInteger]
    embed: Optional[ListOfString]


class GetRestApiRequest(ServiceRequest):
    restApiId: String


class GetRestApisRequest(ServiceRequest):
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetSdkRequest(ServiceRequest):
    restApiId: String
    stageName: String
    sdkType: String
    parameters: Optional[MapOfStringToString]


class GetSdkTypeRequest(ServiceRequest):
    id: String


class GetSdkTypesRequest(ServiceRequest):
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetStageRequest(ServiceRequest):
    restApiId: String
    stageName: String


class GetStagesRequest(ServiceRequest):
    restApiId: String
    deploymentId: Optional[String]


class GetTagsRequest(ServiceRequest):
    resourceArn: String
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetUsagePlanKeyRequest(ServiceRequest):
    usagePlanId: String
    keyId: String


class GetUsagePlanKeysRequest(ServiceRequest):
    usagePlanId: String
    position: Optional[String]
    limit: Optional[NullableInteger]
    nameQuery: Optional[String]


class GetUsagePlanRequest(ServiceRequest):
    usagePlanId: String


class GetUsagePlansRequest(ServiceRequest):
    position: Optional[String]
    keyId: Optional[String]
    limit: Optional[NullableInteger]


class GetUsageRequest(ServiceRequest):
    usagePlanId: String
    keyId: Optional[String]
    startDate: String
    endDate: String
    position: Optional[String]
    limit: Optional[NullableInteger]


class GetVpcLinkRequest(ServiceRequest):
    vpcLinkId: String


class GetVpcLinksRequest(ServiceRequest):
    position: Optional[String]
    limit: Optional[NullableInteger]


class ImportApiKeysRequest(ServiceRequest):
    body: IO[Blob]
    format: ApiKeysFormat
    failOnWarnings: Optional[Boolean]


class ImportDocumentationPartsRequest(ServiceRequest):
    body: IO[Blob]
    restApiId: String
    mode: Optional[PutMode]
    failOnWarnings: Optional[Boolean]


class ImportRestApiRequest(ServiceRequest):
    body: IO[Blob]
    failOnWarnings: Optional[Boolean]
    parameters: Optional[MapOfStringToString]


class TlsConfig(TypedDict, total=False):
    insecureSkipVerification: Optional[Boolean]


class IntegrationResponse(TypedDict, total=False):
    statusCode: Optional[StatusCode]
    selectionPattern: Optional[String]
    responseParameters: Optional[MapOfStringToString]
    responseTemplates: Optional[MapOfStringToString]
    contentHandling: Optional[ContentHandlingStrategy]


MapOfIntegrationResponse = Dict[String, IntegrationResponse]
Integration = TypedDict(
    "Integration",
    {
        "type": Optional[IntegrationType],
        "httpMethod": Optional[String],
        "uri": Optional[String],
        "connectionType": Optional[ConnectionType],
        "connectionId": Optional[String],
        "credentials": Optional[String],
        "requestParameters": Optional[MapOfStringToString],
        "requestTemplates": Optional[MapOfStringToString],
        "passthroughBehavior": Optional[String],
        "contentHandling": Optional[ContentHandlingStrategy],
        "timeoutInMillis": Optional[Integer],
        "cacheNamespace": Optional[String],
        "cacheKeyParameters": Optional[ListOfString],
        "integrationResponses": Optional[MapOfIntegrationResponse],
        "tlsConfig": Optional[TlsConfig],
    },
    total=False,
)
Long = int
ListOfLong = List[Long]


class Model(TypedDict, total=False):
    id: Optional[String]
    name: Optional[String]
    description: Optional[String]
    schema: Optional[String]
    contentType: Optional[String]


ListOfModel = List[Model]
PatchOperation = TypedDict(
    "PatchOperation",
    {
        "op": Optional[Op],
        "path": Optional[String],
        "value": Optional[String],
        "from": Optional[String],
    },
    total=False,
)
ListOfPatchOperation = List[PatchOperation]


class RequestValidator(TypedDict, total=False):
    id: Optional[String]
    name: Optional[String]
    validateRequestBody: Optional[Boolean]
    validateRequestParameters: Optional[Boolean]


ListOfRequestValidator = List[RequestValidator]
MapOfStringToBoolean = Dict[String, NullableBoolean]


class MethodResponse(TypedDict, total=False):
    statusCode: Optional[StatusCode]
    responseParameters: Optional[MapOfStringToBoolean]
    responseModels: Optional[MapOfStringToString]


MapOfMethodResponse = Dict[String, MethodResponse]


class Method(TypedDict, total=False):
    httpMethod: Optional[String]
    authorizationType: Optional[String]
    authorizerId: Optional[String]
    apiKeyRequired: Optional[NullableBoolean]
    requestValidatorId: Optional[String]
    operationName: Optional[String]
    requestParameters: Optional[MapOfStringToBoolean]
    requestModels: Optional[MapOfStringToString]
    methodResponses: Optional[MapOfMethodResponse]
    methodIntegration: Optional[Integration]
    authorizationScopes: Optional[ListOfString]


MapOfMethod = Dict[String, Method]


class Resource(TypedDict, total=False):
    id: Optional[String]
    parentId: Optional[String]
    pathPart: Optional[String]
    path: Optional[String]
    resourceMethods: Optional[MapOfMethod]


ListOfResource = List[Resource]


class RestApi(TypedDict, total=False):
    id: Optional[String]
    name: Optional[String]
    description: Optional[String]
    createdDate: Optional[Timestamp]
    version: Optional[String]
    warnings: Optional[ListOfString]
    binaryMediaTypes: Optional[ListOfString]
    minimumCompressionSize: Optional[NullableInteger]
    apiKeySource: Optional[ApiKeySourceType]
    endpointConfiguration: Optional[EndpointConfiguration]
    policy: Optional[String]
    tags: Optional[MapOfStringToString]
    disableExecuteApiEndpoint: Optional[Boolean]
    rootResourceId: Optional[String]


ListOfRestApi = List[RestApi]


class SdkConfigurationProperty(TypedDict, total=False):
    name: Optional[String]
    friendlyName: Optional[String]
    description: Optional[String]
    required: Optional[Boolean]
    defaultValue: Optional[String]


ListOfSdkConfigurationProperty = List[SdkConfigurationProperty]


class SdkType(TypedDict, total=False):
    id: Optional[String]
    friendlyName: Optional[String]
    description: Optional[String]
    configurationProperties: Optional[ListOfSdkConfigurationProperty]


ListOfSdkType = List[SdkType]


class MethodSetting(TypedDict, total=False):
    metricsEnabled: Optional[Boolean]
    loggingLevel: Optional[String]
    dataTraceEnabled: Optional[Boolean]
    throttlingBurstLimit: Optional[Integer]
    throttlingRateLimit: Optional[Double]
    cachingEnabled: Optional[Boolean]
    cacheTtlInSeconds: Optional[Integer]
    cacheDataEncrypted: Optional[Boolean]
    requireAuthorizationForCacheControl: Optional[Boolean]
    unauthorizedCacheControlHeaderStrategy: Optional[UnauthorizedCacheControlHeaderStrategy]


MapOfMethodSettings = Dict[String, MethodSetting]


class Stage(TypedDict, total=False):
    deploymentId: Optional[String]
    clientCertificateId: Optional[String]
    stageName: Optional[String]
    description: Optional[String]
    cacheClusterEnabled: Optional[Boolean]
    cacheClusterSize: Optional[CacheClusterSize]
    cacheClusterStatus: Optional[CacheClusterStatus]
    methodSettings: Optional[MapOfMethodSettings]
    variables: Optional[MapOfStringToString]
    documentationVersion: Optional[String]
    accessLogSettings: Optional[AccessLogSettings]
    canarySettings: Optional[CanarySettings]
    tracingEnabled: Optional[Boolean]
    webAclArn: Optional[String]
    tags: Optional[MapOfStringToString]
    createdDate: Optional[Timestamp]
    lastUpdatedDate: Optional[Timestamp]


ListOfStage = List[Stage]
ListOfUsage = List[ListOfLong]


class UsagePlan(TypedDict, total=False):
    id: Optional[String]
    name: Optional[String]
    description: Optional[String]
    apiStages: Optional[ListOfApiStage]
    throttle: Optional[ThrottleSettings]
    quota: Optional[QuotaSettings]
    productCode: Optional[String]
    tags: Optional[MapOfStringToString]


ListOfUsagePlan = List[UsagePlan]
UsagePlanKey = TypedDict(
    "UsagePlanKey",
    {
        "id": Optional[String],
        "type": Optional[String],
        "value": Optional[String],
        "name": Optional[String],
    },
    total=False,
)
ListOfUsagePlanKey = List[UsagePlanKey]


class VpcLink(TypedDict, total=False):
    id: Optional[String]
    name: Optional[String]
    description: Optional[String]
    targetArns: Optional[ListOfString]
    status: Optional[VpcLinkStatus]
    statusMessage: Optional[String]
    tags: Optional[MapOfStringToString]


ListOfVpcLink = List[VpcLink]
MapOfKeyUsages = Dict[String, ListOfUsage]
MapOfStringToList = Dict[String, ListOfString]


class Models(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfModel]


class PutGatewayResponseRequest(ServiceRequest):
    restApiId: String
    responseType: GatewayResponseType
    statusCode: Optional[StatusCode]
    responseParameters: Optional[MapOfStringToString]
    responseTemplates: Optional[MapOfStringToString]


PutIntegrationRequest = TypedDict(
    "PutIntegrationRequest",
    {
        "restApiId": String,
        "resourceId": String,
        "httpMethod": String,
        "type": IntegrationType,
        "integrationHttpMethod": Optional[String],
        "uri": Optional[String],
        "connectionType": Optional[ConnectionType],
        "connectionId": Optional[String],
        "credentials": Optional[String],
        "requestParameters": Optional[MapOfStringToString],
        "requestTemplates": Optional[MapOfStringToString],
        "passthroughBehavior": Optional[String],
        "cacheNamespace": Optional[String],
        "cacheKeyParameters": Optional[ListOfString],
        "contentHandling": Optional[ContentHandlingStrategy],
        "timeoutInMillis": Optional[NullableInteger],
        "tlsConfig": Optional[TlsConfig],
    },
    total=False,
)


class PutIntegrationResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode
    selectionPattern: Optional[String]
    responseParameters: Optional[MapOfStringToString]
    responseTemplates: Optional[MapOfStringToString]
    contentHandling: Optional[ContentHandlingStrategy]


class PutMethodRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    authorizationType: String
    authorizerId: Optional[String]
    apiKeyRequired: Optional[Boolean]
    operationName: Optional[String]
    requestParameters: Optional[MapOfStringToBoolean]
    requestModels: Optional[MapOfStringToString]
    requestValidatorId: Optional[String]
    authorizationScopes: Optional[ListOfString]


class PutMethodResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode
    responseParameters: Optional[MapOfStringToBoolean]
    responseModels: Optional[MapOfStringToString]


class PutRestApiRequest(ServiceRequest):
    body: IO[Blob]
    restApiId: String
    mode: Optional[PutMode]
    failOnWarnings: Optional[Boolean]
    parameters: Optional[MapOfStringToString]


class RequestValidators(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfRequestValidator]


class Resources(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfResource]


class RestApis(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfRestApi]


class SdkResponse(TypedDict, total=False):
    body: Optional[Union[Blob, IO[Blob], Iterable[Blob]]]
    contentType: Optional[String]
    contentDisposition: Optional[String]


class SdkTypes(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfSdkType]


class Stages(TypedDict, total=False):
    item: Optional[ListOfStage]


class TagResourceRequest(ServiceRequest):
    resourceArn: String
    tags: MapOfStringToString


class Tags(TypedDict, total=False):
    tags: Optional[MapOfStringToString]


class Template(TypedDict, total=False):
    value: Optional[String]


class TestInvokeAuthorizerRequest(ServiceRequest):
    restApiId: String
    authorizerId: String
    headers: Optional[MapOfStringToString]
    multiValueHeaders: Optional[MapOfStringToList]
    pathWithQueryString: Optional[String]
    body: Optional[String]
    stageVariables: Optional[MapOfStringToString]
    additionalContext: Optional[MapOfStringToString]


class TestInvokeAuthorizerResponse(TypedDict, total=False):
    clientStatus: Optional[Integer]
    log: Optional[String]
    latency: Optional[Long]
    principalId: Optional[String]
    policy: Optional[String]
    authorization: Optional[MapOfStringToList]
    claims: Optional[MapOfStringToString]


class TestInvokeMethodRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    pathWithQueryString: Optional[String]
    body: Optional[String]
    headers: Optional[MapOfStringToString]
    multiValueHeaders: Optional[MapOfStringToList]
    clientCertificateId: Optional[String]
    stageVariables: Optional[MapOfStringToString]


class TestInvokeMethodResponse(TypedDict, total=False):
    status: Optional[Integer]
    body: Optional[String]
    headers: Optional[MapOfStringToString]
    multiValueHeaders: Optional[MapOfStringToList]
    log: Optional[String]
    latency: Optional[Long]


class UntagResourceRequest(ServiceRequest):
    resourceArn: String
    tagKeys: ListOfString


class UpdateAccountRequest(ServiceRequest):
    patchOperations: Optional[ListOfPatchOperation]


class UpdateApiKeyRequest(ServiceRequest):
    apiKey: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateAuthorizerRequest(ServiceRequest):
    restApiId: String
    authorizerId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateBasePathMappingRequest(ServiceRequest):
    domainName: String
    basePath: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateClientCertificateRequest(ServiceRequest):
    clientCertificateId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateDeploymentRequest(ServiceRequest):
    restApiId: String
    deploymentId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateDocumentationPartRequest(ServiceRequest):
    restApiId: String
    documentationPartId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateDocumentationVersionRequest(ServiceRequest):
    restApiId: String
    documentationVersion: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateDomainNameRequest(ServiceRequest):
    domainName: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateGatewayResponseRequest(ServiceRequest):
    restApiId: String
    responseType: GatewayResponseType
    patchOperations: Optional[ListOfPatchOperation]


class UpdateIntegrationRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateIntegrationResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode
    patchOperations: Optional[ListOfPatchOperation]


class UpdateMethodRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateMethodResponseRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    httpMethod: String
    statusCode: StatusCode
    patchOperations: Optional[ListOfPatchOperation]


class UpdateModelRequest(ServiceRequest):
    restApiId: String
    modelName: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateRequestValidatorRequest(ServiceRequest):
    restApiId: String
    requestValidatorId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateResourceRequest(ServiceRequest):
    restApiId: String
    resourceId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateRestApiRequest(ServiceRequest):
    restApiId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateStageRequest(ServiceRequest):
    restApiId: String
    stageName: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateUsagePlanRequest(ServiceRequest):
    usagePlanId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateUsageRequest(ServiceRequest):
    usagePlanId: String
    keyId: String
    patchOperations: Optional[ListOfPatchOperation]


class UpdateVpcLinkRequest(ServiceRequest):
    vpcLinkId: String
    patchOperations: Optional[ListOfPatchOperation]


class Usage(TypedDict, total=False):
    usagePlanId: Optional[String]
    startDate: Optional[String]
    endDate: Optional[String]
    position: Optional[String]
    items: Optional[MapOfKeyUsages]


class UsagePlanKeys(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfUsagePlanKey]


class UsagePlans(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfUsagePlan]


class VpcLinks(TypedDict, total=False):
    position: Optional[String]
    items: Optional[ListOfVpcLink]


class ApigatewayApi:
    service = "apigateway"
    version = "2015-07-09"

    @handler("CreateApiKey")
    def create_api_key(
        self,
        context: RequestContext,
        name: String = None,
        description: String = None,
        enabled: Boolean = None,
        generate_distinct_id: Boolean = None,
        value: String = None,
        stage_keys: ListOfStageKeys = None,
        customer_id: String = None,
        tags: MapOfStringToString = None,
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
        base_path: String = None,
        stage: String = None,
        **kwargs,
    ) -> BasePathMapping:
        raise NotImplementedError

    @handler("CreateDeployment")
    def create_deployment(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String = None,
        stage_description: String = None,
        description: String = None,
        cache_cluster_enabled: NullableBoolean = None,
        cache_cluster_size: CacheClusterSize = None,
        variables: MapOfStringToString = None,
        canary_settings: DeploymentCanarySettings = None,
        tracing_enabled: NullableBoolean = None,
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
        stage_name: String = None,
        description: String = None,
        **kwargs,
    ) -> DocumentationVersion:
        raise NotImplementedError

    @handler("CreateDomainName")
    def create_domain_name(
        self,
        context: RequestContext,
        domain_name: String,
        certificate_name: String = None,
        certificate_body: String = None,
        certificate_private_key: String = None,
        certificate_chain: String = None,
        certificate_arn: String = None,
        regional_certificate_name: String = None,
        regional_certificate_arn: String = None,
        endpoint_configuration: EndpointConfiguration = None,
        tags: MapOfStringToString = None,
        security_policy: SecurityPolicy = None,
        mutual_tls_authentication: MutualTlsAuthenticationInput = None,
        ownership_verification_certificate_arn: String = None,
        **kwargs,
    ) -> DomainName:
        raise NotImplementedError

    @handler("CreateModel")
    def create_model(
        self,
        context: RequestContext,
        rest_api_id: String,
        name: String,
        content_type: String,
        description: String = None,
        schema: String = None,
        **kwargs,
    ) -> Model:
        raise NotImplementedError

    @handler("CreateRequestValidator")
    def create_request_validator(
        self,
        context: RequestContext,
        rest_api_id: String,
        name: String = None,
        validate_request_body: Boolean = None,
        validate_request_parameters: Boolean = None,
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
        description: String = None,
        version: String = None,
        clone_from: String = None,
        binary_media_types: ListOfString = None,
        minimum_compression_size: NullableInteger = None,
        api_key_source: ApiKeySourceType = None,
        endpoint_configuration: EndpointConfiguration = None,
        policy: String = None,
        tags: MapOfStringToString = None,
        disable_execute_api_endpoint: Boolean = None,
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
        description: String = None,
        cache_cluster_enabled: Boolean = None,
        cache_cluster_size: CacheClusterSize = None,
        variables: MapOfStringToString = None,
        documentation_version: String = None,
        canary_settings: CanarySettings = None,
        tracing_enabled: Boolean = None,
        tags: MapOfStringToString = None,
        **kwargs,
    ) -> Stage:
        raise NotImplementedError

    @handler("CreateUsagePlan")
    def create_usage_plan(
        self,
        context: RequestContext,
        name: String,
        description: String = None,
        api_stages: ListOfApiStage = None,
        throttle: ThrottleSettings = None,
        quota: QuotaSettings = None,
        tags: MapOfStringToString = None,
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
        description: String = None,
        tags: MapOfStringToString = None,
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
        self, context: RequestContext, domain_name: String, base_path: String, **kwargs
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
    def delete_domain_name(self, context: RequestContext, domain_name: String, **kwargs) -> None:
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
        description: String = None,
        tags: MapOfStringToString = None,
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
        include_value: NullableBoolean = None,
        **kwargs,
    ) -> ApiKey:
        raise NotImplementedError

    @handler("GetApiKeys")
    def get_api_keys(
        self,
        context: RequestContext,
        position: String = None,
        limit: NullableInteger = None,
        name_query: String = None,
        customer_id: String = None,
        include_values: NullableBoolean = None,
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
        position: String = None,
        limit: NullableInteger = None,
        **kwargs,
    ) -> Authorizers:
        raise NotImplementedError

    @handler("GetBasePathMapping")
    def get_base_path_mapping(
        self, context: RequestContext, domain_name: String, base_path: String, **kwargs
    ) -> BasePathMapping:
        raise NotImplementedError

    @handler("GetBasePathMappings")
    def get_base_path_mappings(
        self,
        context: RequestContext,
        domain_name: String,
        position: String = None,
        limit: NullableInteger = None,
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
        position: String = None,
        limit: NullableInteger = None,
        **kwargs,
    ) -> ClientCertificates:
        raise NotImplementedError

    @handler("GetDeployment")
    def get_deployment(
        self,
        context: RequestContext,
        rest_api_id: String,
        deployment_id: String,
        embed: ListOfString = None,
        **kwargs,
    ) -> Deployment:
        raise NotImplementedError

    @handler("GetDeployments")
    def get_deployments(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String = None,
        limit: NullableInteger = None,
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
        position: String = None,
        limit: NullableInteger = None,
        **kwargs,
    ) -> DocumentationVersions:
        raise NotImplementedError

    @handler("GetDomainName")
    def get_domain_name(self, context: RequestContext, domain_name: String, **kwargs) -> DomainName:
        raise NotImplementedError

    @handler("GetDomainNames")
    def get_domain_names(
        self,
        context: RequestContext,
        position: String = None,
        limit: NullableInteger = None,
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
        parameters: MapOfStringToString = None,
        accepts: String = None,
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
        position: String = None,
        limit: NullableInteger = None,
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
        flatten: Boolean = None,
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
        position: String = None,
        limit: NullableInteger = None,
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
        position: String = None,
        limit: NullableInteger = None,
        **kwargs,
    ) -> RequestValidators:
        raise NotImplementedError

    @handler("GetResource")
    def get_resource(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        embed: ListOfString = None,
        **kwargs,
    ) -> Resource:
        raise NotImplementedError

    @handler("GetResources")
    def get_resources(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String = None,
        limit: NullableInteger = None,
        embed: ListOfString = None,
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
        position: String = None,
        limit: NullableInteger = None,
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
        parameters: MapOfStringToString = None,
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
        position: String = None,
        limit: NullableInteger = None,
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
        self, context: RequestContext, rest_api_id: String, deployment_id: String = None, **kwargs
    ) -> Stages:
        raise NotImplementedError

    @handler("GetTags")
    def get_tags(
        self,
        context: RequestContext,
        resource_arn: String,
        position: String = None,
        limit: NullableInteger = None,
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
        key_id: String = None,
        position: String = None,
        limit: NullableInteger = None,
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
        position: String = None,
        limit: NullableInteger = None,
        name_query: String = None,
        **kwargs,
    ) -> UsagePlanKeys:
        raise NotImplementedError

    @handler("GetUsagePlans")
    def get_usage_plans(
        self,
        context: RequestContext,
        position: String = None,
        key_id: String = None,
        limit: NullableInteger = None,
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
        position: String = None,
        limit: NullableInteger = None,
        **kwargs,
    ) -> VpcLinks:
        raise NotImplementedError

    @handler("ImportApiKeys")
    def import_api_keys(
        self,
        context: RequestContext,
        body: IO[Blob],
        format: ApiKeysFormat,
        fail_on_warnings: Boolean = None,
        **kwargs,
    ) -> ApiKeyIds:
        raise NotImplementedError

    @handler("ImportDocumentationParts")
    def import_documentation_parts(
        self,
        context: RequestContext,
        rest_api_id: String,
        body: IO[Blob],
        mode: PutMode = None,
        fail_on_warnings: Boolean = None,
        **kwargs,
    ) -> DocumentationPartIds:
        raise NotImplementedError

    @handler("ImportRestApi")
    def import_rest_api(
        self,
        context: RequestContext,
        body: IO[Blob],
        fail_on_warnings: Boolean = None,
        parameters: MapOfStringToString = None,
        **kwargs,
    ) -> RestApi:
        raise NotImplementedError

    @handler("PutGatewayResponse")
    def put_gateway_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        response_type: GatewayResponseType,
        status_code: StatusCode = None,
        response_parameters: MapOfStringToString = None,
        response_templates: MapOfStringToString = None,
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
        selection_pattern: String = None,
        response_parameters: MapOfStringToString = None,
        response_templates: MapOfStringToString = None,
        content_handling: ContentHandlingStrategy = None,
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
        authorizer_id: String = None,
        api_key_required: Boolean = None,
        operation_name: String = None,
        request_parameters: MapOfStringToBoolean = None,
        request_models: MapOfStringToString = None,
        request_validator_id: String = None,
        authorization_scopes: ListOfString = None,
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
        response_parameters: MapOfStringToBoolean = None,
        response_models: MapOfStringToString = None,
        **kwargs,
    ) -> MethodResponse:
        raise NotImplementedError

    @handler("PutRestApi")
    def put_rest_api(
        self,
        context: RequestContext,
        rest_api_id: String,
        body: IO[Blob],
        mode: PutMode = None,
        fail_on_warnings: Boolean = None,
        parameters: MapOfStringToString = None,
        **kwargs,
    ) -> RestApi:
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
        headers: MapOfStringToString = None,
        multi_value_headers: MapOfStringToList = None,
        path_with_query_string: String = None,
        body: String = None,
        stage_variables: MapOfStringToString = None,
        additional_context: MapOfStringToString = None,
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
        path_with_query_string: String = None,
        body: String = None,
        headers: MapOfStringToString = None,
        multi_value_headers: MapOfStringToList = None,
        client_certificate_id: String = None,
        stage_variables: MapOfStringToString = None,
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
        self, context: RequestContext, patch_operations: ListOfPatchOperation = None, **kwargs
    ) -> Account:
        raise NotImplementedError

    @handler("UpdateApiKey")
    def update_api_key(
        self,
        context: RequestContext,
        api_key: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> ApiKey:
        raise NotImplementedError

    @handler("UpdateAuthorizer")
    def update_authorizer(
        self,
        context: RequestContext,
        rest_api_id: String,
        authorizer_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> Authorizer:
        raise NotImplementedError

    @handler("UpdateBasePathMapping")
    def update_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        base_path: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> BasePathMapping:
        raise NotImplementedError

    @handler("UpdateClientCertificate")
    def update_client_certificate(
        self,
        context: RequestContext,
        client_certificate_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> ClientCertificate:
        raise NotImplementedError

    @handler("UpdateDeployment")
    def update_deployment(
        self,
        context: RequestContext,
        rest_api_id: String,
        deployment_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> Deployment:
        raise NotImplementedError

    @handler("UpdateDocumentationPart")
    def update_documentation_part(
        self,
        context: RequestContext,
        rest_api_id: String,
        documentation_part_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> DocumentationPart:
        raise NotImplementedError

    @handler("UpdateDocumentationVersion")
    def update_documentation_version(
        self,
        context: RequestContext,
        rest_api_id: String,
        documentation_version: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> DocumentationVersion:
        raise NotImplementedError

    @handler("UpdateDomainName")
    def update_domain_name(
        self,
        context: RequestContext,
        domain_name: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> DomainName:
        raise NotImplementedError

    @handler("UpdateGatewayResponse")
    def update_gateway_response(
        self,
        context: RequestContext,
        rest_api_id: String,
        response_type: GatewayResponseType,
        patch_operations: ListOfPatchOperation = None,
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
        patch_operations: ListOfPatchOperation = None,
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
        patch_operations: ListOfPatchOperation = None,
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
        patch_operations: ListOfPatchOperation = None,
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
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> MethodResponse:
        raise NotImplementedError

    @handler("UpdateModel")
    def update_model(
        self,
        context: RequestContext,
        rest_api_id: String,
        model_name: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> Model:
        raise NotImplementedError

    @handler("UpdateRequestValidator")
    def update_request_validator(
        self,
        context: RequestContext,
        rest_api_id: String,
        request_validator_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> RequestValidator:
        raise NotImplementedError

    @handler("UpdateResource")
    def update_resource(
        self,
        context: RequestContext,
        rest_api_id: String,
        resource_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> Resource:
        raise NotImplementedError

    @handler("UpdateRestApi")
    def update_rest_api(
        self,
        context: RequestContext,
        rest_api_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> RestApi:
        raise NotImplementedError

    @handler("UpdateStage")
    def update_stage(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> Stage:
        raise NotImplementedError

    @handler("UpdateUsage")
    def update_usage(
        self,
        context: RequestContext,
        usage_plan_id: String,
        key_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> Usage:
        raise NotImplementedError

    @handler("UpdateUsagePlan")
    def update_usage_plan(
        self,
        context: RequestContext,
        usage_plan_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> UsagePlan:
        raise NotImplementedError

    @handler("UpdateVpcLink")
    def update_vpc_link(
        self,
        context: RequestContext,
        vpc_link_id: String,
        patch_operations: ListOfPatchOperation = None,
        **kwargs,
    ) -> VpcLink:
        raise NotImplementedError
