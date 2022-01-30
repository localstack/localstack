import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arn = str
Id = str
IntegerWithLengthBetween0And3600 = int
IntegerWithLengthBetween50And30000 = int
IntegerWithLengthBetweenMinus1And86400 = int
NextToken = str
SelectionExpression = str
SelectionKey = str
StringWithLengthBetween0And1024 = str
StringWithLengthBetween0And2048 = str
StringWithLengthBetween0And32K = str
StringWithLengthBetween1And1024 = str
StringWithLengthBetween1And128 = str
StringWithLengthBetween1And1600 = str
StringWithLengthBetween1And256 = str
StringWithLengthBetween1And512 = str
StringWithLengthBetween1And64 = str
UriWithLengthBetween1And2048 = str
_boolean = bool
_double = float
_integer = int
_string = str


class AuthorizationType(str):
    NONE = "NONE"
    AWS_IAM = "AWS_IAM"
    CUSTOM = "CUSTOM"
    JWT = "JWT"


class AuthorizerType(str):
    REQUEST = "REQUEST"
    JWT = "JWT"


class ConnectionType(str):
    INTERNET = "INTERNET"
    VPC_LINK = "VPC_LINK"


class ContentHandlingStrategy(str):
    CONVERT_TO_BINARY = "CONVERT_TO_BINARY"
    CONVERT_TO_TEXT = "CONVERT_TO_TEXT"


class DeploymentStatus(str):
    PENDING = "PENDING"
    FAILED = "FAILED"
    DEPLOYED = "DEPLOYED"


class DomainNameStatus(str):
    AVAILABLE = "AVAILABLE"
    UPDATING = "UPDATING"
    PENDING_CERTIFICATE_REIMPORT = "PENDING_CERTIFICATE_REIMPORT"
    PENDING_OWNERSHIP_VERIFICATION = "PENDING_OWNERSHIP_VERIFICATION"


class EndpointType(str):
    REGIONAL = "REGIONAL"
    EDGE = "EDGE"


class IntegrationType(str):
    AWS = "AWS"
    HTTP = "HTTP"
    MOCK = "MOCK"
    HTTP_PROXY = "HTTP_PROXY"
    AWS_PROXY = "AWS_PROXY"


class LoggingLevel(str):
    ERROR = "ERROR"
    INFO = "INFO"
    OFF = "OFF"


class PassthroughBehavior(str):
    WHEN_NO_MATCH = "WHEN_NO_MATCH"
    NEVER = "NEVER"
    WHEN_NO_TEMPLATES = "WHEN_NO_TEMPLATES"


class ProtocolType(str):
    WEBSOCKET = "WEBSOCKET"
    HTTP = "HTTP"


class SecurityPolicy(str):
    TLS_1_0 = "TLS_1_0"
    TLS_1_2 = "TLS_1_2"


class VpcLinkStatus(str):
    PENDING = "PENDING"
    AVAILABLE = "AVAILABLE"
    DELETING = "DELETING"
    FAILED = "FAILED"
    INACTIVE = "INACTIVE"


class VpcLinkVersion(str):
    V2 = "V2"


class AccessDeniedException(ServiceException):
    Message: Optional[_string]


class BadRequestException(ServiceException):
    Message: Optional[_string]


class ConflictException(ServiceException):
    Message: Optional[_string]


class NotFoundException(ServiceException):
    Message: Optional[_string]
    ResourceType: Optional[_string]


class TooManyRequestsException(ServiceException):
    LimitType: Optional[_string]
    Message: Optional[_string]


class AccessLogSettings(TypedDict, total=False):
    DestinationArn: Optional[Arn]
    Format: Optional[StringWithLengthBetween1And1024]


_listOf__string = List[_string]
Tags = Dict[_string, StringWithLengthBetween1And1600]
_timestampIso8601 = datetime
CorsHeaderList = List[_string]
CorsOriginList = List[_string]
CorsMethodList = List[StringWithLengthBetween1And64]


class Cors(TypedDict, total=False):
    AllowCredentials: Optional[_boolean]
    AllowHeaders: Optional[CorsHeaderList]
    AllowMethods: Optional[CorsMethodList]
    AllowOrigins: Optional[CorsOriginList]
    ExposeHeaders: Optional[CorsHeaderList]
    MaxAge: Optional[IntegerWithLengthBetweenMinus1And86400]


class Api(TypedDict, total=False):
    ApiEndpoint: Optional[_string]
    ApiGatewayManaged: Optional[_boolean]
    ApiId: Optional[Id]
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CreatedDate: Optional[_timestampIso8601]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    ImportInfo: Optional[_listOf__string]
    Name: StringWithLengthBetween1And128
    ProtocolType: ProtocolType
    RouteSelectionExpression: SelectionExpression
    Tags: Optional[Tags]
    Version: Optional[StringWithLengthBetween1And64]
    Warnings: Optional[_listOf__string]


class ApiMapping(TypedDict, total=False):
    ApiId: Id
    ApiMappingId: Optional[Id]
    ApiMappingKey: Optional[SelectionKey]
    Stage: StringWithLengthBetween1And128


_listOfApiMapping = List[ApiMapping]


class ApiMappings(TypedDict, total=False):
    Items: Optional[_listOfApiMapping]
    NextToken: Optional[NextToken]


_listOfApi = List[Api]


class Apis(TypedDict, total=False):
    Items: Optional[_listOfApi]
    NextToken: Optional[NextToken]


AuthorizationScopes = List[StringWithLengthBetween1And64]


class JWTConfiguration(TypedDict, total=False):
    Audience: Optional[_listOf__string]
    Issuer: Optional[UriWithLengthBetween1And2048]


IdentitySourceList = List[_string]


class Authorizer(TypedDict, total=False):
    AuthorizerCredentialsArn: Optional[Arn]
    AuthorizerId: Optional[Id]
    AuthorizerPayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    AuthorizerResultTtlInSeconds: Optional[IntegerWithLengthBetween0And3600]
    AuthorizerType: Optional[AuthorizerType]
    AuthorizerUri: Optional[UriWithLengthBetween1And2048]
    EnableSimpleResponses: Optional[_boolean]
    IdentitySource: Optional[IdentitySourceList]
    IdentityValidationExpression: Optional[StringWithLengthBetween0And1024]
    JwtConfiguration: Optional[JWTConfiguration]
    Name: StringWithLengthBetween1And128


_listOfAuthorizer = List[Authorizer]


class Authorizers(TypedDict, total=False):
    Items: Optional[_listOfAuthorizer]
    NextToken: Optional[NextToken]


class CreateApiInput(TypedDict, total=False):
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    Name: StringWithLengthBetween1And128
    ProtocolType: ProtocolType
    RouteKey: Optional[SelectionKey]
    RouteSelectionExpression: Optional[SelectionExpression]
    Tags: Optional[Tags]
    Target: Optional[UriWithLengthBetween1And2048]
    Version: Optional[StringWithLengthBetween1And64]


class CreateApiMappingInput(TypedDict, total=False):
    ApiId: Id
    ApiMappingKey: Optional[SelectionKey]
    Stage: StringWithLengthBetween1And128


class CreateApiMappingRequest(ServiceRequest):
    ApiId: Id
    ApiMappingKey: Optional[SelectionKey]
    DomainName: _string
    Stage: StringWithLengthBetween1And128


class CreateApiMappingResponse(TypedDict, total=False):
    ApiId: Optional[Id]
    ApiMappingId: Optional[Id]
    ApiMappingKey: Optional[SelectionKey]
    Stage: Optional[StringWithLengthBetween1And128]


class CreateApiRequest(ServiceRequest):
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    Name: StringWithLengthBetween1And128
    ProtocolType: ProtocolType
    RouteKey: Optional[SelectionKey]
    RouteSelectionExpression: Optional[SelectionExpression]
    Tags: Optional[Tags]
    Target: Optional[UriWithLengthBetween1And2048]
    Version: Optional[StringWithLengthBetween1And64]


class CreateApiResponse(TypedDict, total=False):
    ApiEndpoint: Optional[_string]
    ApiGatewayManaged: Optional[_boolean]
    ApiId: Optional[Id]
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CreatedDate: Optional[_timestampIso8601]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    ImportInfo: Optional[_listOf__string]
    Name: Optional[StringWithLengthBetween1And128]
    ProtocolType: Optional[ProtocolType]
    RouteSelectionExpression: Optional[SelectionExpression]
    Tags: Optional[Tags]
    Version: Optional[StringWithLengthBetween1And64]
    Warnings: Optional[_listOf__string]


class CreateAuthorizerInput(TypedDict, total=False):
    AuthorizerCredentialsArn: Optional[Arn]
    AuthorizerPayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    AuthorizerResultTtlInSeconds: Optional[IntegerWithLengthBetween0And3600]
    AuthorizerType: AuthorizerType
    AuthorizerUri: Optional[UriWithLengthBetween1And2048]
    EnableSimpleResponses: Optional[_boolean]
    IdentitySource: IdentitySourceList
    IdentityValidationExpression: Optional[StringWithLengthBetween0And1024]
    JwtConfiguration: Optional[JWTConfiguration]
    Name: StringWithLengthBetween1And128


class CreateAuthorizerRequest(ServiceRequest):
    ApiId: _string
    AuthorizerCredentialsArn: Optional[Arn]
    AuthorizerPayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    AuthorizerResultTtlInSeconds: Optional[IntegerWithLengthBetween0And3600]
    AuthorizerType: AuthorizerType
    AuthorizerUri: Optional[UriWithLengthBetween1And2048]
    EnableSimpleResponses: Optional[_boolean]
    IdentitySource: IdentitySourceList
    IdentityValidationExpression: Optional[StringWithLengthBetween0And1024]
    JwtConfiguration: Optional[JWTConfiguration]
    Name: StringWithLengthBetween1And128


class CreateAuthorizerResponse(TypedDict, total=False):
    AuthorizerCredentialsArn: Optional[Arn]
    AuthorizerId: Optional[Id]
    AuthorizerPayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    AuthorizerResultTtlInSeconds: Optional[IntegerWithLengthBetween0And3600]
    AuthorizerType: Optional[AuthorizerType]
    AuthorizerUri: Optional[UriWithLengthBetween1And2048]
    EnableSimpleResponses: Optional[_boolean]
    IdentitySource: Optional[IdentitySourceList]
    IdentityValidationExpression: Optional[StringWithLengthBetween0And1024]
    JwtConfiguration: Optional[JWTConfiguration]
    Name: Optional[StringWithLengthBetween1And128]


class CreateDeploymentInput(TypedDict, total=False):
    Description: Optional[StringWithLengthBetween0And1024]
    StageName: Optional[StringWithLengthBetween1And128]


class CreateDeploymentRequest(ServiceRequest):
    ApiId: _string
    Description: Optional[StringWithLengthBetween0And1024]
    StageName: Optional[StringWithLengthBetween1And128]


class CreateDeploymentResponse(TypedDict, total=False):
    AutoDeployed: Optional[_boolean]
    CreatedDate: Optional[_timestampIso8601]
    DeploymentId: Optional[Id]
    DeploymentStatus: Optional[DeploymentStatus]
    DeploymentStatusMessage: Optional[_string]
    Description: Optional[StringWithLengthBetween0And1024]


class MutualTlsAuthenticationInput(TypedDict, total=False):
    TruststoreUri: Optional[UriWithLengthBetween1And2048]
    TruststoreVersion: Optional[StringWithLengthBetween1And64]


class DomainNameConfiguration(TypedDict, total=False):
    ApiGatewayDomainName: Optional[_string]
    CertificateArn: Optional[Arn]
    CertificateName: Optional[StringWithLengthBetween1And128]
    CertificateUploadDate: Optional[_timestampIso8601]
    DomainNameStatus: Optional[DomainNameStatus]
    DomainNameStatusMessage: Optional[_string]
    EndpointType: Optional[EndpointType]
    HostedZoneId: Optional[_string]
    SecurityPolicy: Optional[SecurityPolicy]
    OwnershipVerificationCertificateArn: Optional[Arn]


DomainNameConfigurations = List[DomainNameConfiguration]


class CreateDomainNameInput(TypedDict, total=False):
    DomainName: StringWithLengthBetween1And512
    DomainNameConfigurations: Optional[DomainNameConfigurations]
    MutualTlsAuthentication: Optional[MutualTlsAuthenticationInput]
    Tags: Optional[Tags]


class CreateDomainNameRequest(ServiceRequest):
    DomainName: StringWithLengthBetween1And512
    DomainNameConfigurations: Optional[DomainNameConfigurations]
    MutualTlsAuthentication: Optional[MutualTlsAuthenticationInput]
    Tags: Optional[Tags]


class MutualTlsAuthentication(TypedDict, total=False):
    TruststoreUri: Optional[UriWithLengthBetween1And2048]
    TruststoreVersion: Optional[StringWithLengthBetween1And64]
    TruststoreWarnings: Optional[_listOf__string]


class CreateDomainNameResponse(TypedDict, total=False):
    ApiMappingSelectionExpression: Optional[SelectionExpression]
    DomainName: Optional[StringWithLengthBetween1And512]
    DomainNameConfigurations: Optional[DomainNameConfigurations]
    MutualTlsAuthentication: Optional[MutualTlsAuthentication]
    Tags: Optional[Tags]


class TlsConfigInput(TypedDict, total=False):
    ServerNameToVerify: Optional[StringWithLengthBetween1And512]


IntegrationParameters = Dict[_string, StringWithLengthBetween1And512]
ResponseParameters = Dict[_string, IntegrationParameters]
TemplateMap = Dict[_string, StringWithLengthBetween0And32K]


class CreateIntegrationInput(TypedDict, total=False):
    ConnectionId: Optional[StringWithLengthBetween1And1024]
    ConnectionType: Optional[ConnectionType]
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    IntegrationMethod: Optional[StringWithLengthBetween1And64]
    IntegrationSubtype: Optional[StringWithLengthBetween1And128]
    IntegrationType: IntegrationType
    IntegrationUri: Optional[UriWithLengthBetween1And2048]
    PassthroughBehavior: Optional[PassthroughBehavior]
    PayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    RequestParameters: Optional[IntegrationParameters]
    RequestTemplates: Optional[TemplateMap]
    ResponseParameters: Optional[ResponseParameters]
    TemplateSelectionExpression: Optional[SelectionExpression]
    TimeoutInMillis: Optional[IntegerWithLengthBetween50And30000]
    TlsConfig: Optional[TlsConfigInput]


class CreateIntegrationRequest(ServiceRequest):
    ApiId: _string
    ConnectionId: Optional[StringWithLengthBetween1And1024]
    ConnectionType: Optional[ConnectionType]
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    IntegrationMethod: Optional[StringWithLengthBetween1And64]
    IntegrationSubtype: Optional[StringWithLengthBetween1And128]
    IntegrationType: IntegrationType
    IntegrationUri: Optional[UriWithLengthBetween1And2048]
    PassthroughBehavior: Optional[PassthroughBehavior]
    PayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    RequestParameters: Optional[IntegrationParameters]
    RequestTemplates: Optional[TemplateMap]
    ResponseParameters: Optional[ResponseParameters]
    TemplateSelectionExpression: Optional[SelectionExpression]
    TimeoutInMillis: Optional[IntegerWithLengthBetween50And30000]
    TlsConfig: Optional[TlsConfigInput]


class TlsConfig(TypedDict, total=False):
    ServerNameToVerify: Optional[StringWithLengthBetween1And512]


class CreateIntegrationResult(TypedDict, total=False):
    ApiGatewayManaged: Optional[_boolean]
    ConnectionId: Optional[StringWithLengthBetween1And1024]
    ConnectionType: Optional[ConnectionType]
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    IntegrationId: Optional[Id]
    IntegrationMethod: Optional[StringWithLengthBetween1And64]
    IntegrationResponseSelectionExpression: Optional[SelectionExpression]
    IntegrationSubtype: Optional[StringWithLengthBetween1And128]
    IntegrationType: Optional[IntegrationType]
    IntegrationUri: Optional[UriWithLengthBetween1And2048]
    PassthroughBehavior: Optional[PassthroughBehavior]
    PayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    RequestParameters: Optional[IntegrationParameters]
    RequestTemplates: Optional[TemplateMap]
    ResponseParameters: Optional[ResponseParameters]
    TemplateSelectionExpression: Optional[SelectionExpression]
    TimeoutInMillis: Optional[IntegerWithLengthBetween50And30000]
    TlsConfig: Optional[TlsConfig]


class CreateIntegrationResponseInput(TypedDict, total=False):
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    IntegrationResponseKey: SelectionKey
    ResponseParameters: Optional[IntegrationParameters]
    ResponseTemplates: Optional[TemplateMap]
    TemplateSelectionExpression: Optional[SelectionExpression]


class CreateIntegrationResponseRequest(ServiceRequest):
    ApiId: _string
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    IntegrationId: _string
    IntegrationResponseKey: SelectionKey
    ResponseParameters: Optional[IntegrationParameters]
    ResponseTemplates: Optional[TemplateMap]
    TemplateSelectionExpression: Optional[SelectionExpression]


class CreateIntegrationResponseResponse(TypedDict, total=False):
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    IntegrationResponseId: Optional[Id]
    IntegrationResponseKey: Optional[SelectionKey]
    ResponseParameters: Optional[IntegrationParameters]
    ResponseTemplates: Optional[TemplateMap]
    TemplateSelectionExpression: Optional[SelectionExpression]


class CreateModelInput(TypedDict, total=False):
    ContentType: Optional[StringWithLengthBetween1And256]
    Description: Optional[StringWithLengthBetween0And1024]
    Name: StringWithLengthBetween1And128
    Schema: StringWithLengthBetween0And32K


class CreateModelRequest(ServiceRequest):
    ApiId: _string
    ContentType: Optional[StringWithLengthBetween1And256]
    Description: Optional[StringWithLengthBetween0And1024]
    Name: StringWithLengthBetween1And128
    Schema: StringWithLengthBetween0And32K


class CreateModelResponse(TypedDict, total=False):
    ContentType: Optional[StringWithLengthBetween1And256]
    Description: Optional[StringWithLengthBetween0And1024]
    ModelId: Optional[Id]
    Name: Optional[StringWithLengthBetween1And128]
    Schema: Optional[StringWithLengthBetween0And32K]


class ParameterConstraints(TypedDict, total=False):
    Required: Optional[_boolean]


RouteParameters = Dict[_string, ParameterConstraints]
RouteModels = Dict[_string, StringWithLengthBetween1And128]


class CreateRouteInput(TypedDict, total=False):
    ApiKeyRequired: Optional[_boolean]
    AuthorizationScopes: Optional[AuthorizationScopes]
    AuthorizationType: Optional[AuthorizationType]
    AuthorizerId: Optional[Id]
    ModelSelectionExpression: Optional[SelectionExpression]
    OperationName: Optional[StringWithLengthBetween1And64]
    RequestModels: Optional[RouteModels]
    RequestParameters: Optional[RouteParameters]
    RouteKey: SelectionKey
    RouteResponseSelectionExpression: Optional[SelectionExpression]
    Target: Optional[StringWithLengthBetween1And128]


class CreateRouteRequest(ServiceRequest):
    ApiId: _string
    ApiKeyRequired: Optional[_boolean]
    AuthorizationScopes: Optional[AuthorizationScopes]
    AuthorizationType: Optional[AuthorizationType]
    AuthorizerId: Optional[Id]
    ModelSelectionExpression: Optional[SelectionExpression]
    OperationName: Optional[StringWithLengthBetween1And64]
    RequestModels: Optional[RouteModels]
    RequestParameters: Optional[RouteParameters]
    RouteKey: SelectionKey
    RouteResponseSelectionExpression: Optional[SelectionExpression]
    Target: Optional[StringWithLengthBetween1And128]


class CreateRouteResult(TypedDict, total=False):
    ApiGatewayManaged: Optional[_boolean]
    ApiKeyRequired: Optional[_boolean]
    AuthorizationScopes: Optional[AuthorizationScopes]
    AuthorizationType: Optional[AuthorizationType]
    AuthorizerId: Optional[Id]
    ModelSelectionExpression: Optional[SelectionExpression]
    OperationName: Optional[StringWithLengthBetween1And64]
    RequestModels: Optional[RouteModels]
    RequestParameters: Optional[RouteParameters]
    RouteId: Optional[Id]
    RouteKey: Optional[SelectionKey]
    RouteResponseSelectionExpression: Optional[SelectionExpression]
    Target: Optional[StringWithLengthBetween1And128]


class CreateRouteResponseInput(TypedDict, total=False):
    ModelSelectionExpression: Optional[SelectionExpression]
    ResponseModels: Optional[RouteModels]
    ResponseParameters: Optional[RouteParameters]
    RouteResponseKey: SelectionKey


class CreateRouteResponseRequest(ServiceRequest):
    ApiId: _string
    ModelSelectionExpression: Optional[SelectionExpression]
    ResponseModels: Optional[RouteModels]
    ResponseParameters: Optional[RouteParameters]
    RouteId: _string
    RouteResponseKey: SelectionKey


class CreateRouteResponseResponse(TypedDict, total=False):
    ModelSelectionExpression: Optional[SelectionExpression]
    ResponseModels: Optional[RouteModels]
    ResponseParameters: Optional[RouteParameters]
    RouteResponseId: Optional[Id]
    RouteResponseKey: Optional[SelectionKey]


StageVariablesMap = Dict[_string, StringWithLengthBetween0And2048]


class RouteSettings(TypedDict, total=False):
    DataTraceEnabled: Optional[_boolean]
    DetailedMetricsEnabled: Optional[_boolean]
    LoggingLevel: Optional[LoggingLevel]
    ThrottlingBurstLimit: Optional[_integer]
    ThrottlingRateLimit: Optional[_double]


RouteSettingsMap = Dict[_string, RouteSettings]


class CreateStageInput(TypedDict, total=False):
    AccessLogSettings: Optional[AccessLogSettings]
    AutoDeploy: Optional[_boolean]
    ClientCertificateId: Optional[Id]
    DefaultRouteSettings: Optional[RouteSettings]
    DeploymentId: Optional[Id]
    Description: Optional[StringWithLengthBetween0And1024]
    RouteSettings: Optional[RouteSettingsMap]
    StageName: StringWithLengthBetween1And128
    StageVariables: Optional[StageVariablesMap]
    Tags: Optional[Tags]


class CreateStageRequest(ServiceRequest):
    AccessLogSettings: Optional[AccessLogSettings]
    ApiId: _string
    AutoDeploy: Optional[_boolean]
    ClientCertificateId: Optional[Id]
    DefaultRouteSettings: Optional[RouteSettings]
    DeploymentId: Optional[Id]
    Description: Optional[StringWithLengthBetween0And1024]
    RouteSettings: Optional[RouteSettingsMap]
    StageName: StringWithLengthBetween1And128
    StageVariables: Optional[StageVariablesMap]
    Tags: Optional[Tags]


class CreateStageResponse(TypedDict, total=False):
    AccessLogSettings: Optional[AccessLogSettings]
    ApiGatewayManaged: Optional[_boolean]
    AutoDeploy: Optional[_boolean]
    ClientCertificateId: Optional[Id]
    CreatedDate: Optional[_timestampIso8601]
    DefaultRouteSettings: Optional[RouteSettings]
    DeploymentId: Optional[Id]
    Description: Optional[StringWithLengthBetween0And1024]
    LastDeploymentStatusMessage: Optional[_string]
    LastUpdatedDate: Optional[_timestampIso8601]
    RouteSettings: Optional[RouteSettingsMap]
    StageName: Optional[StringWithLengthBetween1And128]
    StageVariables: Optional[StageVariablesMap]
    Tags: Optional[Tags]


SubnetIdList = List[_string]
SecurityGroupIdList = List[_string]


class CreateVpcLinkInput(TypedDict, total=False):
    Name: StringWithLengthBetween1And128
    SecurityGroupIds: Optional[SecurityGroupIdList]
    SubnetIds: SubnetIdList
    Tags: Optional[Tags]


class CreateVpcLinkRequest(ServiceRequest):
    Name: StringWithLengthBetween1And128
    SecurityGroupIds: Optional[SecurityGroupIdList]
    SubnetIds: SubnetIdList
    Tags: Optional[Tags]


class CreateVpcLinkResponse(TypedDict, total=False):
    CreatedDate: Optional[_timestampIso8601]
    Name: Optional[StringWithLengthBetween1And128]
    SecurityGroupIds: Optional[SecurityGroupIdList]
    SubnetIds: Optional[SubnetIdList]
    Tags: Optional[Tags]
    VpcLinkId: Optional[Id]
    VpcLinkStatus: Optional[VpcLinkStatus]
    VpcLinkStatusMessage: Optional[StringWithLengthBetween0And1024]
    VpcLinkVersion: Optional[VpcLinkVersion]


class DeleteAccessLogSettingsRequest(ServiceRequest):
    ApiId: _string
    StageName: _string


class DeleteApiMappingRequest(ServiceRequest):
    ApiMappingId: _string
    DomainName: _string


class DeleteApiRequest(ServiceRequest):
    ApiId: _string


class DeleteAuthorizerRequest(ServiceRequest):
    ApiId: _string
    AuthorizerId: _string


class DeleteCorsConfigurationRequest(ServiceRequest):
    ApiId: _string


class DeleteDeploymentRequest(ServiceRequest):
    ApiId: _string
    DeploymentId: _string


class DeleteDomainNameRequest(ServiceRequest):
    DomainName: _string


class DeleteIntegrationRequest(ServiceRequest):
    ApiId: _string
    IntegrationId: _string


class DeleteIntegrationResponseRequest(ServiceRequest):
    ApiId: _string
    IntegrationId: _string
    IntegrationResponseId: _string


class DeleteModelRequest(ServiceRequest):
    ApiId: _string
    ModelId: _string


class DeleteRouteRequest(ServiceRequest):
    ApiId: _string
    RouteId: _string


class DeleteRouteRequestParameterRequest(ServiceRequest):
    ApiId: _string
    RequestParameterKey: _string
    RouteId: _string


class DeleteRouteResponseRequest(ServiceRequest):
    ApiId: _string
    RouteId: _string
    RouteResponseId: _string


class DeleteRouteSettingsRequest(ServiceRequest):
    ApiId: _string
    RouteKey: _string
    StageName: _string


class DeleteStageRequest(ServiceRequest):
    ApiId: _string
    StageName: _string


class DeleteVpcLinkRequest(ServiceRequest):
    VpcLinkId: _string


class DeleteVpcLinkResponse(TypedDict, total=False):
    pass


class Deployment(TypedDict, total=False):
    AutoDeployed: Optional[_boolean]
    CreatedDate: Optional[_timestampIso8601]
    DeploymentId: Optional[Id]
    DeploymentStatus: Optional[DeploymentStatus]
    DeploymentStatusMessage: Optional[_string]
    Description: Optional[StringWithLengthBetween0And1024]


_listOfDeployment = List[Deployment]


class Deployments(TypedDict, total=False):
    Items: Optional[_listOfDeployment]
    NextToken: Optional[NextToken]


class DomainName(TypedDict, total=False):
    ApiMappingSelectionExpression: Optional[SelectionExpression]
    DomainName: StringWithLengthBetween1And512
    DomainNameConfigurations: Optional[DomainNameConfigurations]
    MutualTlsAuthentication: Optional[MutualTlsAuthentication]
    Tags: Optional[Tags]


_listOfDomainName = List[DomainName]


class DomainNames(TypedDict, total=False):
    Items: Optional[_listOfDomainName]
    NextToken: Optional[NextToken]


class ExportApiRequest(ServiceRequest):
    ApiId: _string
    ExportVersion: Optional[_string]
    IncludeExtensions: Optional[_boolean]
    OutputType: _string
    Specification: _string
    StageName: Optional[_string]


ExportedApi = bytes


class ExportApiResponse(TypedDict, total=False):
    body: Optional[ExportedApi]


class ResetAuthorizersCacheRequest(ServiceRequest):
    ApiId: _string
    StageName: _string


class GetApiMappingRequest(ServiceRequest):
    ApiMappingId: _string
    DomainName: _string


class GetApiMappingResponse(TypedDict, total=False):
    ApiId: Optional[Id]
    ApiMappingId: Optional[Id]
    ApiMappingKey: Optional[SelectionKey]
    Stage: Optional[StringWithLengthBetween1And128]


class GetApiMappingsRequest(ServiceRequest):
    DomainName: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class GetApiMappingsResponse(TypedDict, total=False):
    Items: Optional[_listOfApiMapping]
    NextToken: Optional[NextToken]


class GetApiRequest(ServiceRequest):
    ApiId: _string


class GetApiResponse(TypedDict, total=False):
    ApiEndpoint: Optional[_string]
    ApiGatewayManaged: Optional[_boolean]
    ApiId: Optional[Id]
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CreatedDate: Optional[_timestampIso8601]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    ImportInfo: Optional[_listOf__string]
    Name: Optional[StringWithLengthBetween1And128]
    ProtocolType: Optional[ProtocolType]
    RouteSelectionExpression: Optional[SelectionExpression]
    Tags: Optional[Tags]
    Version: Optional[StringWithLengthBetween1And64]
    Warnings: Optional[_listOf__string]


class GetApisRequest(ServiceRequest):
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class GetApisResponse(TypedDict, total=False):
    Items: Optional[_listOfApi]
    NextToken: Optional[NextToken]


class GetAuthorizerRequest(ServiceRequest):
    ApiId: _string
    AuthorizerId: _string


class GetAuthorizerResponse(TypedDict, total=False):
    AuthorizerCredentialsArn: Optional[Arn]
    AuthorizerId: Optional[Id]
    AuthorizerPayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    AuthorizerResultTtlInSeconds: Optional[IntegerWithLengthBetween0And3600]
    AuthorizerType: Optional[AuthorizerType]
    AuthorizerUri: Optional[UriWithLengthBetween1And2048]
    EnableSimpleResponses: Optional[_boolean]
    IdentitySource: Optional[IdentitySourceList]
    IdentityValidationExpression: Optional[StringWithLengthBetween0And1024]
    JwtConfiguration: Optional[JWTConfiguration]
    Name: Optional[StringWithLengthBetween1And128]


class GetAuthorizersRequest(ServiceRequest):
    ApiId: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class GetAuthorizersResponse(TypedDict, total=False):
    Items: Optional[_listOfAuthorizer]
    NextToken: Optional[NextToken]


class GetDeploymentRequest(ServiceRequest):
    ApiId: _string
    DeploymentId: _string


class GetDeploymentResponse(TypedDict, total=False):
    AutoDeployed: Optional[_boolean]
    CreatedDate: Optional[_timestampIso8601]
    DeploymentId: Optional[Id]
    DeploymentStatus: Optional[DeploymentStatus]
    DeploymentStatusMessage: Optional[_string]
    Description: Optional[StringWithLengthBetween0And1024]


class GetDeploymentsRequest(ServiceRequest):
    ApiId: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class GetDeploymentsResponse(TypedDict, total=False):
    Items: Optional[_listOfDeployment]
    NextToken: Optional[NextToken]


class GetDomainNameRequest(ServiceRequest):
    DomainName: _string


class GetDomainNameResponse(TypedDict, total=False):
    ApiMappingSelectionExpression: Optional[SelectionExpression]
    DomainName: Optional[StringWithLengthBetween1And512]
    DomainNameConfigurations: Optional[DomainNameConfigurations]
    MutualTlsAuthentication: Optional[MutualTlsAuthentication]
    Tags: Optional[Tags]


class GetDomainNamesRequest(ServiceRequest):
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class GetDomainNamesResponse(TypedDict, total=False):
    Items: Optional[_listOfDomainName]
    NextToken: Optional[NextToken]


class GetIntegrationRequest(ServiceRequest):
    ApiId: _string
    IntegrationId: _string


class GetIntegrationResult(TypedDict, total=False):
    ApiGatewayManaged: Optional[_boolean]
    ConnectionId: Optional[StringWithLengthBetween1And1024]
    ConnectionType: Optional[ConnectionType]
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    IntegrationId: Optional[Id]
    IntegrationMethod: Optional[StringWithLengthBetween1And64]
    IntegrationResponseSelectionExpression: Optional[SelectionExpression]
    IntegrationSubtype: Optional[StringWithLengthBetween1And128]
    IntegrationType: Optional[IntegrationType]
    IntegrationUri: Optional[UriWithLengthBetween1And2048]
    PassthroughBehavior: Optional[PassthroughBehavior]
    PayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    RequestParameters: Optional[IntegrationParameters]
    RequestTemplates: Optional[TemplateMap]
    ResponseParameters: Optional[ResponseParameters]
    TemplateSelectionExpression: Optional[SelectionExpression]
    TimeoutInMillis: Optional[IntegerWithLengthBetween50And30000]
    TlsConfig: Optional[TlsConfig]


class GetIntegrationResponseRequest(ServiceRequest):
    ApiId: _string
    IntegrationId: _string
    IntegrationResponseId: _string


class GetIntegrationResponseResponse(TypedDict, total=False):
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    IntegrationResponseId: Optional[Id]
    IntegrationResponseKey: Optional[SelectionKey]
    ResponseParameters: Optional[IntegrationParameters]
    ResponseTemplates: Optional[TemplateMap]
    TemplateSelectionExpression: Optional[SelectionExpression]


class GetIntegrationResponsesRequest(ServiceRequest):
    ApiId: _string
    IntegrationId: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class IntegrationResponse(TypedDict, total=False):
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    IntegrationResponseId: Optional[Id]
    IntegrationResponseKey: SelectionKey
    ResponseParameters: Optional[IntegrationParameters]
    ResponseTemplates: Optional[TemplateMap]
    TemplateSelectionExpression: Optional[SelectionExpression]


_listOfIntegrationResponse = List[IntegrationResponse]


class GetIntegrationResponsesResponse(TypedDict, total=False):
    Items: Optional[_listOfIntegrationResponse]
    NextToken: Optional[NextToken]


class GetIntegrationsRequest(ServiceRequest):
    ApiId: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class Integration(TypedDict, total=False):
    ApiGatewayManaged: Optional[_boolean]
    ConnectionId: Optional[StringWithLengthBetween1And1024]
    ConnectionType: Optional[ConnectionType]
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    IntegrationId: Optional[Id]
    IntegrationMethod: Optional[StringWithLengthBetween1And64]
    IntegrationResponseSelectionExpression: Optional[SelectionExpression]
    IntegrationSubtype: Optional[StringWithLengthBetween1And128]
    IntegrationType: Optional[IntegrationType]
    IntegrationUri: Optional[UriWithLengthBetween1And2048]
    PassthroughBehavior: Optional[PassthroughBehavior]
    PayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    RequestParameters: Optional[IntegrationParameters]
    RequestTemplates: Optional[TemplateMap]
    ResponseParameters: Optional[ResponseParameters]
    TemplateSelectionExpression: Optional[SelectionExpression]
    TimeoutInMillis: Optional[IntegerWithLengthBetween50And30000]
    TlsConfig: Optional[TlsConfig]


_listOfIntegration = List[Integration]


class GetIntegrationsResponse(TypedDict, total=False):
    Items: Optional[_listOfIntegration]
    NextToken: Optional[NextToken]


class GetModelRequest(ServiceRequest):
    ApiId: _string
    ModelId: _string


class GetModelResponse(TypedDict, total=False):
    ContentType: Optional[StringWithLengthBetween1And256]
    Description: Optional[StringWithLengthBetween0And1024]
    ModelId: Optional[Id]
    Name: Optional[StringWithLengthBetween1And128]
    Schema: Optional[StringWithLengthBetween0And32K]


class GetModelTemplateRequest(ServiceRequest):
    ApiId: _string
    ModelId: _string


class GetModelTemplateResponse(TypedDict, total=False):
    Value: Optional[_string]


class GetModelsRequest(ServiceRequest):
    ApiId: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class Model(TypedDict, total=False):
    ContentType: Optional[StringWithLengthBetween1And256]
    Description: Optional[StringWithLengthBetween0And1024]
    ModelId: Optional[Id]
    Name: StringWithLengthBetween1And128
    Schema: Optional[StringWithLengthBetween0And32K]


_listOfModel = List[Model]


class GetModelsResponse(TypedDict, total=False):
    Items: Optional[_listOfModel]
    NextToken: Optional[NextToken]


class GetRouteRequest(ServiceRequest):
    ApiId: _string
    RouteId: _string


class GetRouteResult(TypedDict, total=False):
    ApiGatewayManaged: Optional[_boolean]
    ApiKeyRequired: Optional[_boolean]
    AuthorizationScopes: Optional[AuthorizationScopes]
    AuthorizationType: Optional[AuthorizationType]
    AuthorizerId: Optional[Id]
    ModelSelectionExpression: Optional[SelectionExpression]
    OperationName: Optional[StringWithLengthBetween1And64]
    RequestModels: Optional[RouteModels]
    RequestParameters: Optional[RouteParameters]
    RouteId: Optional[Id]
    RouteKey: Optional[SelectionKey]
    RouteResponseSelectionExpression: Optional[SelectionExpression]
    Target: Optional[StringWithLengthBetween1And128]


class GetRouteResponseRequest(ServiceRequest):
    ApiId: _string
    RouteId: _string
    RouteResponseId: _string


class GetRouteResponseResponse(TypedDict, total=False):
    ModelSelectionExpression: Optional[SelectionExpression]
    ResponseModels: Optional[RouteModels]
    ResponseParameters: Optional[RouteParameters]
    RouteResponseId: Optional[Id]
    RouteResponseKey: Optional[SelectionKey]


class GetRouteResponsesRequest(ServiceRequest):
    ApiId: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]
    RouteId: _string


class RouteResponse(TypedDict, total=False):
    ModelSelectionExpression: Optional[SelectionExpression]
    ResponseModels: Optional[RouteModels]
    ResponseParameters: Optional[RouteParameters]
    RouteResponseId: Optional[Id]
    RouteResponseKey: SelectionKey


_listOfRouteResponse = List[RouteResponse]


class GetRouteResponsesResponse(TypedDict, total=False):
    Items: Optional[_listOfRouteResponse]
    NextToken: Optional[NextToken]


class GetRoutesRequest(ServiceRequest):
    ApiId: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class Route(TypedDict, total=False):
    ApiGatewayManaged: Optional[_boolean]
    ApiKeyRequired: Optional[_boolean]
    AuthorizationScopes: Optional[AuthorizationScopes]
    AuthorizationType: Optional[AuthorizationType]
    AuthorizerId: Optional[Id]
    ModelSelectionExpression: Optional[SelectionExpression]
    OperationName: Optional[StringWithLengthBetween1And64]
    RequestModels: Optional[RouteModels]
    RequestParameters: Optional[RouteParameters]
    RouteId: Optional[Id]
    RouteKey: SelectionKey
    RouteResponseSelectionExpression: Optional[SelectionExpression]
    Target: Optional[StringWithLengthBetween1And128]


_listOfRoute = List[Route]


class GetRoutesResponse(TypedDict, total=False):
    Items: Optional[_listOfRoute]
    NextToken: Optional[NextToken]


class GetStageRequest(ServiceRequest):
    ApiId: _string
    StageName: _string


class GetStageResponse(TypedDict, total=False):
    AccessLogSettings: Optional[AccessLogSettings]
    ApiGatewayManaged: Optional[_boolean]
    AutoDeploy: Optional[_boolean]
    ClientCertificateId: Optional[Id]
    CreatedDate: Optional[_timestampIso8601]
    DefaultRouteSettings: Optional[RouteSettings]
    DeploymentId: Optional[Id]
    Description: Optional[StringWithLengthBetween0And1024]
    LastDeploymentStatusMessage: Optional[_string]
    LastUpdatedDate: Optional[_timestampIso8601]
    RouteSettings: Optional[RouteSettingsMap]
    StageName: Optional[StringWithLengthBetween1And128]
    StageVariables: Optional[StageVariablesMap]
    Tags: Optional[Tags]


class GetStagesRequest(ServiceRequest):
    ApiId: _string
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class Stage(TypedDict, total=False):
    AccessLogSettings: Optional[AccessLogSettings]
    ApiGatewayManaged: Optional[_boolean]
    AutoDeploy: Optional[_boolean]
    ClientCertificateId: Optional[Id]
    CreatedDate: Optional[_timestampIso8601]
    DefaultRouteSettings: Optional[RouteSettings]
    DeploymentId: Optional[Id]
    Description: Optional[StringWithLengthBetween0And1024]
    LastDeploymentStatusMessage: Optional[_string]
    LastUpdatedDate: Optional[_timestampIso8601]
    RouteSettings: Optional[RouteSettingsMap]
    StageName: StringWithLengthBetween1And128
    StageVariables: Optional[StageVariablesMap]
    Tags: Optional[Tags]


_listOfStage = List[Stage]


class GetStagesResponse(TypedDict, total=False):
    Items: Optional[_listOfStage]
    NextToken: Optional[NextToken]


class GetTagsRequest(ServiceRequest):
    ResourceArn: _string


class GetTagsResponse(TypedDict, total=False):
    Tags: Optional[Tags]


class GetVpcLinkRequest(ServiceRequest):
    VpcLinkId: _string


class GetVpcLinkResponse(TypedDict, total=False):
    CreatedDate: Optional[_timestampIso8601]
    Name: Optional[StringWithLengthBetween1And128]
    SecurityGroupIds: Optional[SecurityGroupIdList]
    SubnetIds: Optional[SubnetIdList]
    Tags: Optional[Tags]
    VpcLinkId: Optional[Id]
    VpcLinkStatus: Optional[VpcLinkStatus]
    VpcLinkStatusMessage: Optional[StringWithLengthBetween0And1024]
    VpcLinkVersion: Optional[VpcLinkVersion]


class GetVpcLinksRequest(ServiceRequest):
    MaxResults: Optional[_string]
    NextToken: Optional[_string]


class VpcLink(TypedDict, total=False):
    CreatedDate: Optional[_timestampIso8601]
    Name: StringWithLengthBetween1And128
    SecurityGroupIds: SecurityGroupIdList
    SubnetIds: SubnetIdList
    Tags: Optional[Tags]
    VpcLinkId: Id
    VpcLinkStatus: Optional[VpcLinkStatus]
    VpcLinkStatusMessage: Optional[StringWithLengthBetween0And1024]
    VpcLinkVersion: Optional[VpcLinkVersion]


_listOfVpcLink = List[VpcLink]


class GetVpcLinksResponse(TypedDict, total=False):
    Items: Optional[_listOfVpcLink]
    NextToken: Optional[NextToken]


class ImportApiInput(TypedDict, total=False):
    Body: _string


class ImportApiRequest(ServiceRequest):
    Basepath: Optional[_string]
    Body: _string
    FailOnWarnings: Optional[_boolean]


class ImportApiResponse(TypedDict, total=False):
    ApiEndpoint: Optional[_string]
    ApiGatewayManaged: Optional[_boolean]
    ApiId: Optional[Id]
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CreatedDate: Optional[_timestampIso8601]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    ImportInfo: Optional[_listOf__string]
    Name: Optional[StringWithLengthBetween1And128]
    ProtocolType: Optional[ProtocolType]
    RouteSelectionExpression: Optional[SelectionExpression]
    Tags: Optional[Tags]
    Version: Optional[StringWithLengthBetween1And64]
    Warnings: Optional[_listOf__string]


class IntegrationResponses(TypedDict, total=False):
    Items: Optional[_listOfIntegrationResponse]
    NextToken: Optional[NextToken]


class Integrations(TypedDict, total=False):
    Items: Optional[_listOfIntegration]
    NextToken: Optional[NextToken]


class LimitExceededException(TypedDict, total=False):
    LimitType: Optional[_string]
    Message: Optional[_string]


class Models(TypedDict, total=False):
    Items: Optional[_listOfModel]
    NextToken: Optional[NextToken]


class ReimportApiInput(TypedDict, total=False):
    Body: _string


class ReimportApiRequest(ServiceRequest):
    ApiId: _string
    Basepath: Optional[_string]
    Body: _string
    FailOnWarnings: Optional[_boolean]


class ReimportApiResponse(TypedDict, total=False):
    ApiEndpoint: Optional[_string]
    ApiGatewayManaged: Optional[_boolean]
    ApiId: Optional[Id]
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CreatedDate: Optional[_timestampIso8601]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    ImportInfo: Optional[_listOf__string]
    Name: Optional[StringWithLengthBetween1And128]
    ProtocolType: Optional[ProtocolType]
    RouteSelectionExpression: Optional[SelectionExpression]
    Tags: Optional[Tags]
    Version: Optional[StringWithLengthBetween1And64]
    Warnings: Optional[_listOf__string]


class RouteResponses(TypedDict, total=False):
    Items: Optional[_listOfRouteResponse]
    NextToken: Optional[NextToken]


class Routes(TypedDict, total=False):
    Items: Optional[_listOfRoute]
    NextToken: Optional[NextToken]


class Stages(TypedDict, total=False):
    Items: Optional[_listOfStage]
    NextToken: Optional[NextToken]


class TagResourceInput(TypedDict, total=False):
    Tags: Optional[Tags]


class TagResourceRequest(ServiceRequest):
    ResourceArn: _string
    Tags: Optional[Tags]


class TagResourceResponse(TypedDict, total=False):
    pass


class Template(TypedDict, total=False):
    Value: Optional[_string]


class UntagResourceRequest(ServiceRequest):
    ResourceArn: _string
    TagKeys: _listOf__string


class UpdateApiInput(TypedDict, total=False):
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableExecuteApiEndpoint: Optional[_boolean]
    DisableSchemaValidation: Optional[_boolean]
    Name: Optional[StringWithLengthBetween1And128]
    RouteKey: Optional[SelectionKey]
    RouteSelectionExpression: Optional[SelectionExpression]
    Target: Optional[UriWithLengthBetween1And2048]
    Version: Optional[StringWithLengthBetween1And64]


class UpdateApiMappingInput(TypedDict, total=False):
    ApiId: Optional[Id]
    ApiMappingKey: Optional[SelectionKey]
    Stage: Optional[StringWithLengthBetween1And128]


class UpdateApiMappingRequest(ServiceRequest):
    ApiId: Id
    ApiMappingId: _string
    ApiMappingKey: Optional[SelectionKey]
    DomainName: _string
    Stage: Optional[StringWithLengthBetween1And128]


class UpdateApiMappingResponse(TypedDict, total=False):
    ApiId: Optional[Id]
    ApiMappingId: Optional[Id]
    ApiMappingKey: Optional[SelectionKey]
    Stage: Optional[StringWithLengthBetween1And128]


class UpdateApiRequest(ServiceRequest):
    ApiId: _string
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    Name: Optional[StringWithLengthBetween1And128]
    RouteKey: Optional[SelectionKey]
    RouteSelectionExpression: Optional[SelectionExpression]
    Target: Optional[UriWithLengthBetween1And2048]
    Version: Optional[StringWithLengthBetween1And64]


class UpdateApiResponse(TypedDict, total=False):
    ApiEndpoint: Optional[_string]
    ApiGatewayManaged: Optional[_boolean]
    ApiId: Optional[Id]
    ApiKeySelectionExpression: Optional[SelectionExpression]
    CorsConfiguration: Optional[Cors]
    CreatedDate: Optional[_timestampIso8601]
    Description: Optional[StringWithLengthBetween0And1024]
    DisableSchemaValidation: Optional[_boolean]
    DisableExecuteApiEndpoint: Optional[_boolean]
    ImportInfo: Optional[_listOf__string]
    Name: Optional[StringWithLengthBetween1And128]
    ProtocolType: Optional[ProtocolType]
    RouteSelectionExpression: Optional[SelectionExpression]
    Tags: Optional[Tags]
    Version: Optional[StringWithLengthBetween1And64]
    Warnings: Optional[_listOf__string]


class UpdateAuthorizerInput(TypedDict, total=False):
    AuthorizerCredentialsArn: Optional[Arn]
    AuthorizerPayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    AuthorizerResultTtlInSeconds: Optional[IntegerWithLengthBetween0And3600]
    AuthorizerType: Optional[AuthorizerType]
    AuthorizerUri: Optional[UriWithLengthBetween1And2048]
    EnableSimpleResponses: Optional[_boolean]
    IdentitySource: Optional[IdentitySourceList]
    IdentityValidationExpression: Optional[StringWithLengthBetween0And1024]
    JwtConfiguration: Optional[JWTConfiguration]
    Name: Optional[StringWithLengthBetween1And128]


class UpdateAuthorizerRequest(ServiceRequest):
    ApiId: _string
    AuthorizerCredentialsArn: Optional[Arn]
    AuthorizerId: _string
    AuthorizerPayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    AuthorizerResultTtlInSeconds: Optional[IntegerWithLengthBetween0And3600]
    AuthorizerType: Optional[AuthorizerType]
    AuthorizerUri: Optional[UriWithLengthBetween1And2048]
    EnableSimpleResponses: Optional[_boolean]
    IdentitySource: Optional[IdentitySourceList]
    IdentityValidationExpression: Optional[StringWithLengthBetween0And1024]
    JwtConfiguration: Optional[JWTConfiguration]
    Name: Optional[StringWithLengthBetween1And128]


class UpdateAuthorizerResponse(TypedDict, total=False):
    AuthorizerCredentialsArn: Optional[Arn]
    AuthorizerId: Optional[Id]
    AuthorizerPayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    AuthorizerResultTtlInSeconds: Optional[IntegerWithLengthBetween0And3600]
    AuthorizerType: Optional[AuthorizerType]
    AuthorizerUri: Optional[UriWithLengthBetween1And2048]
    EnableSimpleResponses: Optional[_boolean]
    IdentitySource: Optional[IdentitySourceList]
    IdentityValidationExpression: Optional[StringWithLengthBetween0And1024]
    JwtConfiguration: Optional[JWTConfiguration]
    Name: Optional[StringWithLengthBetween1And128]


class UpdateDeploymentInput(TypedDict, total=False):
    Description: Optional[StringWithLengthBetween0And1024]


class UpdateDeploymentRequest(ServiceRequest):
    ApiId: _string
    DeploymentId: _string
    Description: Optional[StringWithLengthBetween0And1024]


class UpdateDeploymentResponse(TypedDict, total=False):
    AutoDeployed: Optional[_boolean]
    CreatedDate: Optional[_timestampIso8601]
    DeploymentId: Optional[Id]
    DeploymentStatus: Optional[DeploymentStatus]
    DeploymentStatusMessage: Optional[_string]
    Description: Optional[StringWithLengthBetween0And1024]


class UpdateDomainNameInput(TypedDict, total=False):
    DomainNameConfigurations: Optional[DomainNameConfigurations]
    MutualTlsAuthentication: Optional[MutualTlsAuthenticationInput]


class UpdateDomainNameRequest(ServiceRequest):
    DomainName: _string
    DomainNameConfigurations: Optional[DomainNameConfigurations]
    MutualTlsAuthentication: Optional[MutualTlsAuthenticationInput]


class UpdateDomainNameResponse(TypedDict, total=False):
    ApiMappingSelectionExpression: Optional[SelectionExpression]
    DomainName: Optional[StringWithLengthBetween1And512]
    DomainNameConfigurations: Optional[DomainNameConfigurations]
    MutualTlsAuthentication: Optional[MutualTlsAuthentication]
    Tags: Optional[Tags]


class UpdateIntegrationInput(TypedDict, total=False):
    ConnectionId: Optional[StringWithLengthBetween1And1024]
    ConnectionType: Optional[ConnectionType]
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    IntegrationMethod: Optional[StringWithLengthBetween1And64]
    IntegrationSubtype: Optional[StringWithLengthBetween1And128]
    IntegrationType: Optional[IntegrationType]
    IntegrationUri: Optional[UriWithLengthBetween1And2048]
    PassthroughBehavior: Optional[PassthroughBehavior]
    PayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    RequestParameters: Optional[IntegrationParameters]
    RequestTemplates: Optional[TemplateMap]
    ResponseParameters: Optional[ResponseParameters]
    TemplateSelectionExpression: Optional[SelectionExpression]
    TimeoutInMillis: Optional[IntegerWithLengthBetween50And30000]
    TlsConfig: Optional[TlsConfigInput]


class UpdateIntegrationRequest(ServiceRequest):
    ApiId: _string
    ConnectionId: Optional[StringWithLengthBetween1And1024]
    ConnectionType: Optional[ConnectionType]
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    IntegrationId: _string
    IntegrationMethod: Optional[StringWithLengthBetween1And64]
    IntegrationSubtype: Optional[StringWithLengthBetween1And128]
    IntegrationType: Optional[IntegrationType]
    IntegrationUri: Optional[UriWithLengthBetween1And2048]
    PassthroughBehavior: Optional[PassthroughBehavior]
    PayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    RequestParameters: Optional[IntegrationParameters]
    RequestTemplates: Optional[TemplateMap]
    ResponseParameters: Optional[ResponseParameters]
    TemplateSelectionExpression: Optional[SelectionExpression]
    TimeoutInMillis: Optional[IntegerWithLengthBetween50And30000]
    TlsConfig: Optional[TlsConfigInput]


class UpdateIntegrationResult(TypedDict, total=False):
    ApiGatewayManaged: Optional[_boolean]
    ConnectionId: Optional[StringWithLengthBetween1And1024]
    ConnectionType: Optional[ConnectionType]
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    CredentialsArn: Optional[Arn]
    Description: Optional[StringWithLengthBetween0And1024]
    IntegrationId: Optional[Id]
    IntegrationMethod: Optional[StringWithLengthBetween1And64]
    IntegrationResponseSelectionExpression: Optional[SelectionExpression]
    IntegrationSubtype: Optional[StringWithLengthBetween1And128]
    IntegrationType: Optional[IntegrationType]
    IntegrationUri: Optional[UriWithLengthBetween1And2048]
    PassthroughBehavior: Optional[PassthroughBehavior]
    PayloadFormatVersion: Optional[StringWithLengthBetween1And64]
    RequestParameters: Optional[IntegrationParameters]
    RequestTemplates: Optional[TemplateMap]
    ResponseParameters: Optional[ResponseParameters]
    TemplateSelectionExpression: Optional[SelectionExpression]
    TimeoutInMillis: Optional[IntegerWithLengthBetween50And30000]
    TlsConfig: Optional[TlsConfig]


class UpdateIntegrationResponseInput(TypedDict, total=False):
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    IntegrationResponseKey: Optional[SelectionKey]
    ResponseParameters: Optional[IntegrationParameters]
    ResponseTemplates: Optional[TemplateMap]
    TemplateSelectionExpression: Optional[SelectionExpression]


class UpdateIntegrationResponseRequest(ServiceRequest):
    ApiId: _string
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    IntegrationId: _string
    IntegrationResponseId: _string
    IntegrationResponseKey: Optional[SelectionKey]
    ResponseParameters: Optional[IntegrationParameters]
    ResponseTemplates: Optional[TemplateMap]
    TemplateSelectionExpression: Optional[SelectionExpression]


class UpdateIntegrationResponseResponse(TypedDict, total=False):
    ContentHandlingStrategy: Optional[ContentHandlingStrategy]
    IntegrationResponseId: Optional[Id]
    IntegrationResponseKey: Optional[SelectionKey]
    ResponseParameters: Optional[IntegrationParameters]
    ResponseTemplates: Optional[TemplateMap]
    TemplateSelectionExpression: Optional[SelectionExpression]


class UpdateModelInput(TypedDict, total=False):
    ContentType: Optional[StringWithLengthBetween1And256]
    Description: Optional[StringWithLengthBetween0And1024]
    Name: Optional[StringWithLengthBetween1And128]
    Schema: Optional[StringWithLengthBetween0And32K]


class UpdateModelRequest(ServiceRequest):
    ApiId: _string
    ContentType: Optional[StringWithLengthBetween1And256]
    Description: Optional[StringWithLengthBetween0And1024]
    ModelId: _string
    Name: Optional[StringWithLengthBetween1And128]
    Schema: Optional[StringWithLengthBetween0And32K]


class UpdateModelResponse(TypedDict, total=False):
    ContentType: Optional[StringWithLengthBetween1And256]
    Description: Optional[StringWithLengthBetween0And1024]
    ModelId: Optional[Id]
    Name: Optional[StringWithLengthBetween1And128]
    Schema: Optional[StringWithLengthBetween0And32K]


class UpdateRouteInput(TypedDict, total=False):
    ApiKeyRequired: Optional[_boolean]
    AuthorizationScopes: Optional[AuthorizationScopes]
    AuthorizationType: Optional[AuthorizationType]
    AuthorizerId: Optional[Id]
    ModelSelectionExpression: Optional[SelectionExpression]
    OperationName: Optional[StringWithLengthBetween1And64]
    RequestModels: Optional[RouteModels]
    RequestParameters: Optional[RouteParameters]
    RouteKey: Optional[SelectionKey]
    RouteResponseSelectionExpression: Optional[SelectionExpression]
    Target: Optional[StringWithLengthBetween1And128]


class UpdateRouteRequest(ServiceRequest):
    ApiId: _string
    ApiKeyRequired: Optional[_boolean]
    AuthorizationScopes: Optional[AuthorizationScopes]
    AuthorizationType: Optional[AuthorizationType]
    AuthorizerId: Optional[Id]
    ModelSelectionExpression: Optional[SelectionExpression]
    OperationName: Optional[StringWithLengthBetween1And64]
    RequestModels: Optional[RouteModels]
    RequestParameters: Optional[RouteParameters]
    RouteId: _string
    RouteKey: Optional[SelectionKey]
    RouteResponseSelectionExpression: Optional[SelectionExpression]
    Target: Optional[StringWithLengthBetween1And128]


class UpdateRouteResult(TypedDict, total=False):
    ApiGatewayManaged: Optional[_boolean]
    ApiKeyRequired: Optional[_boolean]
    AuthorizationScopes: Optional[AuthorizationScopes]
    AuthorizationType: Optional[AuthorizationType]
    AuthorizerId: Optional[Id]
    ModelSelectionExpression: Optional[SelectionExpression]
    OperationName: Optional[StringWithLengthBetween1And64]
    RequestModels: Optional[RouteModels]
    RequestParameters: Optional[RouteParameters]
    RouteId: Optional[Id]
    RouteKey: Optional[SelectionKey]
    RouteResponseSelectionExpression: Optional[SelectionExpression]
    Target: Optional[StringWithLengthBetween1And128]


class UpdateRouteResponseInput(TypedDict, total=False):
    ModelSelectionExpression: Optional[SelectionExpression]
    ResponseModels: Optional[RouteModels]
    ResponseParameters: Optional[RouteParameters]
    RouteResponseKey: Optional[SelectionKey]


class UpdateRouteResponseRequest(ServiceRequest):
    ApiId: _string
    ModelSelectionExpression: Optional[SelectionExpression]
    ResponseModels: Optional[RouteModels]
    ResponseParameters: Optional[RouteParameters]
    RouteId: _string
    RouteResponseId: _string
    RouteResponseKey: Optional[SelectionKey]


class UpdateRouteResponseResponse(TypedDict, total=False):
    ModelSelectionExpression: Optional[SelectionExpression]
    ResponseModels: Optional[RouteModels]
    ResponseParameters: Optional[RouteParameters]
    RouteResponseId: Optional[Id]
    RouteResponseKey: Optional[SelectionKey]


class UpdateStageInput(TypedDict, total=False):
    AccessLogSettings: Optional[AccessLogSettings]
    AutoDeploy: Optional[_boolean]
    ClientCertificateId: Optional[Id]
    DefaultRouteSettings: Optional[RouteSettings]
    DeploymentId: Optional[Id]
    Description: Optional[StringWithLengthBetween0And1024]
    RouteSettings: Optional[RouteSettingsMap]
    StageVariables: Optional[StageVariablesMap]


class UpdateStageRequest(ServiceRequest):
    AccessLogSettings: Optional[AccessLogSettings]
    ApiId: _string
    AutoDeploy: Optional[_boolean]
    ClientCertificateId: Optional[Id]
    DefaultRouteSettings: Optional[RouteSettings]
    DeploymentId: Optional[Id]
    Description: Optional[StringWithLengthBetween0And1024]
    RouteSettings: Optional[RouteSettingsMap]
    StageName: _string
    StageVariables: Optional[StageVariablesMap]


class UpdateStageResponse(TypedDict, total=False):
    AccessLogSettings: Optional[AccessLogSettings]
    ApiGatewayManaged: Optional[_boolean]
    AutoDeploy: Optional[_boolean]
    ClientCertificateId: Optional[Id]
    CreatedDate: Optional[_timestampIso8601]
    DefaultRouteSettings: Optional[RouteSettings]
    DeploymentId: Optional[Id]
    Description: Optional[StringWithLengthBetween0And1024]
    LastDeploymentStatusMessage: Optional[_string]
    LastUpdatedDate: Optional[_timestampIso8601]
    RouteSettings: Optional[RouteSettingsMap]
    StageName: Optional[StringWithLengthBetween1And128]
    StageVariables: Optional[StageVariablesMap]
    Tags: Optional[Tags]


class UpdateVpcLinkInput(TypedDict, total=False):
    Name: Optional[StringWithLengthBetween1And128]


class UpdateVpcLinkRequest(ServiceRequest):
    Name: Optional[StringWithLengthBetween1And128]
    VpcLinkId: _string


class UpdateVpcLinkResponse(TypedDict, total=False):
    CreatedDate: Optional[_timestampIso8601]
    Name: Optional[StringWithLengthBetween1And128]
    SecurityGroupIds: Optional[SecurityGroupIdList]
    SubnetIds: Optional[SubnetIdList]
    Tags: Optional[Tags]
    VpcLinkId: Optional[Id]
    VpcLinkStatus: Optional[VpcLinkStatus]
    VpcLinkStatusMessage: Optional[StringWithLengthBetween0And1024]
    VpcLinkVersion: Optional[VpcLinkVersion]


class VpcLinks(TypedDict, total=False):
    Items: Optional[_listOfVpcLink]
    NextToken: Optional[NextToken]


_long = int
_timestampUnix = datetime


class Apigatewayv2Api:

    service = "apigatewayv2"
    version = "2018-11-29"

    @handler("CreateApi")
    def create_api(
        self,
        context: RequestContext,
        protocol_type: ProtocolType,
        name: StringWithLengthBetween1And128,
        api_key_selection_expression: SelectionExpression = None,
        cors_configuration: Cors = None,
        credentials_arn: Arn = None,
        description: StringWithLengthBetween0And1024 = None,
        disable_schema_validation: _boolean = None,
        disable_execute_api_endpoint: _boolean = None,
        route_key: SelectionKey = None,
        route_selection_expression: SelectionExpression = None,
        tags: Tags = None,
        target: UriWithLengthBetween1And2048 = None,
        version: StringWithLengthBetween1And64 = None,
    ) -> CreateApiResponse:
        raise NotImplementedError

    @handler("CreateApiMapping")
    def create_api_mapping(
        self,
        context: RequestContext,
        domain_name: _string,
        stage: StringWithLengthBetween1And128,
        api_id: Id,
        api_mapping_key: SelectionKey = None,
    ) -> CreateApiMappingResponse:
        raise NotImplementedError

    @handler("CreateAuthorizer")
    def create_authorizer(
        self,
        context: RequestContext,
        api_id: _string,
        authorizer_type: AuthorizerType,
        identity_source: IdentitySourceList,
        name: StringWithLengthBetween1And128,
        authorizer_credentials_arn: Arn = None,
        authorizer_payload_format_version: StringWithLengthBetween1And64 = None,
        authorizer_result_ttl_in_seconds: IntegerWithLengthBetween0And3600 = None,
        authorizer_uri: UriWithLengthBetween1And2048 = None,
        enable_simple_responses: _boolean = None,
        identity_validation_expression: StringWithLengthBetween0And1024 = None,
        jwt_configuration: JWTConfiguration = None,
    ) -> CreateAuthorizerResponse:
        raise NotImplementedError

    @handler("CreateDeployment")
    def create_deployment(
        self,
        context: RequestContext,
        api_id: _string,
        description: StringWithLengthBetween0And1024 = None,
        stage_name: StringWithLengthBetween1And128 = None,
    ) -> CreateDeploymentResponse:
        raise NotImplementedError

    @handler("CreateDomainName")
    def create_domain_name(
        self,
        context: RequestContext,
        domain_name: StringWithLengthBetween1And512,
        domain_name_configurations: DomainNameConfigurations = None,
        mutual_tls_authentication: MutualTlsAuthenticationInput = None,
        tags: Tags = None,
    ) -> CreateDomainNameResponse:
        raise NotImplementedError

    @handler("CreateIntegration")
    def create_integration(
        self,
        context: RequestContext,
        api_id: _string,
        integration_type: IntegrationType,
        connection_id: StringWithLengthBetween1And1024 = None,
        connection_type: ConnectionType = None,
        content_handling_strategy: ContentHandlingStrategy = None,
        credentials_arn: Arn = None,
        description: StringWithLengthBetween0And1024 = None,
        integration_method: StringWithLengthBetween1And64 = None,
        integration_subtype: StringWithLengthBetween1And128 = None,
        integration_uri: UriWithLengthBetween1And2048 = None,
        passthrough_behavior: PassthroughBehavior = None,
        payload_format_version: StringWithLengthBetween1And64 = None,
        request_parameters: IntegrationParameters = None,
        request_templates: TemplateMap = None,
        response_parameters: ResponseParameters = None,
        template_selection_expression: SelectionExpression = None,
        timeout_in_millis: IntegerWithLengthBetween50And30000 = None,
        tls_config: TlsConfigInput = None,
    ) -> CreateIntegrationResult:
        raise NotImplementedError

    @handler("CreateIntegrationResponse")
    def create_integration_response(
        self,
        context: RequestContext,
        api_id: _string,
        integration_id: _string,
        integration_response_key: SelectionKey,
        content_handling_strategy: ContentHandlingStrategy = None,
        response_parameters: IntegrationParameters = None,
        response_templates: TemplateMap = None,
        template_selection_expression: SelectionExpression = None,
    ) -> CreateIntegrationResponseResponse:
        raise NotImplementedError

    @handler("CreateModel")
    def create_model(
        self,
        context: RequestContext,
        api_id: _string,
        schema: StringWithLengthBetween0And32K,
        name: StringWithLengthBetween1And128,
        content_type: StringWithLengthBetween1And256 = None,
        description: StringWithLengthBetween0And1024 = None,
    ) -> CreateModelResponse:
        raise NotImplementedError

    @handler("CreateRoute")
    def create_route(
        self,
        context: RequestContext,
        api_id: _string,
        route_key: SelectionKey,
        api_key_required: _boolean = None,
        authorization_scopes: AuthorizationScopes = None,
        authorization_type: AuthorizationType = None,
        authorizer_id: Id = None,
        model_selection_expression: SelectionExpression = None,
        operation_name: StringWithLengthBetween1And64 = None,
        request_models: RouteModels = None,
        request_parameters: RouteParameters = None,
        route_response_selection_expression: SelectionExpression = None,
        target: StringWithLengthBetween1And128 = None,
    ) -> CreateRouteResult:
        raise NotImplementedError

    @handler("CreateRouteResponse")
    def create_route_response(
        self,
        context: RequestContext,
        api_id: _string,
        route_id: _string,
        route_response_key: SelectionKey,
        model_selection_expression: SelectionExpression = None,
        response_models: RouteModels = None,
        response_parameters: RouteParameters = None,
    ) -> CreateRouteResponseResponse:
        raise NotImplementedError

    @handler("CreateStage")
    def create_stage(
        self,
        context: RequestContext,
        api_id: _string,
        stage_name: StringWithLengthBetween1And128,
        access_log_settings: AccessLogSettings = None,
        auto_deploy: _boolean = None,
        client_certificate_id: Id = None,
        default_route_settings: RouteSettings = None,
        deployment_id: Id = None,
        description: StringWithLengthBetween0And1024 = None,
        route_settings: RouteSettingsMap = None,
        stage_variables: StageVariablesMap = None,
        tags: Tags = None,
    ) -> CreateStageResponse:
        raise NotImplementedError

    @handler("CreateVpcLink")
    def create_vpc_link(
        self,
        context: RequestContext,
        subnet_ids: SubnetIdList,
        name: StringWithLengthBetween1And128,
        security_group_ids: SecurityGroupIdList = None,
        tags: Tags = None,
    ) -> CreateVpcLinkResponse:
        raise NotImplementedError

    @handler("DeleteAccessLogSettings")
    def delete_access_log_settings(
        self, context: RequestContext, stage_name: _string, api_id: _string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteApi")
    def delete_api(self, context: RequestContext, api_id: _string) -> None:
        raise NotImplementedError

    @handler("DeleteApiMapping")
    def delete_api_mapping(
        self, context: RequestContext, api_mapping_id: _string, domain_name: _string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAuthorizer")
    def delete_authorizer(
        self, context: RequestContext, authorizer_id: _string, api_id: _string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCorsConfiguration")
    def delete_cors_configuration(self, context: RequestContext, api_id: _string) -> None:
        raise NotImplementedError

    @handler("DeleteDeployment")
    def delete_deployment(
        self, context: RequestContext, api_id: _string, deployment_id: _string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDomainName")
    def delete_domain_name(self, context: RequestContext, domain_name: _string) -> None:
        raise NotImplementedError

    @handler("DeleteIntegration")
    def delete_integration(
        self, context: RequestContext, api_id: _string, integration_id: _string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteIntegrationResponse")
    def delete_integration_response(
        self,
        context: RequestContext,
        api_id: _string,
        integration_response_id: _string,
        integration_id: _string,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteModel")
    def delete_model(self, context: RequestContext, model_id: _string, api_id: _string) -> None:
        raise NotImplementedError

    @handler("DeleteRoute")
    def delete_route(self, context: RequestContext, api_id: _string, route_id: _string) -> None:
        raise NotImplementedError

    @handler("DeleteRouteRequestParameter")
    def delete_route_request_parameter(
        self,
        context: RequestContext,
        request_parameter_key: _string,
        api_id: _string,
        route_id: _string,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRouteResponse")
    def delete_route_response(
        self,
        context: RequestContext,
        route_response_id: _string,
        api_id: _string,
        route_id: _string,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRouteSettings")
    def delete_route_settings(
        self, context: RequestContext, stage_name: _string, route_key: _string, api_id: _string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStage")
    def delete_stage(self, context: RequestContext, stage_name: _string, api_id: _string) -> None:
        raise NotImplementedError

    @handler("DeleteVpcLink")
    def delete_vpc_link(
        self, context: RequestContext, vpc_link_id: _string
    ) -> DeleteVpcLinkResponse:
        raise NotImplementedError

    @handler("ExportApi")
    def export_api(
        self,
        context: RequestContext,
        specification: _string,
        output_type: _string,
        api_id: _string,
        export_version: _string = None,
        include_extensions: _boolean = None,
        stage_name: _string = None,
    ) -> ExportApiResponse:
        raise NotImplementedError

    @handler("ResetAuthorizersCache")
    def reset_authorizers_cache(
        self, context: RequestContext, stage_name: _string, api_id: _string
    ) -> None:
        raise NotImplementedError

    @handler("GetApi")
    def get_api(self, context: RequestContext, api_id: _string) -> GetApiResponse:
        raise NotImplementedError

    @handler("GetApiMapping")
    def get_api_mapping(
        self, context: RequestContext, api_mapping_id: _string, domain_name: _string
    ) -> GetApiMappingResponse:
        raise NotImplementedError

    @handler("GetApiMappings")
    def get_api_mappings(
        self,
        context: RequestContext,
        domain_name: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetApiMappingsResponse:
        raise NotImplementedError

    @handler("GetApis")
    def get_apis(
        self, context: RequestContext, max_results: _string = None, next_token: _string = None
    ) -> GetApisResponse:
        raise NotImplementedError

    @handler("GetAuthorizer")
    def get_authorizer(
        self, context: RequestContext, authorizer_id: _string, api_id: _string
    ) -> GetAuthorizerResponse:
        raise NotImplementedError

    @handler("GetAuthorizers")
    def get_authorizers(
        self,
        context: RequestContext,
        api_id: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetAuthorizersResponse:
        raise NotImplementedError

    @handler("GetDeployment")
    def get_deployment(
        self, context: RequestContext, api_id: _string, deployment_id: _string
    ) -> GetDeploymentResponse:
        raise NotImplementedError

    @handler("GetDeployments")
    def get_deployments(
        self,
        context: RequestContext,
        api_id: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetDeploymentsResponse:
        raise NotImplementedError

    @handler("GetDomainName")
    def get_domain_name(
        self, context: RequestContext, domain_name: _string
    ) -> GetDomainNameResponse:
        raise NotImplementedError

    @handler("GetDomainNames")
    def get_domain_names(
        self, context: RequestContext, max_results: _string = None, next_token: _string = None
    ) -> GetDomainNamesResponse:
        raise NotImplementedError

    @handler("GetIntegration")
    def get_integration(
        self, context: RequestContext, api_id: _string, integration_id: _string
    ) -> GetIntegrationResult:
        raise NotImplementedError

    @handler("GetIntegrationResponse")
    def get_integration_response(
        self,
        context: RequestContext,
        api_id: _string,
        integration_response_id: _string,
        integration_id: _string,
    ) -> GetIntegrationResponseResponse:
        raise NotImplementedError

    @handler("GetIntegrationResponses")
    def get_integration_responses(
        self,
        context: RequestContext,
        integration_id: _string,
        api_id: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetIntegrationResponsesResponse:
        raise NotImplementedError

    @handler("GetIntegrations")
    def get_integrations(
        self,
        context: RequestContext,
        api_id: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetIntegrationsResponse:
        raise NotImplementedError

    @handler("GetModel")
    def get_model(
        self, context: RequestContext, model_id: _string, api_id: _string
    ) -> GetModelResponse:
        raise NotImplementedError

    @handler("GetModelTemplate")
    def get_model_template(
        self, context: RequestContext, model_id: _string, api_id: _string
    ) -> GetModelTemplateResponse:
        raise NotImplementedError

    @handler("GetModels")
    def get_models(
        self,
        context: RequestContext,
        api_id: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetModelsResponse:
        raise NotImplementedError

    @handler("GetRoute")
    def get_route(
        self, context: RequestContext, api_id: _string, route_id: _string
    ) -> GetRouteResult:
        raise NotImplementedError

    @handler("GetRouteResponse")
    def get_route_response(
        self,
        context: RequestContext,
        route_response_id: _string,
        api_id: _string,
        route_id: _string,
    ) -> GetRouteResponseResponse:
        raise NotImplementedError

    @handler("GetRouteResponses")
    def get_route_responses(
        self,
        context: RequestContext,
        route_id: _string,
        api_id: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetRouteResponsesResponse:
        raise NotImplementedError

    @handler("GetRoutes")
    def get_routes(
        self,
        context: RequestContext,
        api_id: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetRoutesResponse:
        raise NotImplementedError

    @handler("GetStage")
    def get_stage(
        self, context: RequestContext, stage_name: _string, api_id: _string
    ) -> GetStageResponse:
        raise NotImplementedError

    @handler("GetStages")
    def get_stages(
        self,
        context: RequestContext,
        api_id: _string,
        max_results: _string = None,
        next_token: _string = None,
    ) -> GetStagesResponse:
        raise NotImplementedError

    @handler("GetTags")
    def get_tags(self, context: RequestContext, resource_arn: _string) -> GetTagsResponse:
        raise NotImplementedError

    @handler("GetVpcLink")
    def get_vpc_link(self, context: RequestContext, vpc_link_id: _string) -> GetVpcLinkResponse:
        raise NotImplementedError

    @handler("GetVpcLinks")
    def get_vpc_links(
        self, context: RequestContext, max_results: _string = None, next_token: _string = None
    ) -> GetVpcLinksResponse:
        raise NotImplementedError

    @handler("ImportApi")
    def import_api(
        self,
        context: RequestContext,
        body: _string,
        basepath: _string = None,
        fail_on_warnings: _boolean = None,
    ) -> ImportApiResponse:
        raise NotImplementedError

    @handler("ReimportApi")
    def reimport_api(
        self,
        context: RequestContext,
        api_id: _string,
        body: _string,
        basepath: _string = None,
        fail_on_warnings: _boolean = None,
    ) -> ReimportApiResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: _string, tags: Tags = None
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: _string, tag_keys: _listOf__string
    ) -> None:
        raise NotImplementedError

    @handler("UpdateApi")
    def update_api(
        self,
        context: RequestContext,
        api_id: _string,
        api_key_selection_expression: SelectionExpression = None,
        cors_configuration: Cors = None,
        credentials_arn: Arn = None,
        description: StringWithLengthBetween0And1024 = None,
        disable_schema_validation: _boolean = None,
        disable_execute_api_endpoint: _boolean = None,
        name: StringWithLengthBetween1And128 = None,
        route_key: SelectionKey = None,
        route_selection_expression: SelectionExpression = None,
        target: UriWithLengthBetween1And2048 = None,
        version: StringWithLengthBetween1And64 = None,
    ) -> UpdateApiResponse:
        raise NotImplementedError

    @handler("UpdateApiMapping")
    def update_api_mapping(
        self,
        context: RequestContext,
        api_mapping_id: _string,
        api_id: Id,
        domain_name: _string,
        api_mapping_key: SelectionKey = None,
        stage: StringWithLengthBetween1And128 = None,
    ) -> UpdateApiMappingResponse:
        raise NotImplementedError

    @handler("UpdateAuthorizer")
    def update_authorizer(
        self,
        context: RequestContext,
        authorizer_id: _string,
        api_id: _string,
        authorizer_credentials_arn: Arn = None,
        authorizer_payload_format_version: StringWithLengthBetween1And64 = None,
        authorizer_result_ttl_in_seconds: IntegerWithLengthBetween0And3600 = None,
        authorizer_type: AuthorizerType = None,
        authorizer_uri: UriWithLengthBetween1And2048 = None,
        enable_simple_responses: _boolean = None,
        identity_source: IdentitySourceList = None,
        identity_validation_expression: StringWithLengthBetween0And1024 = None,
        jwt_configuration: JWTConfiguration = None,
        name: StringWithLengthBetween1And128 = None,
    ) -> UpdateAuthorizerResponse:
        raise NotImplementedError

    @handler("UpdateDeployment")
    def update_deployment(
        self,
        context: RequestContext,
        api_id: _string,
        deployment_id: _string,
        description: StringWithLengthBetween0And1024 = None,
    ) -> UpdateDeploymentResponse:
        raise NotImplementedError

    @handler("UpdateDomainName")
    def update_domain_name(
        self,
        context: RequestContext,
        domain_name: _string,
        domain_name_configurations: DomainNameConfigurations = None,
        mutual_tls_authentication: MutualTlsAuthenticationInput = None,
    ) -> UpdateDomainNameResponse:
        raise NotImplementedError

    @handler("UpdateIntegration")
    def update_integration(
        self,
        context: RequestContext,
        api_id: _string,
        integration_id: _string,
        connection_id: StringWithLengthBetween1And1024 = None,
        connection_type: ConnectionType = None,
        content_handling_strategy: ContentHandlingStrategy = None,
        credentials_arn: Arn = None,
        description: StringWithLengthBetween0And1024 = None,
        integration_method: StringWithLengthBetween1And64 = None,
        integration_subtype: StringWithLengthBetween1And128 = None,
        integration_type: IntegrationType = None,
        integration_uri: UriWithLengthBetween1And2048 = None,
        passthrough_behavior: PassthroughBehavior = None,
        payload_format_version: StringWithLengthBetween1And64 = None,
        request_parameters: IntegrationParameters = None,
        request_templates: TemplateMap = None,
        response_parameters: ResponseParameters = None,
        template_selection_expression: SelectionExpression = None,
        timeout_in_millis: IntegerWithLengthBetween50And30000 = None,
        tls_config: TlsConfigInput = None,
    ) -> UpdateIntegrationResult:
        raise NotImplementedError

    @handler("UpdateIntegrationResponse")
    def update_integration_response(
        self,
        context: RequestContext,
        api_id: _string,
        integration_response_id: _string,
        integration_id: _string,
        content_handling_strategy: ContentHandlingStrategy = None,
        integration_response_key: SelectionKey = None,
        response_parameters: IntegrationParameters = None,
        response_templates: TemplateMap = None,
        template_selection_expression: SelectionExpression = None,
    ) -> UpdateIntegrationResponseResponse:
        raise NotImplementedError

    @handler("UpdateModel")
    def update_model(
        self,
        context: RequestContext,
        model_id: _string,
        api_id: _string,
        content_type: StringWithLengthBetween1And256 = None,
        description: StringWithLengthBetween0And1024 = None,
        name: StringWithLengthBetween1And128 = None,
        schema: StringWithLengthBetween0And32K = None,
    ) -> UpdateModelResponse:
        raise NotImplementedError

    @handler("UpdateRoute")
    def update_route(
        self,
        context: RequestContext,
        api_id: _string,
        route_id: _string,
        api_key_required: _boolean = None,
        authorization_scopes: AuthorizationScopes = None,
        authorization_type: AuthorizationType = None,
        authorizer_id: Id = None,
        model_selection_expression: SelectionExpression = None,
        operation_name: StringWithLengthBetween1And64 = None,
        request_models: RouteModels = None,
        request_parameters: RouteParameters = None,
        route_key: SelectionKey = None,
        route_response_selection_expression: SelectionExpression = None,
        target: StringWithLengthBetween1And128 = None,
    ) -> UpdateRouteResult:
        raise NotImplementedError

    @handler("UpdateRouteResponse")
    def update_route_response(
        self,
        context: RequestContext,
        route_response_id: _string,
        api_id: _string,
        route_id: _string,
        model_selection_expression: SelectionExpression = None,
        response_models: RouteModels = None,
        response_parameters: RouteParameters = None,
        route_response_key: SelectionKey = None,
    ) -> UpdateRouteResponseResponse:
        raise NotImplementedError

    @handler("UpdateStage")
    def update_stage(
        self,
        context: RequestContext,
        stage_name: _string,
        api_id: _string,
        access_log_settings: AccessLogSettings = None,
        auto_deploy: _boolean = None,
        client_certificate_id: Id = None,
        default_route_settings: RouteSettings = None,
        deployment_id: Id = None,
        description: StringWithLengthBetween0And1024 = None,
        route_settings: RouteSettingsMap = None,
        stage_variables: StageVariablesMap = None,
    ) -> UpdateStageResponse:
        raise NotImplementedError

    @handler("UpdateVpcLink")
    def update_vpc_link(
        self,
        context: RequestContext,
        vpc_link_id: _string,
        name: StringWithLengthBetween1And128 = None,
    ) -> UpdateVpcLinkResponse:
        raise NotImplementedError
