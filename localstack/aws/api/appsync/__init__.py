import sys
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
BooleanValue = bool
CertificateArn = str
Description = str
DomainName = str
ErrorMessage = str
MappingTemplate = str
MaxBatchSize = int
MaxResults = int
PaginationToken = str
ResourceArn = str
ResourceName = str
String = str
TTL = int
TagKey = str
TagValue = str


class ApiCacheStatus(str):
    AVAILABLE = "AVAILABLE"
    CREATING = "CREATING"
    DELETING = "DELETING"
    MODIFYING = "MODIFYING"
    FAILED = "FAILED"


class ApiCacheType(str):
    T2_SMALL = "T2_SMALL"
    T2_MEDIUM = "T2_MEDIUM"
    R4_LARGE = "R4_LARGE"
    R4_XLARGE = "R4_XLARGE"
    R4_2XLARGE = "R4_2XLARGE"
    R4_4XLARGE = "R4_4XLARGE"
    R4_8XLARGE = "R4_8XLARGE"
    SMALL = "SMALL"
    MEDIUM = "MEDIUM"
    LARGE = "LARGE"
    XLARGE = "XLARGE"
    LARGE_2X = "LARGE_2X"
    LARGE_4X = "LARGE_4X"
    LARGE_8X = "LARGE_8X"
    LARGE_12X = "LARGE_12X"


class ApiCachingBehavior(str):
    FULL_REQUEST_CACHING = "FULL_REQUEST_CACHING"
    PER_RESOLVER_CACHING = "PER_RESOLVER_CACHING"


class AssociationStatus(str):
    PROCESSING = "PROCESSING"
    FAILED = "FAILED"
    SUCCESS = "SUCCESS"


class AuthenticationType(str):
    API_KEY = "API_KEY"
    AWS_IAM = "AWS_IAM"
    AMAZON_COGNITO_USER_POOLS = "AMAZON_COGNITO_USER_POOLS"
    OPENID_CONNECT = "OPENID_CONNECT"
    AWS_LAMBDA = "AWS_LAMBDA"


class AuthorizationType(str):
    AWS_IAM = "AWS_IAM"


class ConflictDetectionType(str):
    VERSION = "VERSION"
    NONE = "NONE"


class ConflictHandlerType(str):
    OPTIMISTIC_CONCURRENCY = "OPTIMISTIC_CONCURRENCY"
    LAMBDA = "LAMBDA"
    AUTOMERGE = "AUTOMERGE"
    NONE = "NONE"


class DataSourceType(str):
    AWS_LAMBDA = "AWS_LAMBDA"
    AMAZON_DYNAMODB = "AMAZON_DYNAMODB"
    AMAZON_ELASTICSEARCH = "AMAZON_ELASTICSEARCH"
    NONE = "NONE"
    HTTP = "HTTP"
    RELATIONAL_DATABASE = "RELATIONAL_DATABASE"
    AMAZON_OPENSEARCH_SERVICE = "AMAZON_OPENSEARCH_SERVICE"


class DefaultAction(str):
    ALLOW = "ALLOW"
    DENY = "DENY"


class FieldLogLevel(str):
    NONE = "NONE"
    ERROR = "ERROR"
    ALL = "ALL"


class OutputType(str):
    SDL = "SDL"
    JSON = "JSON"


class RelationalDatabaseSourceType(str):
    RDS_HTTP_ENDPOINT = "RDS_HTTP_ENDPOINT"


class ResolverKind(str):
    UNIT = "UNIT"
    PIPELINE = "PIPELINE"


class SchemaStatus(str):
    PROCESSING = "PROCESSING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    FAILED = "FAILED"
    SUCCESS = "SUCCESS"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class TypeDefinitionFormat(str):
    SDL = "SDL"
    JSON = "JSON"


class AccessDeniedException(ServiceException):
    message: Optional[String]


class ApiKeyLimitExceededException(ServiceException):
    message: Optional[String]


class ApiKeyValidityOutOfBoundsException(ServiceException):
    message: Optional[String]


class ApiLimitExceededException(ServiceException):
    message: Optional[String]


class BadRequestException(ServiceException):
    message: Optional[ErrorMessage]


class ConcurrentModificationException(ServiceException):
    message: Optional[ErrorMessage]


class GraphQLSchemaException(ServiceException):
    message: Optional[ErrorMessage]


class InternalFailureException(ServiceException):
    message: Optional[String]


class LimitExceededException(ServiceException):
    message: Optional[String]


class NotFoundException(ServiceException):
    message: Optional[String]


class UnauthorizedException(ServiceException):
    message: Optional[String]


class LambdaAuthorizerConfig(TypedDict, total=False):
    authorizerResultTtlInSeconds: Optional[TTL]
    authorizerUri: String
    identityValidationExpression: Optional[String]


class CognitoUserPoolConfig(TypedDict, total=False):
    userPoolId: String
    awsRegion: String
    appIdClientRegex: Optional[String]


Long = int


class OpenIDConnectConfig(TypedDict, total=False):
    issuer: String
    clientId: Optional[String]
    iatTTL: Optional[Long]
    authTTL: Optional[Long]


class AdditionalAuthenticationProvider(TypedDict, total=False):
    authenticationType: Optional[AuthenticationType]
    openIDConnectConfig: Optional[OpenIDConnectConfig]
    userPoolConfig: Optional[CognitoUserPoolConfig]
    lambdaAuthorizerConfig: Optional[LambdaAuthorizerConfig]


AdditionalAuthenticationProviders = List[AdditionalAuthenticationProvider]


class ApiAssociation(TypedDict, total=False):
    domainName: Optional[DomainName]
    apiId: Optional[String]
    associationStatus: Optional[AssociationStatus]
    deploymentDetail: Optional[String]


ApiCache = TypedDict(
    "ApiCache",
    {
        "ttl": Optional[Long],
        "apiCachingBehavior": Optional[ApiCachingBehavior],
        "transitEncryptionEnabled": Optional[Boolean],
        "atRestEncryptionEnabled": Optional[Boolean],
        "type": Optional[ApiCacheType],
        "status": Optional[ApiCacheStatus],
    },
    total=False,
)


class ApiKey(TypedDict, total=False):
    id: Optional[String]
    description: Optional[String]
    expires: Optional[Long]
    deletes: Optional[Long]


ApiKeys = List[ApiKey]


class AssociateApiRequest(ServiceRequest):
    domainName: DomainName
    apiId: String


class AssociateApiResponse(TypedDict, total=False):
    apiAssociation: Optional[ApiAssociation]


class AwsIamConfig(TypedDict, total=False):
    signingRegion: Optional[String]
    signingServiceName: Optional[String]


class AuthorizationConfig(TypedDict, total=False):
    authorizationType: AuthorizationType
    awsIamConfig: Optional[AwsIamConfig]


Blob = bytes
CachingKeys = List[String]


class CachingConfig(TypedDict, total=False):
    ttl: Optional[Long]
    cachingKeys: Optional[CachingKeys]


CreateApiCacheRequest = TypedDict(
    "CreateApiCacheRequest",
    {
        "apiId": String,
        "ttl": Long,
        "transitEncryptionEnabled": Optional[Boolean],
        "atRestEncryptionEnabled": Optional[Boolean],
        "apiCachingBehavior": ApiCachingBehavior,
        "type": ApiCacheType,
    },
    total=False,
)


class CreateApiCacheResponse(TypedDict, total=False):
    apiCache: Optional[ApiCache]


class CreateApiKeyRequest(ServiceRequest):
    apiId: String
    description: Optional[String]
    expires: Optional[Long]


class CreateApiKeyResponse(TypedDict, total=False):
    apiKey: Optional[ApiKey]


class RdsHttpEndpointConfig(TypedDict, total=False):
    awsRegion: Optional[String]
    dbClusterIdentifier: Optional[String]
    databaseName: Optional[String]
    schema: Optional[String]
    awsSecretStoreArn: Optional[String]


class RelationalDatabaseDataSourceConfig(TypedDict, total=False):
    relationalDatabaseSourceType: Optional[RelationalDatabaseSourceType]
    rdsHttpEndpointConfig: Optional[RdsHttpEndpointConfig]


class HttpDataSourceConfig(TypedDict, total=False):
    endpoint: Optional[String]
    authorizationConfig: Optional[AuthorizationConfig]


class OpenSearchServiceDataSourceConfig(TypedDict, total=False):
    endpoint: String
    awsRegion: String


class ElasticsearchDataSourceConfig(TypedDict, total=False):
    endpoint: String
    awsRegion: String


class LambdaDataSourceConfig(TypedDict, total=False):
    lambdaFunctionArn: String


class DeltaSyncConfig(TypedDict, total=False):
    baseTableTTL: Optional[Long]
    deltaSyncTableName: Optional[String]
    deltaSyncTableTTL: Optional[Long]


class DynamodbDataSourceConfig(TypedDict, total=False):
    tableName: String
    awsRegion: String
    useCallerCredentials: Optional[Boolean]
    deltaSyncConfig: Optional[DeltaSyncConfig]
    versioned: Optional[Boolean]


CreateDataSourceRequest = TypedDict(
    "CreateDataSourceRequest",
    {
        "apiId": String,
        "name": ResourceName,
        "description": Optional[String],
        "type": DataSourceType,
        "serviceRoleArn": Optional[String],
        "dynamodbConfig": Optional[DynamodbDataSourceConfig],
        "lambdaConfig": Optional[LambdaDataSourceConfig],
        "elasticsearchConfig": Optional[ElasticsearchDataSourceConfig],
        "openSearchServiceConfig": Optional[OpenSearchServiceDataSourceConfig],
        "httpConfig": Optional[HttpDataSourceConfig],
        "relationalDatabaseConfig": Optional[RelationalDatabaseDataSourceConfig],
    },
    total=False,
)
DataSource = TypedDict(
    "DataSource",
    {
        "dataSourceArn": Optional[String],
        "name": Optional[ResourceName],
        "description": Optional[String],
        "type": Optional[DataSourceType],
        "serviceRoleArn": Optional[String],
        "dynamodbConfig": Optional[DynamodbDataSourceConfig],
        "lambdaConfig": Optional[LambdaDataSourceConfig],
        "elasticsearchConfig": Optional[ElasticsearchDataSourceConfig],
        "openSearchServiceConfig": Optional[OpenSearchServiceDataSourceConfig],
        "httpConfig": Optional[HttpDataSourceConfig],
        "relationalDatabaseConfig": Optional[RelationalDatabaseDataSourceConfig],
    },
    total=False,
)


class CreateDataSourceResponse(TypedDict, total=False):
    dataSource: Optional[DataSource]


class CreateDomainNameRequest(ServiceRequest):
    domainName: DomainName
    certificateArn: CertificateArn
    description: Optional[Description]


class DomainNameConfig(TypedDict, total=False):
    domainName: Optional[DomainName]
    description: Optional[Description]
    certificateArn: Optional[CertificateArn]
    appsyncDomainName: Optional[String]
    hostedZoneId: Optional[String]


class CreateDomainNameResponse(TypedDict, total=False):
    domainNameConfig: Optional[DomainNameConfig]


class LambdaConflictHandlerConfig(TypedDict, total=False):
    lambdaConflictHandlerArn: Optional[String]


class SyncConfig(TypedDict, total=False):
    conflictHandler: Optional[ConflictHandlerType]
    conflictDetection: Optional[ConflictDetectionType]
    lambdaConflictHandlerConfig: Optional[LambdaConflictHandlerConfig]


class CreateFunctionRequest(ServiceRequest):
    apiId: String
    name: ResourceName
    description: Optional[String]
    dataSourceName: ResourceName
    requestMappingTemplate: Optional[MappingTemplate]
    responseMappingTemplate: Optional[MappingTemplate]
    functionVersion: String
    syncConfig: Optional[SyncConfig]
    maxBatchSize: Optional[MaxBatchSize]


class FunctionConfiguration(TypedDict, total=False):
    functionId: Optional[String]
    functionArn: Optional[String]
    name: Optional[ResourceName]
    description: Optional[String]
    dataSourceName: Optional[ResourceName]
    requestMappingTemplate: Optional[MappingTemplate]
    responseMappingTemplate: Optional[MappingTemplate]
    functionVersion: Optional[String]
    syncConfig: Optional[SyncConfig]
    maxBatchSize: Optional[MaxBatchSize]


class CreateFunctionResponse(TypedDict, total=False):
    functionConfiguration: Optional[FunctionConfiguration]


TagMap = Dict[TagKey, TagValue]


class UserPoolConfig(TypedDict, total=False):
    userPoolId: String
    awsRegion: String
    defaultAction: DefaultAction
    appIdClientRegex: Optional[String]


class LogConfig(TypedDict, total=False):
    fieldLogLevel: FieldLogLevel
    cloudWatchLogsRoleArn: String
    excludeVerboseContent: Optional[Boolean]


class CreateGraphqlApiRequest(ServiceRequest):
    name: String
    logConfig: Optional[LogConfig]
    authenticationType: AuthenticationType
    userPoolConfig: Optional[UserPoolConfig]
    openIDConnectConfig: Optional[OpenIDConnectConfig]
    tags: Optional[TagMap]
    additionalAuthenticationProviders: Optional[AdditionalAuthenticationProviders]
    xrayEnabled: Optional[Boolean]
    lambdaAuthorizerConfig: Optional[LambdaAuthorizerConfig]


MapOfStringToString = Dict[String, String]


class GraphqlApi(TypedDict, total=False):
    name: Optional[ResourceName]
    apiId: Optional[String]
    authenticationType: Optional[AuthenticationType]
    logConfig: Optional[LogConfig]
    userPoolConfig: Optional[UserPoolConfig]
    openIDConnectConfig: Optional[OpenIDConnectConfig]
    arn: Optional[String]
    uris: Optional[MapOfStringToString]
    tags: Optional[TagMap]
    additionalAuthenticationProviders: Optional[AdditionalAuthenticationProviders]
    xrayEnabled: Optional[Boolean]
    wafWebAclArn: Optional[String]
    lambdaAuthorizerConfig: Optional[LambdaAuthorizerConfig]


class CreateGraphqlApiResponse(TypedDict, total=False):
    graphqlApi: Optional[GraphqlApi]


FunctionsIds = List[String]


class PipelineConfig(TypedDict, total=False):
    functions: Optional[FunctionsIds]


class CreateResolverRequest(ServiceRequest):
    apiId: String
    typeName: ResourceName
    fieldName: ResourceName
    dataSourceName: Optional[ResourceName]
    requestMappingTemplate: Optional[MappingTemplate]
    responseMappingTemplate: Optional[MappingTemplate]
    kind: Optional[ResolverKind]
    pipelineConfig: Optional[PipelineConfig]
    syncConfig: Optional[SyncConfig]
    cachingConfig: Optional[CachingConfig]
    maxBatchSize: Optional[MaxBatchSize]


class Resolver(TypedDict, total=False):
    typeName: Optional[ResourceName]
    fieldName: Optional[ResourceName]
    dataSourceName: Optional[ResourceName]
    resolverArn: Optional[String]
    requestMappingTemplate: Optional[MappingTemplate]
    responseMappingTemplate: Optional[MappingTemplate]
    kind: Optional[ResolverKind]
    pipelineConfig: Optional[PipelineConfig]
    syncConfig: Optional[SyncConfig]
    cachingConfig: Optional[CachingConfig]
    maxBatchSize: Optional[MaxBatchSize]


class CreateResolverResponse(TypedDict, total=False):
    resolver: Optional[Resolver]


class CreateTypeRequest(ServiceRequest):
    apiId: String
    definition: String
    format: TypeDefinitionFormat


class Type(TypedDict, total=False):
    name: Optional[ResourceName]
    description: Optional[String]
    arn: Optional[String]
    definition: Optional[String]
    format: Optional[TypeDefinitionFormat]


CreateTypeResponse = TypedDict(
    "CreateTypeResponse",
    {
        "type": Optional[Type],
    },
    total=False,
)
DataSources = List[DataSource]


class DeleteApiCacheRequest(ServiceRequest):
    apiId: String


class DeleteApiCacheResponse(TypedDict, total=False):
    pass


class DeleteApiKeyRequest(ServiceRequest):
    apiId: String
    id: String


class DeleteApiKeyResponse(TypedDict, total=False):
    pass


class DeleteDataSourceRequest(ServiceRequest):
    apiId: String
    name: ResourceName


class DeleteDataSourceResponse(TypedDict, total=False):
    pass


class DeleteDomainNameRequest(ServiceRequest):
    domainName: DomainName


class DeleteDomainNameResponse(TypedDict, total=False):
    pass


class DeleteFunctionRequest(ServiceRequest):
    apiId: String
    functionId: ResourceName


class DeleteFunctionResponse(TypedDict, total=False):
    pass


class DeleteGraphqlApiRequest(ServiceRequest):
    apiId: String


class DeleteGraphqlApiResponse(TypedDict, total=False):
    pass


class DeleteResolverRequest(ServiceRequest):
    apiId: String
    typeName: ResourceName
    fieldName: ResourceName


class DeleteResolverResponse(TypedDict, total=False):
    pass


class DeleteTypeRequest(ServiceRequest):
    apiId: String
    typeName: ResourceName


class DeleteTypeResponse(TypedDict, total=False):
    pass


class DisassociateApiRequest(ServiceRequest):
    domainName: DomainName


class DisassociateApiResponse(TypedDict, total=False):
    pass


DomainNameConfigs = List[DomainNameConfig]


class FlushApiCacheRequest(ServiceRequest):
    apiId: String


class FlushApiCacheResponse(TypedDict, total=False):
    pass


Functions = List[FunctionConfiguration]


class GetApiAssociationRequest(ServiceRequest):
    domainName: DomainName


class GetApiAssociationResponse(TypedDict, total=False):
    apiAssociation: Optional[ApiAssociation]


class GetApiCacheRequest(ServiceRequest):
    apiId: String


class GetApiCacheResponse(TypedDict, total=False):
    apiCache: Optional[ApiCache]


class GetDataSourceRequest(ServiceRequest):
    apiId: String
    name: ResourceName


class GetDataSourceResponse(TypedDict, total=False):
    dataSource: Optional[DataSource]


class GetDomainNameRequest(ServiceRequest):
    domainName: DomainName


class GetDomainNameResponse(TypedDict, total=False):
    domainNameConfig: Optional[DomainNameConfig]


class GetFunctionRequest(ServiceRequest):
    apiId: String
    functionId: ResourceName


class GetFunctionResponse(TypedDict, total=False):
    functionConfiguration: Optional[FunctionConfiguration]


class GetGraphqlApiRequest(ServiceRequest):
    apiId: String


class GetGraphqlApiResponse(TypedDict, total=False):
    graphqlApi: Optional[GraphqlApi]


class GetIntrospectionSchemaRequest(ServiceRequest):
    apiId: String
    format: OutputType
    includeDirectives: Optional[BooleanValue]


class GetIntrospectionSchemaResponse(TypedDict, total=False):
    schema: Optional[Blob]


class GetResolverRequest(ServiceRequest):
    apiId: String
    typeName: ResourceName
    fieldName: ResourceName


class GetResolverResponse(TypedDict, total=False):
    resolver: Optional[Resolver]


class GetSchemaCreationStatusRequest(ServiceRequest):
    apiId: String


class GetSchemaCreationStatusResponse(TypedDict, total=False):
    status: Optional[SchemaStatus]
    details: Optional[String]


class GetTypeRequest(ServiceRequest):
    apiId: String
    typeName: ResourceName
    format: TypeDefinitionFormat


GetTypeResponse = TypedDict(
    "GetTypeResponse",
    {
        "type": Optional[Type],
    },
    total=False,
)
GraphqlApis = List[GraphqlApi]


class ListApiKeysRequest(ServiceRequest):
    apiId: String
    nextToken: Optional[PaginationToken]
    maxResults: Optional[MaxResults]


class ListApiKeysResponse(TypedDict, total=False):
    apiKeys: Optional[ApiKeys]
    nextToken: Optional[PaginationToken]


class ListDataSourcesRequest(ServiceRequest):
    apiId: String
    nextToken: Optional[PaginationToken]
    maxResults: Optional[MaxResults]


class ListDataSourcesResponse(TypedDict, total=False):
    dataSources: Optional[DataSources]
    nextToken: Optional[PaginationToken]


class ListDomainNamesRequest(ServiceRequest):
    nextToken: Optional[PaginationToken]
    maxResults: Optional[MaxResults]


class ListDomainNamesResponse(TypedDict, total=False):
    domainNameConfigs: Optional[DomainNameConfigs]
    nextToken: Optional[PaginationToken]


class ListFunctionsRequest(ServiceRequest):
    apiId: String
    nextToken: Optional[PaginationToken]
    maxResults: Optional[MaxResults]


class ListFunctionsResponse(TypedDict, total=False):
    functions: Optional[Functions]
    nextToken: Optional[PaginationToken]


class ListGraphqlApisRequest(ServiceRequest):
    nextToken: Optional[PaginationToken]
    maxResults: Optional[MaxResults]


class ListGraphqlApisResponse(TypedDict, total=False):
    graphqlApis: Optional[GraphqlApis]
    nextToken: Optional[PaginationToken]


class ListResolversByFunctionRequest(ServiceRequest):
    apiId: String
    functionId: String
    nextToken: Optional[PaginationToken]
    maxResults: Optional[MaxResults]


Resolvers = List[Resolver]


class ListResolversByFunctionResponse(TypedDict, total=False):
    resolvers: Optional[Resolvers]
    nextToken: Optional[PaginationToken]


class ListResolversRequest(ServiceRequest):
    apiId: String
    typeName: String
    nextToken: Optional[PaginationToken]
    maxResults: Optional[MaxResults]


class ListResolversResponse(TypedDict, total=False):
    resolvers: Optional[Resolvers]
    nextToken: Optional[PaginationToken]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: ResourceArn


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagMap]


class ListTypesRequest(ServiceRequest):
    apiId: String
    format: TypeDefinitionFormat
    nextToken: Optional[PaginationToken]
    maxResults: Optional[MaxResults]


TypeList = List[Type]


class ListTypesResponse(TypedDict, total=False):
    types: Optional[TypeList]
    nextToken: Optional[PaginationToken]


class StartSchemaCreationRequest(ServiceRequest):
    apiId: String
    definition: Blob


class StartSchemaCreationResponse(TypedDict, total=False):
    status: Optional[SchemaStatus]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    tags: TagMap


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    tagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


UpdateApiCacheRequest = TypedDict(
    "UpdateApiCacheRequest",
    {
        "apiId": String,
        "ttl": Long,
        "apiCachingBehavior": ApiCachingBehavior,
        "type": ApiCacheType,
    },
    total=False,
)


class UpdateApiCacheResponse(TypedDict, total=False):
    apiCache: Optional[ApiCache]


class UpdateApiKeyRequest(ServiceRequest):
    apiId: String
    id: String
    description: Optional[String]
    expires: Optional[Long]


class UpdateApiKeyResponse(TypedDict, total=False):
    apiKey: Optional[ApiKey]


UpdateDataSourceRequest = TypedDict(
    "UpdateDataSourceRequest",
    {
        "apiId": String,
        "name": ResourceName,
        "description": Optional[String],
        "type": DataSourceType,
        "serviceRoleArn": Optional[String],
        "dynamodbConfig": Optional[DynamodbDataSourceConfig],
        "lambdaConfig": Optional[LambdaDataSourceConfig],
        "elasticsearchConfig": Optional[ElasticsearchDataSourceConfig],
        "openSearchServiceConfig": Optional[OpenSearchServiceDataSourceConfig],
        "httpConfig": Optional[HttpDataSourceConfig],
        "relationalDatabaseConfig": Optional[RelationalDatabaseDataSourceConfig],
    },
    total=False,
)


class UpdateDataSourceResponse(TypedDict, total=False):
    dataSource: Optional[DataSource]


class UpdateDomainNameRequest(ServiceRequest):
    domainName: DomainName
    description: Optional[Description]


class UpdateDomainNameResponse(TypedDict, total=False):
    domainNameConfig: Optional[DomainNameConfig]


class UpdateFunctionRequest(ServiceRequest):
    apiId: String
    name: ResourceName
    description: Optional[String]
    functionId: ResourceName
    dataSourceName: ResourceName
    requestMappingTemplate: Optional[MappingTemplate]
    responseMappingTemplate: Optional[MappingTemplate]
    functionVersion: String
    syncConfig: Optional[SyncConfig]
    maxBatchSize: Optional[MaxBatchSize]


class UpdateFunctionResponse(TypedDict, total=False):
    functionConfiguration: Optional[FunctionConfiguration]


class UpdateGraphqlApiRequest(ServiceRequest):
    apiId: String
    name: String
    logConfig: Optional[LogConfig]
    authenticationType: Optional[AuthenticationType]
    userPoolConfig: Optional[UserPoolConfig]
    openIDConnectConfig: Optional[OpenIDConnectConfig]
    additionalAuthenticationProviders: Optional[AdditionalAuthenticationProviders]
    xrayEnabled: Optional[Boolean]
    lambdaAuthorizerConfig: Optional[LambdaAuthorizerConfig]


class UpdateGraphqlApiResponse(TypedDict, total=False):
    graphqlApi: Optional[GraphqlApi]


class UpdateResolverRequest(ServiceRequest):
    apiId: String
    typeName: ResourceName
    fieldName: ResourceName
    dataSourceName: Optional[ResourceName]
    requestMappingTemplate: Optional[MappingTemplate]
    responseMappingTemplate: Optional[MappingTemplate]
    kind: Optional[ResolverKind]
    pipelineConfig: Optional[PipelineConfig]
    syncConfig: Optional[SyncConfig]
    cachingConfig: Optional[CachingConfig]
    maxBatchSize: Optional[MaxBatchSize]


class UpdateResolverResponse(TypedDict, total=False):
    resolver: Optional[Resolver]


class UpdateTypeRequest(ServiceRequest):
    apiId: String
    typeName: ResourceName
    definition: Optional[String]
    format: TypeDefinitionFormat


UpdateTypeResponse = TypedDict(
    "UpdateTypeResponse",
    {
        "type": Optional[Type],
    },
    total=False,
)


class AppsyncApi:

    service = "appsync"
    version = "2017-07-25"

    @handler("AssociateApi")
    def associate_api(
        self, context: RequestContext, domain_name: DomainName, api_id: String
    ) -> AssociateApiResponse:
        raise NotImplementedError

    @handler("CreateApiCache", expand=False)
    def create_api_cache(
        self, context: RequestContext, request: CreateApiCacheRequest
    ) -> CreateApiCacheResponse:
        raise NotImplementedError

    @handler("CreateApiKey")
    def create_api_key(
        self,
        context: RequestContext,
        api_id: String,
        description: String = None,
        expires: Long = None,
    ) -> CreateApiKeyResponse:
        raise NotImplementedError

    @handler("CreateDataSource", expand=False)
    def create_data_source(
        self, context: RequestContext, request: CreateDataSourceRequest
    ) -> CreateDataSourceResponse:
        raise NotImplementedError

    @handler("CreateDomainName")
    def create_domain_name(
        self,
        context: RequestContext,
        domain_name: DomainName,
        certificate_arn: CertificateArn,
        description: Description = None,
    ) -> CreateDomainNameResponse:
        raise NotImplementedError

    @handler("CreateFunction")
    def create_function(
        self,
        context: RequestContext,
        api_id: String,
        name: ResourceName,
        data_source_name: ResourceName,
        function_version: String,
        description: String = None,
        request_mapping_template: MappingTemplate = None,
        response_mapping_template: MappingTemplate = None,
        sync_config: SyncConfig = None,
        max_batch_size: MaxBatchSize = None,
    ) -> CreateFunctionResponse:
        raise NotImplementedError

    @handler("CreateGraphqlApi")
    def create_graphql_api(
        self,
        context: RequestContext,
        name: String,
        authentication_type: AuthenticationType,
        log_config: LogConfig = None,
        user_pool_config: UserPoolConfig = None,
        open_id_connect_config: OpenIDConnectConfig = None,
        tags: TagMap = None,
        additional_authentication_providers: AdditionalAuthenticationProviders = None,
        xray_enabled: Boolean = None,
        lambda_authorizer_config: LambdaAuthorizerConfig = None,
    ) -> CreateGraphqlApiResponse:
        raise NotImplementedError

    @handler("CreateResolver")
    def create_resolver(
        self,
        context: RequestContext,
        api_id: String,
        type_name: ResourceName,
        field_name: ResourceName,
        data_source_name: ResourceName = None,
        request_mapping_template: MappingTemplate = None,
        response_mapping_template: MappingTemplate = None,
        kind: ResolverKind = None,
        pipeline_config: PipelineConfig = None,
        sync_config: SyncConfig = None,
        caching_config: CachingConfig = None,
        max_batch_size: MaxBatchSize = None,
    ) -> CreateResolverResponse:
        raise NotImplementedError

    @handler("CreateType")
    def create_type(
        self,
        context: RequestContext,
        api_id: String,
        definition: String,
        format: TypeDefinitionFormat,
    ) -> CreateTypeResponse:
        raise NotImplementedError

    @handler("DeleteApiCache")
    def delete_api_cache(self, context: RequestContext, api_id: String) -> DeleteApiCacheResponse:
        raise NotImplementedError

    @handler("DeleteApiKey")
    def delete_api_key(
        self, context: RequestContext, api_id: String, id: String
    ) -> DeleteApiKeyResponse:
        raise NotImplementedError

    @handler("DeleteDataSource")
    def delete_data_source(
        self, context: RequestContext, api_id: String, name: ResourceName
    ) -> DeleteDataSourceResponse:
        raise NotImplementedError

    @handler("DeleteDomainName")
    def delete_domain_name(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteDomainNameResponse:
        raise NotImplementedError

    @handler("DeleteFunction")
    def delete_function(
        self, context: RequestContext, api_id: String, function_id: ResourceName
    ) -> DeleteFunctionResponse:
        raise NotImplementedError

    @handler("DeleteGraphqlApi")
    def delete_graphql_api(
        self, context: RequestContext, api_id: String
    ) -> DeleteGraphqlApiResponse:
        raise NotImplementedError

    @handler("DeleteResolver")
    def delete_resolver(
        self,
        context: RequestContext,
        api_id: String,
        type_name: ResourceName,
        field_name: ResourceName,
    ) -> DeleteResolverResponse:
        raise NotImplementedError

    @handler("DeleteType")
    def delete_type(
        self, context: RequestContext, api_id: String, type_name: ResourceName
    ) -> DeleteTypeResponse:
        raise NotImplementedError

    @handler("DisassociateApi")
    def disassociate_api(
        self, context: RequestContext, domain_name: DomainName
    ) -> DisassociateApiResponse:
        raise NotImplementedError

    @handler("FlushApiCache")
    def flush_api_cache(self, context: RequestContext, api_id: String) -> FlushApiCacheResponse:
        raise NotImplementedError

    @handler("GetApiAssociation")
    def get_api_association(
        self, context: RequestContext, domain_name: DomainName
    ) -> GetApiAssociationResponse:
        raise NotImplementedError

    @handler("GetApiCache")
    def get_api_cache(self, context: RequestContext, api_id: String) -> GetApiCacheResponse:
        raise NotImplementedError

    @handler("GetDataSource")
    def get_data_source(
        self, context: RequestContext, api_id: String, name: ResourceName
    ) -> GetDataSourceResponse:
        raise NotImplementedError

    @handler("GetDomainName")
    def get_domain_name(
        self, context: RequestContext, domain_name: DomainName
    ) -> GetDomainNameResponse:
        raise NotImplementedError

    @handler("GetFunction")
    def get_function(
        self, context: RequestContext, api_id: String, function_id: ResourceName
    ) -> GetFunctionResponse:
        raise NotImplementedError

    @handler("GetGraphqlApi")
    def get_graphql_api(self, context: RequestContext, api_id: String) -> GetGraphqlApiResponse:
        raise NotImplementedError

    @handler("GetIntrospectionSchema")
    def get_introspection_schema(
        self,
        context: RequestContext,
        api_id: String,
        format: OutputType,
        include_directives: BooleanValue = None,
    ) -> GetIntrospectionSchemaResponse:
        raise NotImplementedError

    @handler("GetResolver")
    def get_resolver(
        self,
        context: RequestContext,
        api_id: String,
        type_name: ResourceName,
        field_name: ResourceName,
    ) -> GetResolverResponse:
        raise NotImplementedError

    @handler("GetSchemaCreationStatus")
    def get_schema_creation_status(
        self, context: RequestContext, api_id: String
    ) -> GetSchemaCreationStatusResponse:
        raise NotImplementedError

    @handler("GetType")
    def get_type(
        self,
        context: RequestContext,
        api_id: String,
        type_name: ResourceName,
        format: TypeDefinitionFormat,
    ) -> GetTypeResponse:
        raise NotImplementedError

    @handler("ListApiKeys")
    def list_api_keys(
        self,
        context: RequestContext,
        api_id: String,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListApiKeysResponse:
        raise NotImplementedError

    @handler("ListDataSources")
    def list_data_sources(
        self,
        context: RequestContext,
        api_id: String,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListDataSourcesResponse:
        raise NotImplementedError

    @handler("ListDomainNames")
    def list_domain_names(
        self,
        context: RequestContext,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListDomainNamesResponse:
        raise NotImplementedError

    @handler("ListFunctions")
    def list_functions(
        self,
        context: RequestContext,
        api_id: String,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListFunctionsResponse:
        raise NotImplementedError

    @handler("ListGraphqlApis")
    def list_graphql_apis(
        self,
        context: RequestContext,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListGraphqlApisResponse:
        raise NotImplementedError

    @handler("ListResolvers")
    def list_resolvers(
        self,
        context: RequestContext,
        api_id: String,
        type_name: String,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListResolversResponse:
        raise NotImplementedError

    @handler("ListResolversByFunction")
    def list_resolvers_by_function(
        self,
        context: RequestContext,
        api_id: String,
        function_id: String,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListResolversByFunctionResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTypes")
    def list_types(
        self,
        context: RequestContext,
        api_id: String,
        format: TypeDefinitionFormat,
        next_token: PaginationToken = None,
        max_results: MaxResults = None,
    ) -> ListTypesResponse:
        raise NotImplementedError

    @handler("StartSchemaCreation")
    def start_schema_creation(
        self, context: RequestContext, api_id: String, definition: Blob
    ) -> StartSchemaCreationResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tags: TagMap
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateApiCache", expand=False)
    def update_api_cache(
        self, context: RequestContext, request: UpdateApiCacheRequest
    ) -> UpdateApiCacheResponse:
        raise NotImplementedError

    @handler("UpdateApiKey")
    def update_api_key(
        self,
        context: RequestContext,
        api_id: String,
        id: String,
        description: String = None,
        expires: Long = None,
    ) -> UpdateApiKeyResponse:
        raise NotImplementedError

    @handler("UpdateDataSource", expand=False)
    def update_data_source(
        self, context: RequestContext, request: UpdateDataSourceRequest
    ) -> UpdateDataSourceResponse:
        raise NotImplementedError

    @handler("UpdateDomainName")
    def update_domain_name(
        self, context: RequestContext, domain_name: DomainName, description: Description = None
    ) -> UpdateDomainNameResponse:
        raise NotImplementedError

    @handler("UpdateFunction")
    def update_function(
        self,
        context: RequestContext,
        api_id: String,
        name: ResourceName,
        function_id: ResourceName,
        data_source_name: ResourceName,
        function_version: String,
        description: String = None,
        request_mapping_template: MappingTemplate = None,
        response_mapping_template: MappingTemplate = None,
        sync_config: SyncConfig = None,
        max_batch_size: MaxBatchSize = None,
    ) -> UpdateFunctionResponse:
        raise NotImplementedError

    @handler("UpdateGraphqlApi")
    def update_graphql_api(
        self,
        context: RequestContext,
        api_id: String,
        name: String,
        log_config: LogConfig = None,
        authentication_type: AuthenticationType = None,
        user_pool_config: UserPoolConfig = None,
        open_id_connect_config: OpenIDConnectConfig = None,
        additional_authentication_providers: AdditionalAuthenticationProviders = None,
        xray_enabled: Boolean = None,
        lambda_authorizer_config: LambdaAuthorizerConfig = None,
    ) -> UpdateGraphqlApiResponse:
        raise NotImplementedError

    @handler("UpdateResolver")
    def update_resolver(
        self,
        context: RequestContext,
        api_id: String,
        type_name: ResourceName,
        field_name: ResourceName,
        data_source_name: ResourceName = None,
        request_mapping_template: MappingTemplate = None,
        response_mapping_template: MappingTemplate = None,
        kind: ResolverKind = None,
        pipeline_config: PipelineConfig = None,
        sync_config: SyncConfig = None,
        caching_config: CachingConfig = None,
        max_batch_size: MaxBatchSize = None,
    ) -> UpdateResolverResponse:
        raise NotImplementedError

    @handler("UpdateType")
    def update_type(
        self,
        context: RequestContext,
        api_id: String,
        type_name: ResourceName,
        format: TypeDefinitionFormat,
        definition: String = None,
    ) -> UpdateTypeResponse:
        raise NotImplementedError
