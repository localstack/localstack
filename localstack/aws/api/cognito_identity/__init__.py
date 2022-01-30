import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ARNString = str
AccessKeyString = str
AccountId = str
ClaimName = str
ClaimValue = str
ClassicFlow = bool
CognitoIdentityProviderClientId = str
CognitoIdentityProviderName = str
CognitoIdentityProviderTokenCheck = bool
DeveloperProviderName = str
DeveloperUserIdentifier = str
HideDisabled = bool
IdentityId = str
IdentityPoolId = str
IdentityPoolName = str
IdentityPoolUnauthenticated = bool
IdentityProviderId = str
IdentityProviderName = str
IdentityProviderToken = str
OIDCToken = str
PaginationKey = str
PrincipalTagID = str
PrincipalTagValue = str
QueryLimit = int
RoleType = str
SecretKeyString = str
SessionTokenString = str
String = str
TagKeysType = str
TagValueType = str
UseDefaults = bool


class AmbiguousRoleResolutionType(str):
    AuthenticatedRole = "AuthenticatedRole"
    Deny = "Deny"


class ErrorCode(str):
    AccessDenied = "AccessDenied"
    InternalServerError = "InternalServerError"


class MappingRuleMatchType(str):
    Equals = "Equals"
    Contains = "Contains"
    StartsWith = "StartsWith"
    NotEqual = "NotEqual"


class RoleMappingType(str):
    Token = "Token"
    Rules = "Rules"


class ConcurrentModificationException(ServiceException):
    message: Optional[String]


class DeveloperUserAlreadyRegisteredException(ServiceException):
    message: Optional[String]


class ExternalServiceException(ServiceException):
    message: Optional[String]


class InternalErrorException(ServiceException):
    message: Optional[String]


class InvalidIdentityPoolConfigurationException(ServiceException):
    message: Optional[String]


class InvalidParameterException(ServiceException):
    message: Optional[String]


class LimitExceededException(ServiceException):
    message: Optional[String]


class NotAuthorizedException(ServiceException):
    message: Optional[String]


class ResourceConflictException(ServiceException):
    message: Optional[String]


class ResourceNotFoundException(ServiceException):
    message: Optional[String]


class TooManyRequestsException(ServiceException):
    message: Optional[String]


class CognitoIdentityProvider(TypedDict, total=False):
    ProviderName: Optional[CognitoIdentityProviderName]
    ClientId: Optional[CognitoIdentityProviderClientId]
    ServerSideTokenCheck: Optional[CognitoIdentityProviderTokenCheck]


CognitoIdentityProviderList = List[CognitoIdentityProvider]
IdentityPoolTagsType = Dict[TagKeysType, TagValueType]
SAMLProviderList = List[ARNString]
OIDCProviderList = List[ARNString]
IdentityProviders = Dict[IdentityProviderName, IdentityProviderId]


class CreateIdentityPoolInput(ServiceRequest):
    IdentityPoolName: IdentityPoolName
    AllowUnauthenticatedIdentities: IdentityPoolUnauthenticated
    AllowClassicFlow: Optional[ClassicFlow]
    SupportedLoginProviders: Optional[IdentityProviders]
    DeveloperProviderName: Optional[DeveloperProviderName]
    OpenIdConnectProviderARNs: Optional[OIDCProviderList]
    CognitoIdentityProviders: Optional[CognitoIdentityProviderList]
    SamlProviderARNs: Optional[SAMLProviderList]
    IdentityPoolTags: Optional[IdentityPoolTagsType]


DateType = datetime


class Credentials(TypedDict, total=False):
    AccessKeyId: Optional[AccessKeyString]
    SecretKey: Optional[SecretKeyString]
    SessionToken: Optional[SessionTokenString]
    Expiration: Optional[DateType]


IdentityIdList = List[IdentityId]


class DeleteIdentitiesInput(ServiceRequest):
    IdentityIdsToDelete: IdentityIdList


class UnprocessedIdentityId(TypedDict, total=False):
    IdentityId: Optional[IdentityId]
    ErrorCode: Optional[ErrorCode]


UnprocessedIdentityIdList = List[UnprocessedIdentityId]


class DeleteIdentitiesResponse(TypedDict, total=False):
    UnprocessedIdentityIds: Optional[UnprocessedIdentityIdList]


class DeleteIdentityPoolInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId


class DescribeIdentityInput(ServiceRequest):
    IdentityId: IdentityId


class DescribeIdentityPoolInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId


DeveloperUserIdentifierList = List[DeveloperUserIdentifier]
LoginsMap = Dict[IdentityProviderName, IdentityProviderToken]


class GetCredentialsForIdentityInput(ServiceRequest):
    IdentityId: IdentityId
    Logins: Optional[LoginsMap]
    CustomRoleArn: Optional[ARNString]


class GetCredentialsForIdentityResponse(TypedDict, total=False):
    IdentityId: Optional[IdentityId]
    Credentials: Optional[Credentials]


class GetIdInput(ServiceRequest):
    AccountId: Optional[AccountId]
    IdentityPoolId: IdentityPoolId
    Logins: Optional[LoginsMap]


class GetIdResponse(TypedDict, total=False):
    IdentityId: Optional[IdentityId]


class GetIdentityPoolRolesInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId


class MappingRule(TypedDict, total=False):
    Claim: ClaimName
    MatchType: MappingRuleMatchType
    Value: ClaimValue
    RoleARN: ARNString


MappingRulesList = List[MappingRule]


class RulesConfigurationType(TypedDict, total=False):
    Rules: MappingRulesList


class RoleMapping(TypedDict, total=False):
    Type: RoleMappingType
    AmbiguousRoleResolution: Optional[AmbiguousRoleResolutionType]
    RulesConfiguration: Optional[RulesConfigurationType]


RoleMappingMap = Dict[IdentityProviderName, RoleMapping]
RolesMap = Dict[RoleType, ARNString]


class GetIdentityPoolRolesResponse(TypedDict, total=False):
    IdentityPoolId: Optional[IdentityPoolId]
    Roles: Optional[RolesMap]
    RoleMappings: Optional[RoleMappingMap]


TokenDuration = int
PrincipalTags = Dict[PrincipalTagID, PrincipalTagValue]


class GetOpenIdTokenForDeveloperIdentityInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId
    IdentityId: Optional[IdentityId]
    Logins: LoginsMap
    PrincipalTags: Optional[PrincipalTags]
    TokenDuration: Optional[TokenDuration]


class GetOpenIdTokenForDeveloperIdentityResponse(TypedDict, total=False):
    IdentityId: Optional[IdentityId]
    Token: Optional[OIDCToken]


class GetOpenIdTokenInput(ServiceRequest):
    IdentityId: IdentityId
    Logins: Optional[LoginsMap]


class GetOpenIdTokenResponse(TypedDict, total=False):
    IdentityId: Optional[IdentityId]
    Token: Optional[OIDCToken]


class GetPrincipalTagAttributeMapInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId
    IdentityProviderName: IdentityProviderName


class GetPrincipalTagAttributeMapResponse(TypedDict, total=False):
    IdentityPoolId: Optional[IdentityPoolId]
    IdentityProviderName: Optional[IdentityProviderName]
    UseDefaults: Optional[UseDefaults]
    PrincipalTags: Optional[PrincipalTags]


LoginsList = List[IdentityProviderName]


class IdentityDescription(TypedDict, total=False):
    IdentityId: Optional[IdentityId]
    Logins: Optional[LoginsList]
    CreationDate: Optional[DateType]
    LastModifiedDate: Optional[DateType]


IdentitiesList = List[IdentityDescription]


class IdentityPool(ServiceRequest):
    IdentityPoolId: IdentityPoolId
    IdentityPoolName: IdentityPoolName
    AllowUnauthenticatedIdentities: IdentityPoolUnauthenticated
    AllowClassicFlow: Optional[ClassicFlow]
    SupportedLoginProviders: Optional[IdentityProviders]
    DeveloperProviderName: Optional[DeveloperProviderName]
    OpenIdConnectProviderARNs: Optional[OIDCProviderList]
    CognitoIdentityProviders: Optional[CognitoIdentityProviderList]
    SamlProviderARNs: Optional[SAMLProviderList]
    IdentityPoolTags: Optional[IdentityPoolTagsType]


class IdentityPoolShortDescription(TypedDict, total=False):
    IdentityPoolId: Optional[IdentityPoolId]
    IdentityPoolName: Optional[IdentityPoolName]


IdentityPoolTagsListType = List[TagKeysType]
IdentityPoolsList = List[IdentityPoolShortDescription]


class ListIdentitiesInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId
    MaxResults: QueryLimit
    NextToken: Optional[PaginationKey]
    HideDisabled: Optional[HideDisabled]


class ListIdentitiesResponse(TypedDict, total=False):
    IdentityPoolId: Optional[IdentityPoolId]
    Identities: Optional[IdentitiesList]
    NextToken: Optional[PaginationKey]


class ListIdentityPoolsInput(ServiceRequest):
    MaxResults: QueryLimit
    NextToken: Optional[PaginationKey]


class ListIdentityPoolsResponse(TypedDict, total=False):
    IdentityPools: Optional[IdentityPoolsList]
    NextToken: Optional[PaginationKey]


class ListTagsForResourceInput(ServiceRequest):
    ResourceArn: ARNString


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[IdentityPoolTagsType]


class LookupDeveloperIdentityInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId
    IdentityId: Optional[IdentityId]
    DeveloperUserIdentifier: Optional[DeveloperUserIdentifier]
    MaxResults: Optional[QueryLimit]
    NextToken: Optional[PaginationKey]


class LookupDeveloperIdentityResponse(TypedDict, total=False):
    IdentityId: Optional[IdentityId]
    DeveloperUserIdentifierList: Optional[DeveloperUserIdentifierList]
    NextToken: Optional[PaginationKey]


class MergeDeveloperIdentitiesInput(ServiceRequest):
    SourceUserIdentifier: DeveloperUserIdentifier
    DestinationUserIdentifier: DeveloperUserIdentifier
    DeveloperProviderName: DeveloperProviderName
    IdentityPoolId: IdentityPoolId


class MergeDeveloperIdentitiesResponse(TypedDict, total=False):
    IdentityId: Optional[IdentityId]


class SetIdentityPoolRolesInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId
    Roles: RolesMap
    RoleMappings: Optional[RoleMappingMap]


class SetPrincipalTagAttributeMapInput(ServiceRequest):
    IdentityPoolId: IdentityPoolId
    IdentityProviderName: IdentityProviderName
    UseDefaults: Optional[UseDefaults]
    PrincipalTags: Optional[PrincipalTags]


class SetPrincipalTagAttributeMapResponse(TypedDict, total=False):
    IdentityPoolId: Optional[IdentityPoolId]
    IdentityProviderName: Optional[IdentityProviderName]
    UseDefaults: Optional[UseDefaults]
    PrincipalTags: Optional[PrincipalTags]


class TagResourceInput(ServiceRequest):
    ResourceArn: ARNString
    Tags: IdentityPoolTagsType


class TagResourceResponse(TypedDict, total=False):
    pass


class UnlinkDeveloperIdentityInput(ServiceRequest):
    IdentityId: IdentityId
    IdentityPoolId: IdentityPoolId
    DeveloperProviderName: DeveloperProviderName
    DeveloperUserIdentifier: DeveloperUserIdentifier


class UnlinkIdentityInput(ServiceRequest):
    IdentityId: IdentityId
    Logins: LoginsMap
    LoginsToRemove: LoginsList


class UntagResourceInput(ServiceRequest):
    ResourceArn: ARNString
    TagKeys: IdentityPoolTagsListType


class UntagResourceResponse(TypedDict, total=False):
    pass


class CognitoIdentityApi:

    service = "cognito-identity"
    version = "2014-06-30"

    @handler("CreateIdentityPool")
    def create_identity_pool(
        self,
        context: RequestContext,
        identity_pool_name: IdentityPoolName,
        allow_unauthenticated_identities: IdentityPoolUnauthenticated,
        allow_classic_flow: ClassicFlow = None,
        supported_login_providers: IdentityProviders = None,
        developer_provider_name: DeveloperProviderName = None,
        open_id_connect_provider_arns: OIDCProviderList = None,
        cognito_identity_providers: CognitoIdentityProviderList = None,
        saml_provider_arns: SAMLProviderList = None,
        identity_pool_tags: IdentityPoolTagsType = None,
    ) -> IdentityPool:
        raise NotImplementedError

    @handler("DeleteIdentities")
    def delete_identities(
        self, context: RequestContext, identity_ids_to_delete: IdentityIdList
    ) -> DeleteIdentitiesResponse:
        raise NotImplementedError

    @handler("DeleteIdentityPool")
    def delete_identity_pool(
        self, context: RequestContext, identity_pool_id: IdentityPoolId
    ) -> None:
        raise NotImplementedError

    @handler("DescribeIdentity")
    def describe_identity(
        self, context: RequestContext, identity_id: IdentityId
    ) -> IdentityDescription:
        raise NotImplementedError

    @handler("DescribeIdentityPool")
    def describe_identity_pool(
        self, context: RequestContext, identity_pool_id: IdentityPoolId
    ) -> IdentityPool:
        raise NotImplementedError

    @handler("GetCredentialsForIdentity")
    def get_credentials_for_identity(
        self,
        context: RequestContext,
        identity_id: IdentityId,
        logins: LoginsMap = None,
        custom_role_arn: ARNString = None,
    ) -> GetCredentialsForIdentityResponse:
        raise NotImplementedError

    @handler("GetId")
    def get_id(
        self,
        context: RequestContext,
        identity_pool_id: IdentityPoolId,
        account_id: AccountId = None,
        logins: LoginsMap = None,
    ) -> GetIdResponse:
        raise NotImplementedError

    @handler("GetIdentityPoolRoles")
    def get_identity_pool_roles(
        self, context: RequestContext, identity_pool_id: IdentityPoolId
    ) -> GetIdentityPoolRolesResponse:
        raise NotImplementedError

    @handler("GetOpenIdToken")
    def get_open_id_token(
        self, context: RequestContext, identity_id: IdentityId, logins: LoginsMap = None
    ) -> GetOpenIdTokenResponse:
        raise NotImplementedError

    @handler("GetOpenIdTokenForDeveloperIdentity")
    def get_open_id_token_for_developer_identity(
        self,
        context: RequestContext,
        identity_pool_id: IdentityPoolId,
        logins: LoginsMap,
        identity_id: IdentityId = None,
        principal_tags: PrincipalTags = None,
        token_duration: TokenDuration = None,
    ) -> GetOpenIdTokenForDeveloperIdentityResponse:
        raise NotImplementedError

    @handler("GetPrincipalTagAttributeMap")
    def get_principal_tag_attribute_map(
        self,
        context: RequestContext,
        identity_pool_id: IdentityPoolId,
        identity_provider_name: IdentityProviderName,
    ) -> GetPrincipalTagAttributeMapResponse:
        raise NotImplementedError

    @handler("ListIdentities")
    def list_identities(
        self,
        context: RequestContext,
        identity_pool_id: IdentityPoolId,
        max_results: QueryLimit,
        next_token: PaginationKey = None,
        hide_disabled: HideDisabled = None,
    ) -> ListIdentitiesResponse:
        raise NotImplementedError

    @handler("ListIdentityPools")
    def list_identity_pools(
        self, context: RequestContext, max_results: QueryLimit, next_token: PaginationKey = None
    ) -> ListIdentityPoolsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ARNString
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("LookupDeveloperIdentity")
    def lookup_developer_identity(
        self,
        context: RequestContext,
        identity_pool_id: IdentityPoolId,
        identity_id: IdentityId = None,
        developer_user_identifier: DeveloperUserIdentifier = None,
        max_results: QueryLimit = None,
        next_token: PaginationKey = None,
    ) -> LookupDeveloperIdentityResponse:
        raise NotImplementedError

    @handler("MergeDeveloperIdentities")
    def merge_developer_identities(
        self,
        context: RequestContext,
        source_user_identifier: DeveloperUserIdentifier,
        destination_user_identifier: DeveloperUserIdentifier,
        developer_provider_name: DeveloperProviderName,
        identity_pool_id: IdentityPoolId,
    ) -> MergeDeveloperIdentitiesResponse:
        raise NotImplementedError

    @handler("SetIdentityPoolRoles")
    def set_identity_pool_roles(
        self,
        context: RequestContext,
        identity_pool_id: IdentityPoolId,
        roles: RolesMap,
        role_mappings: RoleMappingMap = None,
    ) -> None:
        raise NotImplementedError

    @handler("SetPrincipalTagAttributeMap")
    def set_principal_tag_attribute_map(
        self,
        context: RequestContext,
        identity_pool_id: IdentityPoolId,
        identity_provider_name: IdentityProviderName,
        use_defaults: UseDefaults = None,
        principal_tags: PrincipalTags = None,
    ) -> SetPrincipalTagAttributeMapResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ARNString, tags: IdentityPoolTagsType
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UnlinkDeveloperIdentity")
    def unlink_developer_identity(
        self,
        context: RequestContext,
        identity_id: IdentityId,
        identity_pool_id: IdentityPoolId,
        developer_provider_name: DeveloperProviderName,
        developer_user_identifier: DeveloperUserIdentifier,
    ) -> None:
        raise NotImplementedError

    @handler("UnlinkIdentity")
    def unlink_identity(
        self,
        context: RequestContext,
        identity_id: IdentityId,
        logins: LoginsMap,
        logins_to_remove: LoginsList,
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ARNString, tag_keys: IdentityPoolTagsListType
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateIdentityPool")
    def update_identity_pool(
        self,
        context: RequestContext,
        identity_pool_id: IdentityPoolId,
        identity_pool_name: IdentityPoolName,
        allow_unauthenticated_identities: IdentityPoolUnauthenticated,
        allow_classic_flow: ClassicFlow = None,
        supported_login_providers: IdentityProviders = None,
        developer_provider_name: DeveloperProviderName = None,
        open_id_connect_provider_arns: OIDCProviderList = None,
        cognito_identity_providers: CognitoIdentityProviderList = None,
        saml_provider_arns: SAMLProviderList = None,
        identity_pool_tags: IdentityPoolTagsType = None,
    ) -> IdentityPool:
        raise NotImplementedError
