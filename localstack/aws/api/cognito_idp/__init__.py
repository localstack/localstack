import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AWSAccountIdType = str
AccessTokenValidityType = int
AccountTakeoverActionNotifyType = bool
AdminCreateUserUnusedAccountValidityDaysType = int
ArnType = str
AttributeMappingKeyType = str
AttributeNameType = str
AttributeValueType = str
BooleanType = bool
CSSType = str
CSSVersionType = str
ClientIdType = str
ClientNameType = str
ClientPermissionType = str
ClientSecretType = str
CompletionMessageType = str
ConfirmationCodeType = str
CustomAttributeNameType = str
DescriptionType = str
DeviceKeyType = str
DeviceNameType = str
DomainType = str
DomainVersionType = str
EmailAddressType = str
EmailNotificationBodyType = str
EmailNotificationSubjectType = str
EmailVerificationMessageByLinkType = str
EmailVerificationMessageType = str
EmailVerificationSubjectByLinkType = str
EmailVerificationSubjectType = str
EventIdType = str
ForceAliasCreation = bool
GenerateSecret = bool
GroupNameType = str
HexStringType = str
IdTokenValidityType = int
IdpIdentifierType = str
ImageUrlType = str
IntegerType = int
ListProvidersLimitType = int
ListResourceServersLimitType = int
MessageType = str
PaginationKey = str
PaginationKeyType = str
PasswordPolicyMinLengthType = int
PasswordType = str
PoolQueryLimitType = int
PreSignedUrlType = str
PrecedenceType = int
PriorityType = int
ProviderNameType = str
ProviderNameTypeV1 = str
QueryLimit = int
QueryLimitType = int
RedirectUrlType = str
RefreshTokenValidityType = int
ResourceServerIdentifierType = str
ResourceServerNameType = str
ResourceServerScopeDescriptionType = str
ResourceServerScopeNameType = str
S3BucketType = str
SESConfigurationSet = str
ScopeType = str
SearchPaginationTokenType = str
SecretCodeType = str
SecretHashType = str
SessionType = str
SmsVerificationMessageType = str
SoftwareTokenMFAUserCodeType = str
StringType = str
TagKeysType = str
TagValueType = str
TemporaryPasswordValidityDaysType = int
TokenModelType = str
UserFilterType = str
UserImportJobIdType = str
UserImportJobNameType = str
UserPoolIdType = str
UserPoolNameType = str
UsernameType = str
WrappedBooleanType = bool


class AccountTakeoverEventActionType(str):
    BLOCK = "BLOCK"
    MFA_IF_CONFIGURED = "MFA_IF_CONFIGURED"
    MFA_REQUIRED = "MFA_REQUIRED"
    NO_ACTION = "NO_ACTION"


class AdvancedSecurityModeType(str):
    OFF = "OFF"
    AUDIT = "AUDIT"
    ENFORCED = "ENFORCED"


class AliasAttributeType(str):
    phone_number = "phone_number"
    email = "email"
    preferred_username = "preferred_username"


class AttributeDataType(str):
    String = "String"
    Number = "Number"
    DateTime = "DateTime"
    Boolean = "Boolean"


class AuthFlowType(str):
    USER_SRP_AUTH = "USER_SRP_AUTH"
    REFRESH_TOKEN_AUTH = "REFRESH_TOKEN_AUTH"
    REFRESH_TOKEN = "REFRESH_TOKEN"
    CUSTOM_AUTH = "CUSTOM_AUTH"
    ADMIN_NO_SRP_AUTH = "ADMIN_NO_SRP_AUTH"
    USER_PASSWORD_AUTH = "USER_PASSWORD_AUTH"
    ADMIN_USER_PASSWORD_AUTH = "ADMIN_USER_PASSWORD_AUTH"


class ChallengeName(str):
    Password = "Password"
    Mfa = "Mfa"


class ChallengeNameType(str):
    SMS_MFA = "SMS_MFA"
    SOFTWARE_TOKEN_MFA = "SOFTWARE_TOKEN_MFA"
    SELECT_MFA_TYPE = "SELECT_MFA_TYPE"
    MFA_SETUP = "MFA_SETUP"
    PASSWORD_VERIFIER = "PASSWORD_VERIFIER"
    CUSTOM_CHALLENGE = "CUSTOM_CHALLENGE"
    DEVICE_SRP_AUTH = "DEVICE_SRP_AUTH"
    DEVICE_PASSWORD_VERIFIER = "DEVICE_PASSWORD_VERIFIER"
    ADMIN_NO_SRP_AUTH = "ADMIN_NO_SRP_AUTH"
    NEW_PASSWORD_REQUIRED = "NEW_PASSWORD_REQUIRED"


class ChallengeResponse(str):
    Success = "Success"
    Failure = "Failure"


class CompromisedCredentialsEventActionType(str):
    BLOCK = "BLOCK"
    NO_ACTION = "NO_ACTION"


class CustomEmailSenderLambdaVersionType(str):
    V1_0 = "V1_0"


class CustomSMSSenderLambdaVersionType(str):
    V1_0 = "V1_0"


class DefaultEmailOptionType(str):
    CONFIRM_WITH_LINK = "CONFIRM_WITH_LINK"
    CONFIRM_WITH_CODE = "CONFIRM_WITH_CODE"


class DeliveryMediumType(str):
    SMS = "SMS"
    EMAIL = "EMAIL"


class DeviceRememberedStatusType(str):
    remembered = "remembered"
    not_remembered = "not_remembered"


class DomainStatusType(str):
    CREATING = "CREATING"
    DELETING = "DELETING"
    UPDATING = "UPDATING"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"


class EmailSendingAccountType(str):
    COGNITO_DEFAULT = "COGNITO_DEFAULT"
    DEVELOPER = "DEVELOPER"


class EventFilterType(str):
    SIGN_IN = "SIGN_IN"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    SIGN_UP = "SIGN_UP"


class EventResponseType(str):
    Success = "Success"
    Failure = "Failure"


class EventType(str):
    SignIn = "SignIn"
    SignUp = "SignUp"
    ForgotPassword = "ForgotPassword"


class ExplicitAuthFlowsType(str):
    ADMIN_NO_SRP_AUTH = "ADMIN_NO_SRP_AUTH"
    CUSTOM_AUTH_FLOW_ONLY = "CUSTOM_AUTH_FLOW_ONLY"
    USER_PASSWORD_AUTH = "USER_PASSWORD_AUTH"
    ALLOW_ADMIN_USER_PASSWORD_AUTH = "ALLOW_ADMIN_USER_PASSWORD_AUTH"
    ALLOW_CUSTOM_AUTH = "ALLOW_CUSTOM_AUTH"
    ALLOW_USER_PASSWORD_AUTH = "ALLOW_USER_PASSWORD_AUTH"
    ALLOW_USER_SRP_AUTH = "ALLOW_USER_SRP_AUTH"
    ALLOW_REFRESH_TOKEN_AUTH = "ALLOW_REFRESH_TOKEN_AUTH"


class FeedbackValueType(str):
    Valid = "Valid"
    Invalid = "Invalid"


class IdentityProviderTypeType(str):
    SAML = "SAML"
    Facebook = "Facebook"
    Google = "Google"
    LoginWithAmazon = "LoginWithAmazon"
    SignInWithApple = "SignInWithApple"
    OIDC = "OIDC"


class MessageActionType(str):
    RESEND = "RESEND"
    SUPPRESS = "SUPPRESS"


class OAuthFlowType(str):
    code = "code"
    implicit = "implicit"
    client_credentials = "client_credentials"


class PreventUserExistenceErrorTypes(str):
    LEGACY = "LEGACY"
    ENABLED = "ENABLED"


class RecoveryOptionNameType(str):
    verified_email = "verified_email"
    verified_phone_number = "verified_phone_number"
    admin_only = "admin_only"


class RiskDecisionType(str):
    NoRisk = "NoRisk"
    AccountTakeover = "AccountTakeover"
    Block = "Block"


class RiskLevelType(str):
    Low = "Low"
    Medium = "Medium"
    High = "High"


class StatusType(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class TimeUnitsType(str):
    seconds = "seconds"
    minutes = "minutes"
    hours = "hours"
    days = "days"


class UserImportJobStatusType(str):
    Created = "Created"
    Pending = "Pending"
    InProgress = "InProgress"
    Stopping = "Stopping"
    Expired = "Expired"
    Stopped = "Stopped"
    Failed = "Failed"
    Succeeded = "Succeeded"


class UserPoolMfaType(str):
    OFF = "OFF"
    ON = "ON"
    OPTIONAL = "OPTIONAL"


class UserStatusType(str):
    UNCONFIRMED = "UNCONFIRMED"
    CONFIRMED = "CONFIRMED"
    ARCHIVED = "ARCHIVED"
    COMPROMISED = "COMPROMISED"
    UNKNOWN = "UNKNOWN"
    RESET_REQUIRED = "RESET_REQUIRED"
    FORCE_CHANGE_PASSWORD = "FORCE_CHANGE_PASSWORD"


class UsernameAttributeType(str):
    phone_number = "phone_number"
    email = "email"


class VerifiedAttributeType(str):
    phone_number = "phone_number"
    email = "email"


class VerifySoftwareTokenResponseType(str):
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"


class AliasExistsException(ServiceException):
    message: Optional[MessageType]


class CodeDeliveryFailureException(ServiceException):
    message: Optional[MessageType]


class CodeMismatchException(ServiceException):
    message: Optional[MessageType]


class ConcurrentModificationException(ServiceException):
    message: Optional[MessageType]


class DuplicateProviderException(ServiceException):
    message: Optional[MessageType]


class EnableSoftwareTokenMFAException(ServiceException):
    message: Optional[MessageType]


class ExpiredCodeException(ServiceException):
    message: Optional[MessageType]


class GroupExistsException(ServiceException):
    message: Optional[MessageType]


class InternalErrorException(ServiceException):
    message: Optional[MessageType]


class InvalidEmailRoleAccessPolicyException(ServiceException):
    message: Optional[MessageType]


class InvalidLambdaResponseException(ServiceException):
    message: Optional[MessageType]


class InvalidOAuthFlowException(ServiceException):
    message: Optional[MessageType]


class InvalidParameterException(ServiceException):
    message: Optional[MessageType]


class InvalidPasswordException(ServiceException):
    message: Optional[MessageType]


class InvalidSmsRoleAccessPolicyException(ServiceException):
    message: Optional[MessageType]


class InvalidSmsRoleTrustRelationshipException(ServiceException):
    message: Optional[MessageType]


class InvalidUserPoolConfigurationException(ServiceException):
    message: Optional[MessageType]


class LimitExceededException(ServiceException):
    message: Optional[MessageType]


class MFAMethodNotFoundException(ServiceException):
    message: Optional[MessageType]


class NotAuthorizedException(ServiceException):
    message: Optional[MessageType]


class PasswordResetRequiredException(ServiceException):
    message: Optional[MessageType]


class PreconditionNotMetException(ServiceException):
    message: Optional[MessageType]


class ResourceNotFoundException(ServiceException):
    message: Optional[MessageType]


class ScopeDoesNotExistException(ServiceException):
    message: Optional[MessageType]


class SoftwareTokenMFANotFoundException(ServiceException):
    message: Optional[MessageType]


class TooManyFailedAttemptsException(ServiceException):
    message: Optional[MessageType]


class TooManyRequestsException(ServiceException):
    message: Optional[MessageType]


class UnauthorizedException(ServiceException):
    message: Optional[MessageType]


class UnexpectedLambdaException(ServiceException):
    message: Optional[MessageType]


class UnsupportedIdentityProviderException(ServiceException):
    message: Optional[MessageType]


class UnsupportedOperationException(ServiceException):
    message: Optional[MessageType]


class UnsupportedTokenTypeException(ServiceException):
    message: Optional[MessageType]


class UnsupportedUserStateException(ServiceException):
    message: Optional[MessageType]


class UserImportInProgressException(ServiceException):
    message: Optional[MessageType]


class UserLambdaValidationException(ServiceException):
    message: Optional[MessageType]


class UserNotConfirmedException(ServiceException):
    message: Optional[MessageType]


class UserNotFoundException(ServiceException):
    message: Optional[MessageType]


class UserPoolAddOnNotEnabledException(ServiceException):
    message: Optional[MessageType]


class UserPoolTaggingException(ServiceException):
    message: Optional[MessageType]


class UsernameExistsException(ServiceException):
    message: Optional[MessageType]


class RecoveryOptionType(TypedDict, total=False):
    Priority: PriorityType
    Name: RecoveryOptionNameType


RecoveryMechanismsType = List[RecoveryOptionType]


class AccountRecoverySettingType(TypedDict, total=False):
    RecoveryMechanisms: Optional[RecoveryMechanismsType]


class AccountTakeoverActionType(TypedDict, total=False):
    Notify: AccountTakeoverActionNotifyType
    EventAction: AccountTakeoverEventActionType


class AccountTakeoverActionsType(TypedDict, total=False):
    LowAction: Optional[AccountTakeoverActionType]
    MediumAction: Optional[AccountTakeoverActionType]
    HighAction: Optional[AccountTakeoverActionType]


class NotifyEmailType(TypedDict, total=False):
    Subject: EmailNotificationSubjectType
    HtmlBody: Optional[EmailNotificationBodyType]
    TextBody: Optional[EmailNotificationBodyType]


class NotifyConfigurationType(TypedDict, total=False):
    From: Optional[StringType]
    ReplyTo: Optional[StringType]
    SourceArn: ArnType
    BlockEmail: Optional[NotifyEmailType]
    NoActionEmail: Optional[NotifyEmailType]
    MfaEmail: Optional[NotifyEmailType]


class AccountTakeoverRiskConfigurationType(TypedDict, total=False):
    NotifyConfiguration: Optional[NotifyConfigurationType]
    Actions: AccountTakeoverActionsType


class StringAttributeConstraintsType(TypedDict, total=False):
    MinLength: Optional[StringType]
    MaxLength: Optional[StringType]


class NumberAttributeConstraintsType(TypedDict, total=False):
    MinValue: Optional[StringType]
    MaxValue: Optional[StringType]


class SchemaAttributeType(TypedDict, total=False):
    Name: Optional[CustomAttributeNameType]
    AttributeDataType: Optional[AttributeDataType]
    DeveloperOnlyAttribute: Optional[BooleanType]
    Mutable: Optional[BooleanType]
    Required: Optional[BooleanType]
    NumberAttributeConstraints: Optional[NumberAttributeConstraintsType]
    StringAttributeConstraints: Optional[StringAttributeConstraintsType]


CustomAttributesListType = List[SchemaAttributeType]


class AddCustomAttributesRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    CustomAttributes: CustomAttributesListType


class AddCustomAttributesResponse(TypedDict, total=False):
    pass


class AdminAddUserToGroupRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    GroupName: GroupNameType


ClientMetadataType = Dict[StringType, StringType]


class AdminConfirmSignUpRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    ClientMetadata: Optional[ClientMetadataType]


class AdminConfirmSignUpResponse(TypedDict, total=False):
    pass


class MessageTemplateType(TypedDict, total=False):
    SMSMessage: Optional[SmsVerificationMessageType]
    EmailMessage: Optional[EmailVerificationMessageType]
    EmailSubject: Optional[EmailVerificationSubjectType]


class AdminCreateUserConfigType(TypedDict, total=False):
    AllowAdminCreateUserOnly: Optional[BooleanType]
    UnusedAccountValidityDays: Optional[AdminCreateUserUnusedAccountValidityDaysType]
    InviteMessageTemplate: Optional[MessageTemplateType]


DeliveryMediumListType = List[DeliveryMediumType]


class AttributeType(TypedDict, total=False):
    Name: AttributeNameType
    Value: Optional[AttributeValueType]


AttributeListType = List[AttributeType]


class AdminCreateUserRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    UserAttributes: Optional[AttributeListType]
    ValidationData: Optional[AttributeListType]
    TemporaryPassword: Optional[PasswordType]
    ForceAliasCreation: Optional[ForceAliasCreation]
    MessageAction: Optional[MessageActionType]
    DesiredDeliveryMediums: Optional[DeliveryMediumListType]
    ClientMetadata: Optional[ClientMetadataType]


class MFAOptionType(TypedDict, total=False):
    DeliveryMedium: Optional[DeliveryMediumType]
    AttributeName: Optional[AttributeNameType]


MFAOptionListType = List[MFAOptionType]
DateType = datetime


class UserType(TypedDict, total=False):
    Username: Optional[UsernameType]
    Attributes: Optional[AttributeListType]
    UserCreateDate: Optional[DateType]
    UserLastModifiedDate: Optional[DateType]
    Enabled: Optional[BooleanType]
    UserStatus: Optional[UserStatusType]
    MFAOptions: Optional[MFAOptionListType]


class AdminCreateUserResponse(TypedDict, total=False):
    User: Optional[UserType]


AttributeNameListType = List[AttributeNameType]


class AdminDeleteUserAttributesRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    UserAttributeNames: AttributeNameListType


class AdminDeleteUserAttributesResponse(TypedDict, total=False):
    pass


class AdminDeleteUserRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType


class ProviderUserIdentifierType(TypedDict, total=False):
    ProviderName: Optional[ProviderNameType]
    ProviderAttributeName: Optional[StringType]
    ProviderAttributeValue: Optional[StringType]


class AdminDisableProviderForUserRequest(ServiceRequest):
    UserPoolId: StringType
    User: ProviderUserIdentifierType


class AdminDisableProviderForUserResponse(TypedDict, total=False):
    pass


class AdminDisableUserRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType


class AdminDisableUserResponse(TypedDict, total=False):
    pass


class AdminEnableUserRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType


class AdminEnableUserResponse(TypedDict, total=False):
    pass


class AdminForgetDeviceRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    DeviceKey: DeviceKeyType


class AdminGetDeviceRequest(ServiceRequest):
    DeviceKey: DeviceKeyType
    UserPoolId: UserPoolIdType
    Username: UsernameType


class DeviceType(TypedDict, total=False):
    DeviceKey: Optional[DeviceKeyType]
    DeviceAttributes: Optional[AttributeListType]
    DeviceCreateDate: Optional[DateType]
    DeviceLastModifiedDate: Optional[DateType]
    DeviceLastAuthenticatedDate: Optional[DateType]


class AdminGetDeviceResponse(TypedDict, total=False):
    Device: DeviceType


class AdminGetUserRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType


UserMFASettingListType = List[StringType]


class AdminGetUserResponse(TypedDict, total=False):
    Username: UsernameType
    UserAttributes: Optional[AttributeListType]
    UserCreateDate: Optional[DateType]
    UserLastModifiedDate: Optional[DateType]
    Enabled: Optional[BooleanType]
    UserStatus: Optional[UserStatusType]
    MFAOptions: Optional[MFAOptionListType]
    PreferredMfaSetting: Optional[StringType]
    UserMFASettingList: Optional[UserMFASettingListType]


class HttpHeader(TypedDict, total=False):
    headerName: Optional[StringType]
    headerValue: Optional[StringType]


HttpHeaderList = List[HttpHeader]


class ContextDataType(TypedDict, total=False):
    IpAddress: StringType
    ServerName: StringType
    ServerPath: StringType
    HttpHeaders: HttpHeaderList
    EncodedData: Optional[StringType]


class AnalyticsMetadataType(TypedDict, total=False):
    AnalyticsEndpointId: Optional[StringType]


AuthParametersType = Dict[StringType, StringType]


class AdminInitiateAuthRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: ClientIdType
    AuthFlow: AuthFlowType
    AuthParameters: Optional[AuthParametersType]
    ClientMetadata: Optional[ClientMetadataType]
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    ContextData: Optional[ContextDataType]


class NewDeviceMetadataType(TypedDict, total=False):
    DeviceKey: Optional[DeviceKeyType]
    DeviceGroupKey: Optional[StringType]


class AuthenticationResultType(TypedDict, total=False):
    AccessToken: Optional[TokenModelType]
    ExpiresIn: Optional[IntegerType]
    TokenType: Optional[StringType]
    RefreshToken: Optional[TokenModelType]
    IdToken: Optional[TokenModelType]
    NewDeviceMetadata: Optional[NewDeviceMetadataType]


ChallengeParametersType = Dict[StringType, StringType]


class AdminInitiateAuthResponse(TypedDict, total=False):
    ChallengeName: Optional[ChallengeNameType]
    Session: Optional[SessionType]
    ChallengeParameters: Optional[ChallengeParametersType]
    AuthenticationResult: Optional[AuthenticationResultType]


class AdminLinkProviderForUserRequest(ServiceRequest):
    UserPoolId: StringType
    DestinationUser: ProviderUserIdentifierType
    SourceUser: ProviderUserIdentifierType


class AdminLinkProviderForUserResponse(TypedDict, total=False):
    pass


class AdminListDevicesRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    Limit: Optional[QueryLimitType]
    PaginationToken: Optional[SearchPaginationTokenType]


DeviceListType = List[DeviceType]


class AdminListDevicesResponse(TypedDict, total=False):
    Devices: Optional[DeviceListType]
    PaginationToken: Optional[SearchPaginationTokenType]


class AdminListGroupsForUserRequest(ServiceRequest):
    Username: UsernameType
    UserPoolId: UserPoolIdType
    Limit: Optional[QueryLimitType]
    NextToken: Optional[PaginationKey]


class GroupType(TypedDict, total=False):
    GroupName: Optional[GroupNameType]
    UserPoolId: Optional[UserPoolIdType]
    Description: Optional[DescriptionType]
    RoleArn: Optional[ArnType]
    Precedence: Optional[PrecedenceType]
    LastModifiedDate: Optional[DateType]
    CreationDate: Optional[DateType]


GroupListType = List[GroupType]


class AdminListGroupsForUserResponse(TypedDict, total=False):
    Groups: Optional[GroupListType]
    NextToken: Optional[PaginationKey]


class AdminListUserAuthEventsRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    MaxResults: Optional[QueryLimitType]
    NextToken: Optional[PaginationKey]


class EventFeedbackType(TypedDict, total=False):
    FeedbackValue: FeedbackValueType
    Provider: StringType
    FeedbackDate: Optional[DateType]


class EventContextDataType(TypedDict, total=False):
    IpAddress: Optional[StringType]
    DeviceName: Optional[StringType]
    Timezone: Optional[StringType]
    City: Optional[StringType]
    Country: Optional[StringType]


class ChallengeResponseType(TypedDict, total=False):
    ChallengeName: Optional[ChallengeName]
    ChallengeResponse: Optional[ChallengeResponse]


ChallengeResponseListType = List[ChallengeResponseType]


class EventRiskType(TypedDict, total=False):
    RiskDecision: Optional[RiskDecisionType]
    RiskLevel: Optional[RiskLevelType]
    CompromisedCredentialsDetected: Optional[WrappedBooleanType]


class AuthEventType(TypedDict, total=False):
    EventId: Optional[StringType]
    EventType: Optional[EventType]
    CreationDate: Optional[DateType]
    EventResponse: Optional[EventResponseType]
    EventRisk: Optional[EventRiskType]
    ChallengeResponses: Optional[ChallengeResponseListType]
    EventContextData: Optional[EventContextDataType]
    EventFeedback: Optional[EventFeedbackType]


AuthEventsType = List[AuthEventType]


class AdminListUserAuthEventsResponse(TypedDict, total=False):
    AuthEvents: Optional[AuthEventsType]
    NextToken: Optional[PaginationKey]


class AdminRemoveUserFromGroupRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    GroupName: GroupNameType


class AdminResetUserPasswordRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    ClientMetadata: Optional[ClientMetadataType]


class AdminResetUserPasswordResponse(TypedDict, total=False):
    pass


ChallengeResponsesType = Dict[StringType, StringType]


class AdminRespondToAuthChallengeRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: ClientIdType
    ChallengeName: ChallengeNameType
    ChallengeResponses: Optional[ChallengeResponsesType]
    Session: Optional[SessionType]
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    ContextData: Optional[ContextDataType]
    ClientMetadata: Optional[ClientMetadataType]


class AdminRespondToAuthChallengeResponse(TypedDict, total=False):
    ChallengeName: Optional[ChallengeNameType]
    Session: Optional[SessionType]
    ChallengeParameters: Optional[ChallengeParametersType]
    AuthenticationResult: Optional[AuthenticationResultType]


class SoftwareTokenMfaSettingsType(TypedDict, total=False):
    Enabled: Optional[BooleanType]
    PreferredMfa: Optional[BooleanType]


class SMSMfaSettingsType(TypedDict, total=False):
    Enabled: Optional[BooleanType]
    PreferredMfa: Optional[BooleanType]


class AdminSetUserMFAPreferenceRequest(ServiceRequest):
    SMSMfaSettings: Optional[SMSMfaSettingsType]
    SoftwareTokenMfaSettings: Optional[SoftwareTokenMfaSettingsType]
    Username: UsernameType
    UserPoolId: UserPoolIdType


class AdminSetUserMFAPreferenceResponse(TypedDict, total=False):
    pass


class AdminSetUserPasswordRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    Password: PasswordType
    Permanent: Optional[BooleanType]


class AdminSetUserPasswordResponse(TypedDict, total=False):
    pass


class AdminSetUserSettingsRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    MFAOptions: MFAOptionListType


class AdminSetUserSettingsResponse(TypedDict, total=False):
    pass


class AdminUpdateAuthEventFeedbackRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    EventId: EventIdType
    FeedbackValue: FeedbackValueType


class AdminUpdateAuthEventFeedbackResponse(TypedDict, total=False):
    pass


class AdminUpdateDeviceStatusRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    DeviceKey: DeviceKeyType
    DeviceRememberedStatus: Optional[DeviceRememberedStatusType]


class AdminUpdateDeviceStatusResponse(TypedDict, total=False):
    pass


class AdminUpdateUserAttributesRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    UserAttributes: AttributeListType
    ClientMetadata: Optional[ClientMetadataType]


class AdminUpdateUserAttributesResponse(TypedDict, total=False):
    pass


class AdminUserGlobalSignOutRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType


class AdminUserGlobalSignOutResponse(TypedDict, total=False):
    pass


AliasAttributesListType = List[AliasAttributeType]


class AnalyticsConfigurationType(TypedDict, total=False):
    ApplicationId: Optional[HexStringType]
    ApplicationArn: Optional[ArnType]
    RoleArn: Optional[ArnType]
    ExternalId: Optional[StringType]
    UserDataShared: Optional[BooleanType]


class AssociateSoftwareTokenRequest(ServiceRequest):
    AccessToken: Optional[TokenModelType]
    Session: Optional[SessionType]


class AssociateSoftwareTokenResponse(TypedDict, total=False):
    SecretCode: Optional[SecretCodeType]
    Session: Optional[SessionType]


AttributeMappingType = Dict[AttributeMappingKeyType, StringType]
BlockedIPRangeListType = List[StringType]
CallbackURLsListType = List[RedirectUrlType]


class ChangePasswordRequest(ServiceRequest):
    PreviousPassword: PasswordType
    ProposedPassword: PasswordType
    AccessToken: TokenModelType


class ChangePasswordResponse(TypedDict, total=False):
    pass


ClientPermissionListType = List[ClientPermissionType]


class CodeDeliveryDetailsType(TypedDict, total=False):
    Destination: Optional[StringType]
    DeliveryMedium: Optional[DeliveryMediumType]
    AttributeName: Optional[AttributeNameType]


CodeDeliveryDetailsListType = List[CodeDeliveryDetailsType]


class CompromisedCredentialsActionsType(TypedDict, total=False):
    EventAction: CompromisedCredentialsEventActionType


EventFiltersType = List[EventFilterType]


class CompromisedCredentialsRiskConfigurationType(TypedDict, total=False):
    EventFilter: Optional[EventFiltersType]
    Actions: CompromisedCredentialsActionsType


class DeviceSecretVerifierConfigType(TypedDict, total=False):
    PasswordVerifier: Optional[StringType]
    Salt: Optional[StringType]


class ConfirmDeviceRequest(ServiceRequest):
    AccessToken: TokenModelType
    DeviceKey: DeviceKeyType
    DeviceSecretVerifierConfig: Optional[DeviceSecretVerifierConfigType]
    DeviceName: Optional[DeviceNameType]


class ConfirmDeviceResponse(TypedDict, total=False):
    UserConfirmationNecessary: Optional[BooleanType]


class UserContextDataType(TypedDict, total=False):
    EncodedData: Optional[StringType]


class ConfirmForgotPasswordRequest(ServiceRequest):
    ClientId: ClientIdType
    SecretHash: Optional[SecretHashType]
    Username: UsernameType
    ConfirmationCode: ConfirmationCodeType
    Password: PasswordType
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    UserContextData: Optional[UserContextDataType]
    ClientMetadata: Optional[ClientMetadataType]


class ConfirmForgotPasswordResponse(TypedDict, total=False):
    pass


class ConfirmSignUpRequest(ServiceRequest):
    ClientId: ClientIdType
    SecretHash: Optional[SecretHashType]
    Username: UsernameType
    ConfirmationCode: ConfirmationCodeType
    ForceAliasCreation: Optional[ForceAliasCreation]
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    UserContextData: Optional[UserContextDataType]
    ClientMetadata: Optional[ClientMetadataType]


class ConfirmSignUpResponse(TypedDict, total=False):
    pass


class CreateGroupRequest(ServiceRequest):
    GroupName: GroupNameType
    UserPoolId: UserPoolIdType
    Description: Optional[DescriptionType]
    RoleArn: Optional[ArnType]
    Precedence: Optional[PrecedenceType]


class CreateGroupResponse(TypedDict, total=False):
    Group: Optional[GroupType]


IdpIdentifiersListType = List[IdpIdentifierType]
ProviderDetailsType = Dict[StringType, StringType]


class CreateIdentityProviderRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ProviderName: ProviderNameTypeV1
    ProviderType: IdentityProviderTypeType
    ProviderDetails: ProviderDetailsType
    AttributeMapping: Optional[AttributeMappingType]
    IdpIdentifiers: Optional[IdpIdentifiersListType]


class IdentityProviderType(TypedDict, total=False):
    UserPoolId: Optional[UserPoolIdType]
    ProviderName: Optional[ProviderNameType]
    ProviderType: Optional[IdentityProviderTypeType]
    ProviderDetails: Optional[ProviderDetailsType]
    AttributeMapping: Optional[AttributeMappingType]
    IdpIdentifiers: Optional[IdpIdentifiersListType]
    LastModifiedDate: Optional[DateType]
    CreationDate: Optional[DateType]


class CreateIdentityProviderResponse(TypedDict, total=False):
    IdentityProvider: IdentityProviderType


class ResourceServerScopeType(TypedDict, total=False):
    ScopeName: ResourceServerScopeNameType
    ScopeDescription: ResourceServerScopeDescriptionType


ResourceServerScopeListType = List[ResourceServerScopeType]


class CreateResourceServerRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Identifier: ResourceServerIdentifierType
    Name: ResourceServerNameType
    Scopes: Optional[ResourceServerScopeListType]


class ResourceServerType(TypedDict, total=False):
    UserPoolId: Optional[UserPoolIdType]
    Identifier: Optional[ResourceServerIdentifierType]
    Name: Optional[ResourceServerNameType]
    Scopes: Optional[ResourceServerScopeListType]


class CreateResourceServerResponse(TypedDict, total=False):
    ResourceServer: ResourceServerType


class CreateUserImportJobRequest(ServiceRequest):
    JobName: UserImportJobNameType
    UserPoolId: UserPoolIdType
    CloudWatchLogsRoleArn: ArnType


LongType = int


class UserImportJobType(TypedDict, total=False):
    JobName: Optional[UserImportJobNameType]
    JobId: Optional[UserImportJobIdType]
    UserPoolId: Optional[UserPoolIdType]
    PreSignedUrl: Optional[PreSignedUrlType]
    CreationDate: Optional[DateType]
    StartDate: Optional[DateType]
    CompletionDate: Optional[DateType]
    Status: Optional[UserImportJobStatusType]
    CloudWatchLogsRoleArn: Optional[ArnType]
    ImportedUsers: Optional[LongType]
    SkippedUsers: Optional[LongType]
    FailedUsers: Optional[LongType]
    CompletionMessage: Optional[CompletionMessageType]


class CreateUserImportJobResponse(TypedDict, total=False):
    UserImportJob: Optional[UserImportJobType]


ScopeListType = List[ScopeType]
OAuthFlowsType = List[OAuthFlowType]
LogoutURLsListType = List[RedirectUrlType]
SupportedIdentityProvidersListType = List[ProviderNameType]
ExplicitAuthFlowsListType = List[ExplicitAuthFlowsType]


class TokenValidityUnitsType(TypedDict, total=False):
    AccessToken: Optional[TimeUnitsType]
    IdToken: Optional[TimeUnitsType]
    RefreshToken: Optional[TimeUnitsType]


class CreateUserPoolClientRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientName: ClientNameType
    GenerateSecret: Optional[GenerateSecret]
    RefreshTokenValidity: Optional[RefreshTokenValidityType]
    AccessTokenValidity: Optional[AccessTokenValidityType]
    IdTokenValidity: Optional[IdTokenValidityType]
    TokenValidityUnits: Optional[TokenValidityUnitsType]
    ReadAttributes: Optional[ClientPermissionListType]
    WriteAttributes: Optional[ClientPermissionListType]
    ExplicitAuthFlows: Optional[ExplicitAuthFlowsListType]
    SupportedIdentityProviders: Optional[SupportedIdentityProvidersListType]
    CallbackURLs: Optional[CallbackURLsListType]
    LogoutURLs: Optional[LogoutURLsListType]
    DefaultRedirectURI: Optional[RedirectUrlType]
    AllowedOAuthFlows: Optional[OAuthFlowsType]
    AllowedOAuthScopes: Optional[ScopeListType]
    AllowedOAuthFlowsUserPoolClient: Optional[BooleanType]
    AnalyticsConfiguration: Optional[AnalyticsConfigurationType]
    PreventUserExistenceErrors: Optional[PreventUserExistenceErrorTypes]
    EnableTokenRevocation: Optional[WrappedBooleanType]


class UserPoolClientType(TypedDict, total=False):
    UserPoolId: Optional[UserPoolIdType]
    ClientName: Optional[ClientNameType]
    ClientId: Optional[ClientIdType]
    ClientSecret: Optional[ClientSecretType]
    LastModifiedDate: Optional[DateType]
    CreationDate: Optional[DateType]
    RefreshTokenValidity: Optional[RefreshTokenValidityType]
    AccessTokenValidity: Optional[AccessTokenValidityType]
    IdTokenValidity: Optional[IdTokenValidityType]
    TokenValidityUnits: Optional[TokenValidityUnitsType]
    ReadAttributes: Optional[ClientPermissionListType]
    WriteAttributes: Optional[ClientPermissionListType]
    ExplicitAuthFlows: Optional[ExplicitAuthFlowsListType]
    SupportedIdentityProviders: Optional[SupportedIdentityProvidersListType]
    CallbackURLs: Optional[CallbackURLsListType]
    LogoutURLs: Optional[LogoutURLsListType]
    DefaultRedirectURI: Optional[RedirectUrlType]
    AllowedOAuthFlows: Optional[OAuthFlowsType]
    AllowedOAuthScopes: Optional[ScopeListType]
    AllowedOAuthFlowsUserPoolClient: Optional[BooleanType]
    AnalyticsConfiguration: Optional[AnalyticsConfigurationType]
    PreventUserExistenceErrors: Optional[PreventUserExistenceErrorTypes]
    EnableTokenRevocation: Optional[WrappedBooleanType]


class CreateUserPoolClientResponse(TypedDict, total=False):
    UserPoolClient: Optional[UserPoolClientType]


class CustomDomainConfigType(TypedDict, total=False):
    CertificateArn: ArnType


class CreateUserPoolDomainRequest(ServiceRequest):
    Domain: DomainType
    UserPoolId: UserPoolIdType
    CustomDomainConfig: Optional[CustomDomainConfigType]


class CreateUserPoolDomainResponse(TypedDict, total=False):
    CloudFrontDomain: Optional[DomainType]


class UsernameConfigurationType(TypedDict, total=False):
    CaseSensitive: WrappedBooleanType


class UserPoolAddOnsType(TypedDict, total=False):
    AdvancedSecurityMode: AdvancedSecurityModeType


SchemaAttributesListType = List[SchemaAttributeType]
UserPoolTagsType = Dict[TagKeysType, TagValueType]


class SmsConfigurationType(TypedDict, total=False):
    SnsCallerArn: ArnType
    ExternalId: Optional[StringType]


class EmailConfigurationType(TypedDict, total=False):
    SourceArn: Optional[ArnType]
    ReplyToEmailAddress: Optional[EmailAddressType]
    EmailSendingAccount: Optional[EmailSendingAccountType]
    From: Optional[StringType]
    ConfigurationSet: Optional[SESConfigurationSet]


class DeviceConfigurationType(TypedDict, total=False):
    ChallengeRequiredOnNewDevice: Optional[BooleanType]
    DeviceOnlyRememberedOnUserPrompt: Optional[BooleanType]


class VerificationMessageTemplateType(TypedDict, total=False):
    SmsMessage: Optional[SmsVerificationMessageType]
    EmailMessage: Optional[EmailVerificationMessageType]
    EmailSubject: Optional[EmailVerificationSubjectType]
    EmailMessageByLink: Optional[EmailVerificationMessageByLinkType]
    EmailSubjectByLink: Optional[EmailVerificationSubjectByLinkType]
    DefaultEmailOption: Optional[DefaultEmailOptionType]


UsernameAttributesListType = List[UsernameAttributeType]
VerifiedAttributesListType = List[VerifiedAttributeType]


class CustomEmailLambdaVersionConfigType(TypedDict, total=False):
    LambdaVersion: CustomEmailSenderLambdaVersionType
    LambdaArn: ArnType


class CustomSMSLambdaVersionConfigType(TypedDict, total=False):
    LambdaVersion: CustomSMSSenderLambdaVersionType
    LambdaArn: ArnType


class LambdaConfigType(TypedDict, total=False):
    PreSignUp: Optional[ArnType]
    CustomMessage: Optional[ArnType]
    PostConfirmation: Optional[ArnType]
    PreAuthentication: Optional[ArnType]
    PostAuthentication: Optional[ArnType]
    DefineAuthChallenge: Optional[ArnType]
    CreateAuthChallenge: Optional[ArnType]
    VerifyAuthChallengeResponse: Optional[ArnType]
    PreTokenGeneration: Optional[ArnType]
    UserMigration: Optional[ArnType]
    CustomSMSSender: Optional[CustomSMSLambdaVersionConfigType]
    CustomEmailSender: Optional[CustomEmailLambdaVersionConfigType]
    KMSKeyID: Optional[ArnType]


class PasswordPolicyType(TypedDict, total=False):
    MinimumLength: Optional[PasswordPolicyMinLengthType]
    RequireUppercase: Optional[BooleanType]
    RequireLowercase: Optional[BooleanType]
    RequireNumbers: Optional[BooleanType]
    RequireSymbols: Optional[BooleanType]
    TemporaryPasswordValidityDays: Optional[TemporaryPasswordValidityDaysType]


class UserPoolPolicyType(TypedDict, total=False):
    PasswordPolicy: Optional[PasswordPolicyType]


class CreateUserPoolRequest(ServiceRequest):
    PoolName: UserPoolNameType
    Policies: Optional[UserPoolPolicyType]
    LambdaConfig: Optional[LambdaConfigType]
    AutoVerifiedAttributes: Optional[VerifiedAttributesListType]
    AliasAttributes: Optional[AliasAttributesListType]
    UsernameAttributes: Optional[UsernameAttributesListType]
    SmsVerificationMessage: Optional[SmsVerificationMessageType]
    EmailVerificationMessage: Optional[EmailVerificationMessageType]
    EmailVerificationSubject: Optional[EmailVerificationSubjectType]
    VerificationMessageTemplate: Optional[VerificationMessageTemplateType]
    SmsAuthenticationMessage: Optional[SmsVerificationMessageType]
    MfaConfiguration: Optional[UserPoolMfaType]
    DeviceConfiguration: Optional[DeviceConfigurationType]
    EmailConfiguration: Optional[EmailConfigurationType]
    SmsConfiguration: Optional[SmsConfigurationType]
    UserPoolTags: Optional[UserPoolTagsType]
    AdminCreateUserConfig: Optional[AdminCreateUserConfigType]
    Schema: Optional[SchemaAttributesListType]
    UserPoolAddOns: Optional[UserPoolAddOnsType]
    UsernameConfiguration: Optional[UsernameConfigurationType]
    AccountRecoverySetting: Optional[AccountRecoverySettingType]


class UserPoolType(TypedDict, total=False):
    Id: Optional[UserPoolIdType]
    Name: Optional[UserPoolNameType]
    Policies: Optional[UserPoolPolicyType]
    LambdaConfig: Optional[LambdaConfigType]
    Status: Optional[StatusType]
    LastModifiedDate: Optional[DateType]
    CreationDate: Optional[DateType]
    SchemaAttributes: Optional[SchemaAttributesListType]
    AutoVerifiedAttributes: Optional[VerifiedAttributesListType]
    AliasAttributes: Optional[AliasAttributesListType]
    UsernameAttributes: Optional[UsernameAttributesListType]
    SmsVerificationMessage: Optional[SmsVerificationMessageType]
    EmailVerificationMessage: Optional[EmailVerificationMessageType]
    EmailVerificationSubject: Optional[EmailVerificationSubjectType]
    VerificationMessageTemplate: Optional[VerificationMessageTemplateType]
    SmsAuthenticationMessage: Optional[SmsVerificationMessageType]
    MfaConfiguration: Optional[UserPoolMfaType]
    DeviceConfiguration: Optional[DeviceConfigurationType]
    EstimatedNumberOfUsers: Optional[IntegerType]
    EmailConfiguration: Optional[EmailConfigurationType]
    SmsConfiguration: Optional[SmsConfigurationType]
    UserPoolTags: Optional[UserPoolTagsType]
    SmsConfigurationFailure: Optional[StringType]
    EmailConfigurationFailure: Optional[StringType]
    Domain: Optional[DomainType]
    CustomDomain: Optional[DomainType]
    AdminCreateUserConfig: Optional[AdminCreateUserConfigType]
    UserPoolAddOns: Optional[UserPoolAddOnsType]
    UsernameConfiguration: Optional[UsernameConfigurationType]
    Arn: Optional[ArnType]
    AccountRecoverySetting: Optional[AccountRecoverySettingType]


class CreateUserPoolResponse(TypedDict, total=False):
    UserPool: Optional[UserPoolType]


class DeleteGroupRequest(ServiceRequest):
    GroupName: GroupNameType
    UserPoolId: UserPoolIdType


class DeleteIdentityProviderRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ProviderName: ProviderNameType


class DeleteResourceServerRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Identifier: ResourceServerIdentifierType


class DeleteUserAttributesRequest(ServiceRequest):
    UserAttributeNames: AttributeNameListType
    AccessToken: TokenModelType


class DeleteUserAttributesResponse(TypedDict, total=False):
    pass


class DeleteUserPoolClientRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: ClientIdType


class DeleteUserPoolDomainRequest(ServiceRequest):
    Domain: DomainType
    UserPoolId: UserPoolIdType


class DeleteUserPoolDomainResponse(TypedDict, total=False):
    pass


class DeleteUserPoolRequest(ServiceRequest):
    UserPoolId: UserPoolIdType


class DeleteUserRequest(ServiceRequest):
    AccessToken: TokenModelType


class DescribeIdentityProviderRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ProviderName: ProviderNameType


class DescribeIdentityProviderResponse(TypedDict, total=False):
    IdentityProvider: IdentityProviderType


class DescribeResourceServerRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Identifier: ResourceServerIdentifierType


class DescribeResourceServerResponse(TypedDict, total=False):
    ResourceServer: ResourceServerType


class DescribeRiskConfigurationRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: Optional[ClientIdType]


SkippedIPRangeListType = List[StringType]


class RiskExceptionConfigurationType(TypedDict, total=False):
    BlockedIPRangeList: Optional[BlockedIPRangeListType]
    SkippedIPRangeList: Optional[SkippedIPRangeListType]


class RiskConfigurationType(TypedDict, total=False):
    UserPoolId: Optional[UserPoolIdType]
    ClientId: Optional[ClientIdType]
    CompromisedCredentialsRiskConfiguration: Optional[CompromisedCredentialsRiskConfigurationType]
    AccountTakeoverRiskConfiguration: Optional[AccountTakeoverRiskConfigurationType]
    RiskExceptionConfiguration: Optional[RiskExceptionConfigurationType]
    LastModifiedDate: Optional[DateType]


class DescribeRiskConfigurationResponse(TypedDict, total=False):
    RiskConfiguration: RiskConfigurationType


class DescribeUserImportJobRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    JobId: UserImportJobIdType


class DescribeUserImportJobResponse(TypedDict, total=False):
    UserImportJob: Optional[UserImportJobType]


class DescribeUserPoolClientRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: ClientIdType


class DescribeUserPoolClientResponse(TypedDict, total=False):
    UserPoolClient: Optional[UserPoolClientType]


class DescribeUserPoolDomainRequest(ServiceRequest):
    Domain: DomainType


class DomainDescriptionType(TypedDict, total=False):
    UserPoolId: Optional[UserPoolIdType]
    AWSAccountId: Optional[AWSAccountIdType]
    Domain: Optional[DomainType]
    S3Bucket: Optional[S3BucketType]
    CloudFrontDistribution: Optional[StringType]
    Version: Optional[DomainVersionType]
    Status: Optional[DomainStatusType]
    CustomDomainConfig: Optional[CustomDomainConfigType]


class DescribeUserPoolDomainResponse(TypedDict, total=False):
    DomainDescription: Optional[DomainDescriptionType]


class DescribeUserPoolRequest(ServiceRequest):
    UserPoolId: UserPoolIdType


class DescribeUserPoolResponse(TypedDict, total=False):
    UserPool: Optional[UserPoolType]


class ForgetDeviceRequest(ServiceRequest):
    AccessToken: Optional[TokenModelType]
    DeviceKey: DeviceKeyType


class ForgotPasswordRequest(ServiceRequest):
    ClientId: ClientIdType
    SecretHash: Optional[SecretHashType]
    UserContextData: Optional[UserContextDataType]
    Username: UsernameType
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    ClientMetadata: Optional[ClientMetadataType]


class ForgotPasswordResponse(TypedDict, total=False):
    CodeDeliveryDetails: Optional[CodeDeliveryDetailsType]


class GetCSVHeaderRequest(ServiceRequest):
    UserPoolId: UserPoolIdType


ListOfStringTypes = List[StringType]


class GetCSVHeaderResponse(TypedDict, total=False):
    UserPoolId: Optional[UserPoolIdType]
    CSVHeader: Optional[ListOfStringTypes]


class GetDeviceRequest(ServiceRequest):
    DeviceKey: DeviceKeyType
    AccessToken: Optional[TokenModelType]


class GetDeviceResponse(TypedDict, total=False):
    Device: DeviceType


class GetGroupRequest(ServiceRequest):
    GroupName: GroupNameType
    UserPoolId: UserPoolIdType


class GetGroupResponse(TypedDict, total=False):
    Group: Optional[GroupType]


class GetIdentityProviderByIdentifierRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    IdpIdentifier: IdpIdentifierType


class GetIdentityProviderByIdentifierResponse(TypedDict, total=False):
    IdentityProvider: IdentityProviderType


class GetSigningCertificateRequest(ServiceRequest):
    UserPoolId: UserPoolIdType


class GetSigningCertificateResponse(TypedDict, total=False):
    Certificate: Optional[StringType]


class GetUICustomizationRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: Optional[ClientIdType]


class UICustomizationType(TypedDict, total=False):
    UserPoolId: Optional[UserPoolIdType]
    ClientId: Optional[ClientIdType]
    ImageUrl: Optional[ImageUrlType]
    CSS: Optional[CSSType]
    CSSVersion: Optional[CSSVersionType]
    LastModifiedDate: Optional[DateType]
    CreationDate: Optional[DateType]


class GetUICustomizationResponse(TypedDict, total=False):
    UICustomization: UICustomizationType


class GetUserAttributeVerificationCodeRequest(ServiceRequest):
    AccessToken: TokenModelType
    AttributeName: AttributeNameType
    ClientMetadata: Optional[ClientMetadataType]


class GetUserAttributeVerificationCodeResponse(TypedDict, total=False):
    CodeDeliveryDetails: Optional[CodeDeliveryDetailsType]


class GetUserPoolMfaConfigRequest(ServiceRequest):
    UserPoolId: UserPoolIdType


class SoftwareTokenMfaConfigType(TypedDict, total=False):
    Enabled: Optional[BooleanType]


class SmsMfaConfigType(TypedDict, total=False):
    SmsAuthenticationMessage: Optional[SmsVerificationMessageType]
    SmsConfiguration: Optional[SmsConfigurationType]


class GetUserPoolMfaConfigResponse(TypedDict, total=False):
    SmsMfaConfiguration: Optional[SmsMfaConfigType]
    SoftwareTokenMfaConfiguration: Optional[SoftwareTokenMfaConfigType]
    MfaConfiguration: Optional[UserPoolMfaType]


class GetUserRequest(ServiceRequest):
    AccessToken: TokenModelType


class GetUserResponse(TypedDict, total=False):
    Username: UsernameType
    UserAttributes: AttributeListType
    MFAOptions: Optional[MFAOptionListType]
    PreferredMfaSetting: Optional[StringType]
    UserMFASettingList: Optional[UserMFASettingListType]


class GlobalSignOutRequest(ServiceRequest):
    AccessToken: TokenModelType


class GlobalSignOutResponse(TypedDict, total=False):
    pass


ImageFileType = bytes


class InitiateAuthRequest(ServiceRequest):
    AuthFlow: AuthFlowType
    AuthParameters: Optional[AuthParametersType]
    ClientMetadata: Optional[ClientMetadataType]
    ClientId: ClientIdType
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    UserContextData: Optional[UserContextDataType]


class InitiateAuthResponse(TypedDict, total=False):
    ChallengeName: Optional[ChallengeNameType]
    Session: Optional[SessionType]
    ChallengeParameters: Optional[ChallengeParametersType]
    AuthenticationResult: Optional[AuthenticationResultType]


class ListDevicesRequest(ServiceRequest):
    AccessToken: TokenModelType
    Limit: Optional[QueryLimitType]
    PaginationToken: Optional[SearchPaginationTokenType]


class ListDevicesResponse(TypedDict, total=False):
    Devices: Optional[DeviceListType]
    PaginationToken: Optional[SearchPaginationTokenType]


class ListGroupsRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Limit: Optional[QueryLimitType]
    NextToken: Optional[PaginationKey]


class ListGroupsResponse(TypedDict, total=False):
    Groups: Optional[GroupListType]
    NextToken: Optional[PaginationKey]


class ListIdentityProvidersRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    MaxResults: Optional[ListProvidersLimitType]
    NextToken: Optional[PaginationKeyType]


class ProviderDescription(TypedDict, total=False):
    ProviderName: Optional[ProviderNameType]
    ProviderType: Optional[IdentityProviderTypeType]
    LastModifiedDate: Optional[DateType]
    CreationDate: Optional[DateType]


ProvidersListType = List[ProviderDescription]


class ListIdentityProvidersResponse(TypedDict, total=False):
    Providers: ProvidersListType
    NextToken: Optional[PaginationKeyType]


class ListResourceServersRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    MaxResults: Optional[ListResourceServersLimitType]
    NextToken: Optional[PaginationKeyType]


ResourceServersListType = List[ResourceServerType]


class ListResourceServersResponse(TypedDict, total=False):
    ResourceServers: ResourceServersListType
    NextToken: Optional[PaginationKeyType]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: ArnType


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[UserPoolTagsType]


class ListUserImportJobsRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    MaxResults: PoolQueryLimitType
    PaginationToken: Optional[PaginationKeyType]


UserImportJobsListType = List[UserImportJobType]


class ListUserImportJobsResponse(TypedDict, total=False):
    UserImportJobs: Optional[UserImportJobsListType]
    PaginationToken: Optional[PaginationKeyType]


class ListUserPoolClientsRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    MaxResults: Optional[QueryLimit]
    NextToken: Optional[PaginationKey]


class UserPoolClientDescription(TypedDict, total=False):
    ClientId: Optional[ClientIdType]
    UserPoolId: Optional[UserPoolIdType]
    ClientName: Optional[ClientNameType]


UserPoolClientListType = List[UserPoolClientDescription]


class ListUserPoolClientsResponse(TypedDict, total=False):
    UserPoolClients: Optional[UserPoolClientListType]
    NextToken: Optional[PaginationKey]


class ListUserPoolsRequest(ServiceRequest):
    NextToken: Optional[PaginationKeyType]
    MaxResults: PoolQueryLimitType


class UserPoolDescriptionType(TypedDict, total=False):
    Id: Optional[UserPoolIdType]
    Name: Optional[UserPoolNameType]
    LambdaConfig: Optional[LambdaConfigType]
    Status: Optional[StatusType]
    LastModifiedDate: Optional[DateType]
    CreationDate: Optional[DateType]


UserPoolListType = List[UserPoolDescriptionType]


class ListUserPoolsResponse(TypedDict, total=False):
    UserPools: Optional[UserPoolListType]
    NextToken: Optional[PaginationKeyType]


class ListUsersInGroupRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    GroupName: GroupNameType
    Limit: Optional[QueryLimitType]
    NextToken: Optional[PaginationKey]


UsersListType = List[UserType]


class ListUsersInGroupResponse(TypedDict, total=False):
    Users: Optional[UsersListType]
    NextToken: Optional[PaginationKey]


SearchedAttributeNamesListType = List[AttributeNameType]


class ListUsersRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    AttributesToGet: Optional[SearchedAttributeNamesListType]
    Limit: Optional[QueryLimitType]
    PaginationToken: Optional[SearchPaginationTokenType]
    Filter: Optional[UserFilterType]


class ListUsersResponse(TypedDict, total=False):
    Users: Optional[UsersListType]
    PaginationToken: Optional[SearchPaginationTokenType]


class ResendConfirmationCodeRequest(ServiceRequest):
    ClientId: ClientIdType
    SecretHash: Optional[SecretHashType]
    UserContextData: Optional[UserContextDataType]
    Username: UsernameType
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    ClientMetadata: Optional[ClientMetadataType]


class ResendConfirmationCodeResponse(TypedDict, total=False):
    CodeDeliveryDetails: Optional[CodeDeliveryDetailsType]


class RespondToAuthChallengeRequest(ServiceRequest):
    ClientId: ClientIdType
    ChallengeName: ChallengeNameType
    Session: Optional[SessionType]
    ChallengeResponses: Optional[ChallengeResponsesType]
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    UserContextData: Optional[UserContextDataType]
    ClientMetadata: Optional[ClientMetadataType]


class RespondToAuthChallengeResponse(TypedDict, total=False):
    ChallengeName: Optional[ChallengeNameType]
    Session: Optional[SessionType]
    ChallengeParameters: Optional[ChallengeParametersType]
    AuthenticationResult: Optional[AuthenticationResultType]


class RevokeTokenRequest(ServiceRequest):
    Token: TokenModelType
    ClientId: ClientIdType
    ClientSecret: Optional[ClientSecretType]


class RevokeTokenResponse(TypedDict, total=False):
    pass


class SetRiskConfigurationRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: Optional[ClientIdType]
    CompromisedCredentialsRiskConfiguration: Optional[CompromisedCredentialsRiskConfigurationType]
    AccountTakeoverRiskConfiguration: Optional[AccountTakeoverRiskConfigurationType]
    RiskExceptionConfiguration: Optional[RiskExceptionConfigurationType]


class SetRiskConfigurationResponse(TypedDict, total=False):
    RiskConfiguration: RiskConfigurationType


class SetUICustomizationRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: Optional[ClientIdType]
    CSS: Optional[CSSType]
    ImageFile: Optional[ImageFileType]


class SetUICustomizationResponse(TypedDict, total=False):
    UICustomization: UICustomizationType


class SetUserMFAPreferenceRequest(ServiceRequest):
    SMSMfaSettings: Optional[SMSMfaSettingsType]
    SoftwareTokenMfaSettings: Optional[SoftwareTokenMfaSettingsType]
    AccessToken: TokenModelType


class SetUserMFAPreferenceResponse(TypedDict, total=False):
    pass


class SetUserPoolMfaConfigRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    SmsMfaConfiguration: Optional[SmsMfaConfigType]
    SoftwareTokenMfaConfiguration: Optional[SoftwareTokenMfaConfigType]
    MfaConfiguration: Optional[UserPoolMfaType]


class SetUserPoolMfaConfigResponse(TypedDict, total=False):
    SmsMfaConfiguration: Optional[SmsMfaConfigType]
    SoftwareTokenMfaConfiguration: Optional[SoftwareTokenMfaConfigType]
    MfaConfiguration: Optional[UserPoolMfaType]


class SetUserSettingsRequest(ServiceRequest):
    AccessToken: TokenModelType
    MFAOptions: MFAOptionListType


class SetUserSettingsResponse(TypedDict, total=False):
    pass


class SignUpRequest(ServiceRequest):
    ClientId: ClientIdType
    SecretHash: Optional[SecretHashType]
    Username: UsernameType
    Password: PasswordType
    UserAttributes: Optional[AttributeListType]
    ValidationData: Optional[AttributeListType]
    AnalyticsMetadata: Optional[AnalyticsMetadataType]
    UserContextData: Optional[UserContextDataType]
    ClientMetadata: Optional[ClientMetadataType]


class SignUpResponse(TypedDict, total=False):
    UserConfirmed: BooleanType
    CodeDeliveryDetails: Optional[CodeDeliveryDetailsType]
    UserSub: StringType


class StartUserImportJobRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    JobId: UserImportJobIdType


class StartUserImportJobResponse(TypedDict, total=False):
    UserImportJob: Optional[UserImportJobType]


class StopUserImportJobRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    JobId: UserImportJobIdType


class StopUserImportJobResponse(TypedDict, total=False):
    UserImportJob: Optional[UserImportJobType]


class TagResourceRequest(ServiceRequest):
    ResourceArn: ArnType
    Tags: UserPoolTagsType


class TagResourceResponse(TypedDict, total=False):
    pass


UserPoolTagsListType = List[TagKeysType]


class UntagResourceRequest(ServiceRequest):
    ResourceArn: ArnType
    TagKeys: UserPoolTagsListType


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateAuthEventFeedbackRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Username: UsernameType
    EventId: EventIdType
    FeedbackToken: TokenModelType
    FeedbackValue: FeedbackValueType


class UpdateAuthEventFeedbackResponse(TypedDict, total=False):
    pass


class UpdateDeviceStatusRequest(ServiceRequest):
    AccessToken: TokenModelType
    DeviceKey: DeviceKeyType
    DeviceRememberedStatus: Optional[DeviceRememberedStatusType]


class UpdateDeviceStatusResponse(TypedDict, total=False):
    pass


class UpdateGroupRequest(ServiceRequest):
    GroupName: GroupNameType
    UserPoolId: UserPoolIdType
    Description: Optional[DescriptionType]
    RoleArn: Optional[ArnType]
    Precedence: Optional[PrecedenceType]


class UpdateGroupResponse(TypedDict, total=False):
    Group: Optional[GroupType]


class UpdateIdentityProviderRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ProviderName: ProviderNameType
    ProviderDetails: Optional[ProviderDetailsType]
    AttributeMapping: Optional[AttributeMappingType]
    IdpIdentifiers: Optional[IdpIdentifiersListType]


class UpdateIdentityProviderResponse(TypedDict, total=False):
    IdentityProvider: IdentityProviderType


class UpdateResourceServerRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Identifier: ResourceServerIdentifierType
    Name: ResourceServerNameType
    Scopes: Optional[ResourceServerScopeListType]


class UpdateResourceServerResponse(TypedDict, total=False):
    ResourceServer: ResourceServerType


class UpdateUserAttributesRequest(ServiceRequest):
    UserAttributes: AttributeListType
    AccessToken: TokenModelType
    ClientMetadata: Optional[ClientMetadataType]


class UpdateUserAttributesResponse(TypedDict, total=False):
    CodeDeliveryDetailsList: Optional[CodeDeliveryDetailsListType]


class UpdateUserPoolClientRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    ClientId: ClientIdType
    ClientName: Optional[ClientNameType]
    RefreshTokenValidity: Optional[RefreshTokenValidityType]
    AccessTokenValidity: Optional[AccessTokenValidityType]
    IdTokenValidity: Optional[IdTokenValidityType]
    TokenValidityUnits: Optional[TokenValidityUnitsType]
    ReadAttributes: Optional[ClientPermissionListType]
    WriteAttributes: Optional[ClientPermissionListType]
    ExplicitAuthFlows: Optional[ExplicitAuthFlowsListType]
    SupportedIdentityProviders: Optional[SupportedIdentityProvidersListType]
    CallbackURLs: Optional[CallbackURLsListType]
    LogoutURLs: Optional[LogoutURLsListType]
    DefaultRedirectURI: Optional[RedirectUrlType]
    AllowedOAuthFlows: Optional[OAuthFlowsType]
    AllowedOAuthScopes: Optional[ScopeListType]
    AllowedOAuthFlowsUserPoolClient: Optional[BooleanType]
    AnalyticsConfiguration: Optional[AnalyticsConfigurationType]
    PreventUserExistenceErrors: Optional[PreventUserExistenceErrorTypes]
    EnableTokenRevocation: Optional[WrappedBooleanType]


class UpdateUserPoolClientResponse(TypedDict, total=False):
    UserPoolClient: Optional[UserPoolClientType]


class UpdateUserPoolDomainRequest(ServiceRequest):
    Domain: DomainType
    UserPoolId: UserPoolIdType
    CustomDomainConfig: CustomDomainConfigType


class UpdateUserPoolDomainResponse(TypedDict, total=False):
    CloudFrontDomain: Optional[DomainType]


class UpdateUserPoolRequest(ServiceRequest):
    UserPoolId: UserPoolIdType
    Policies: Optional[UserPoolPolicyType]
    LambdaConfig: Optional[LambdaConfigType]
    AutoVerifiedAttributes: Optional[VerifiedAttributesListType]
    SmsVerificationMessage: Optional[SmsVerificationMessageType]
    EmailVerificationMessage: Optional[EmailVerificationMessageType]
    EmailVerificationSubject: Optional[EmailVerificationSubjectType]
    VerificationMessageTemplate: Optional[VerificationMessageTemplateType]
    SmsAuthenticationMessage: Optional[SmsVerificationMessageType]
    MfaConfiguration: Optional[UserPoolMfaType]
    DeviceConfiguration: Optional[DeviceConfigurationType]
    EmailConfiguration: Optional[EmailConfigurationType]
    SmsConfiguration: Optional[SmsConfigurationType]
    UserPoolTags: Optional[UserPoolTagsType]
    AdminCreateUserConfig: Optional[AdminCreateUserConfigType]
    UserPoolAddOns: Optional[UserPoolAddOnsType]
    AccountRecoverySetting: Optional[AccountRecoverySettingType]


class UpdateUserPoolResponse(TypedDict, total=False):
    pass


class VerifySoftwareTokenRequest(ServiceRequest):
    AccessToken: Optional[TokenModelType]
    Session: Optional[SessionType]
    UserCode: SoftwareTokenMFAUserCodeType
    FriendlyDeviceName: Optional[StringType]


class VerifySoftwareTokenResponse(TypedDict, total=False):
    Status: Optional[VerifySoftwareTokenResponseType]
    Session: Optional[SessionType]


class VerifyUserAttributeRequest(ServiceRequest):
    AccessToken: TokenModelType
    AttributeName: AttributeNameType
    Code: ConfirmationCodeType


class VerifyUserAttributeResponse(TypedDict, total=False):
    pass


class CognitoIdpApi:

    service = "cognito-idp"
    version = "2016-04-18"

    @handler("AddCustomAttributes")
    def add_custom_attributes(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        custom_attributes: CustomAttributesListType,
    ) -> AddCustomAttributesResponse:
        raise NotImplementedError

    @handler("AdminAddUserToGroup")
    def admin_add_user_to_group(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        group_name: GroupNameType,
    ) -> None:
        raise NotImplementedError

    @handler("AdminConfirmSignUp")
    def admin_confirm_sign_up(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        client_metadata: ClientMetadataType = None,
    ) -> AdminConfirmSignUpResponse:
        raise NotImplementedError

    @handler("AdminCreateUser")
    def admin_create_user(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        user_attributes: AttributeListType = None,
        validation_data: AttributeListType = None,
        temporary_password: PasswordType = None,
        force_alias_creation: ForceAliasCreation = None,
        message_action: MessageActionType = None,
        desired_delivery_mediums: DeliveryMediumListType = None,
        client_metadata: ClientMetadataType = None,
    ) -> AdminCreateUserResponse:
        raise NotImplementedError

    @handler("AdminDeleteUser")
    def admin_delete_user(
        self, context: RequestContext, user_pool_id: UserPoolIdType, username: UsernameType
    ) -> None:
        raise NotImplementedError

    @handler("AdminDeleteUserAttributes")
    def admin_delete_user_attributes(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        user_attribute_names: AttributeNameListType,
    ) -> AdminDeleteUserAttributesResponse:
        raise NotImplementedError

    @handler("AdminDisableProviderForUser")
    def admin_disable_provider_for_user(
        self, context: RequestContext, user_pool_id: StringType, user: ProviderUserIdentifierType
    ) -> AdminDisableProviderForUserResponse:
        raise NotImplementedError

    @handler("AdminDisableUser")
    def admin_disable_user(
        self, context: RequestContext, user_pool_id: UserPoolIdType, username: UsernameType
    ) -> AdminDisableUserResponse:
        raise NotImplementedError

    @handler("AdminEnableUser")
    def admin_enable_user(
        self, context: RequestContext, user_pool_id: UserPoolIdType, username: UsernameType
    ) -> AdminEnableUserResponse:
        raise NotImplementedError

    @handler("AdminForgetDevice")
    def admin_forget_device(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        device_key: DeviceKeyType,
    ) -> None:
        raise NotImplementedError

    @handler("AdminGetDevice")
    def admin_get_device(
        self,
        context: RequestContext,
        device_key: DeviceKeyType,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
    ) -> AdminGetDeviceResponse:
        raise NotImplementedError

    @handler("AdminGetUser")
    def admin_get_user(
        self, context: RequestContext, user_pool_id: UserPoolIdType, username: UsernameType
    ) -> AdminGetUserResponse:
        raise NotImplementedError

    @handler("AdminInitiateAuth")
    def admin_initiate_auth(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        client_id: ClientIdType,
        auth_flow: AuthFlowType,
        auth_parameters: AuthParametersType = None,
        client_metadata: ClientMetadataType = None,
        analytics_metadata: AnalyticsMetadataType = None,
        context_data: ContextDataType = None,
    ) -> AdminInitiateAuthResponse:
        raise NotImplementedError

    @handler("AdminLinkProviderForUser")
    def admin_link_provider_for_user(
        self,
        context: RequestContext,
        user_pool_id: StringType,
        destination_user: ProviderUserIdentifierType,
        source_user: ProviderUserIdentifierType,
    ) -> AdminLinkProviderForUserResponse:
        raise NotImplementedError

    @handler("AdminListDevices")
    def admin_list_devices(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        limit: QueryLimitType = None,
        pagination_token: SearchPaginationTokenType = None,
    ) -> AdminListDevicesResponse:
        raise NotImplementedError

    @handler("AdminListGroupsForUser")
    def admin_list_groups_for_user(
        self,
        context: RequestContext,
        username: UsernameType,
        user_pool_id: UserPoolIdType,
        limit: QueryLimitType = None,
        next_token: PaginationKey = None,
    ) -> AdminListGroupsForUserResponse:
        raise NotImplementedError

    @handler("AdminListUserAuthEvents")
    def admin_list_user_auth_events(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        max_results: QueryLimitType = None,
        next_token: PaginationKey = None,
    ) -> AdminListUserAuthEventsResponse:
        raise NotImplementedError

    @handler("AdminRemoveUserFromGroup")
    def admin_remove_user_from_group(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        group_name: GroupNameType,
    ) -> None:
        raise NotImplementedError

    @handler("AdminResetUserPassword")
    def admin_reset_user_password(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        client_metadata: ClientMetadataType = None,
    ) -> AdminResetUserPasswordResponse:
        raise NotImplementedError

    @handler("AdminRespondToAuthChallenge")
    def admin_respond_to_auth_challenge(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        client_id: ClientIdType,
        challenge_name: ChallengeNameType,
        challenge_responses: ChallengeResponsesType = None,
        session: SessionType = None,
        analytics_metadata: AnalyticsMetadataType = None,
        context_data: ContextDataType = None,
        client_metadata: ClientMetadataType = None,
    ) -> AdminRespondToAuthChallengeResponse:
        raise NotImplementedError

    @handler("AdminSetUserMFAPreference")
    def admin_set_user_mfa_preference(
        self,
        context: RequestContext,
        username: UsernameType,
        user_pool_id: UserPoolIdType,
        sms_mfa_settings: SMSMfaSettingsType = None,
        software_token_mfa_settings: SoftwareTokenMfaSettingsType = None,
    ) -> AdminSetUserMFAPreferenceResponse:
        raise NotImplementedError

    @handler("AdminSetUserPassword")
    def admin_set_user_password(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        password: PasswordType,
        permanent: BooleanType = None,
    ) -> AdminSetUserPasswordResponse:
        raise NotImplementedError

    @handler("AdminSetUserSettings")
    def admin_set_user_settings(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        mfa_options: MFAOptionListType,
    ) -> AdminSetUserSettingsResponse:
        raise NotImplementedError

    @handler("AdminUpdateAuthEventFeedback")
    def admin_update_auth_event_feedback(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        event_id: EventIdType,
        feedback_value: FeedbackValueType,
    ) -> AdminUpdateAuthEventFeedbackResponse:
        raise NotImplementedError

    @handler("AdminUpdateDeviceStatus")
    def admin_update_device_status(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        device_key: DeviceKeyType,
        device_remembered_status: DeviceRememberedStatusType = None,
    ) -> AdminUpdateDeviceStatusResponse:
        raise NotImplementedError

    @handler("AdminUpdateUserAttributes")
    def admin_update_user_attributes(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        user_attributes: AttributeListType,
        client_metadata: ClientMetadataType = None,
    ) -> AdminUpdateUserAttributesResponse:
        raise NotImplementedError

    @handler("AdminUserGlobalSignOut")
    def admin_user_global_sign_out(
        self, context: RequestContext, user_pool_id: UserPoolIdType, username: UsernameType
    ) -> AdminUserGlobalSignOutResponse:
        raise NotImplementedError

    @handler("AssociateSoftwareToken")
    def associate_software_token(
        self,
        context: RequestContext,
        access_token: TokenModelType = None,
        session: SessionType = None,
    ) -> AssociateSoftwareTokenResponse:
        raise NotImplementedError

    @handler("ChangePassword")
    def change_password(
        self,
        context: RequestContext,
        previous_password: PasswordType,
        proposed_password: PasswordType,
        access_token: TokenModelType,
    ) -> ChangePasswordResponse:
        raise NotImplementedError

    @handler("ConfirmDevice")
    def confirm_device(
        self,
        context: RequestContext,
        access_token: TokenModelType,
        device_key: DeviceKeyType,
        device_secret_verifier_config: DeviceSecretVerifierConfigType = None,
        device_name: DeviceNameType = None,
    ) -> ConfirmDeviceResponse:
        raise NotImplementedError

    @handler("ConfirmForgotPassword")
    def confirm_forgot_password(
        self,
        context: RequestContext,
        client_id: ClientIdType,
        username: UsernameType,
        confirmation_code: ConfirmationCodeType,
        password: PasswordType,
        secret_hash: SecretHashType = None,
        analytics_metadata: AnalyticsMetadataType = None,
        user_context_data: UserContextDataType = None,
        client_metadata: ClientMetadataType = None,
    ) -> ConfirmForgotPasswordResponse:
        raise NotImplementedError

    @handler("ConfirmSignUp")
    def confirm_sign_up(
        self,
        context: RequestContext,
        client_id: ClientIdType,
        username: UsernameType,
        confirmation_code: ConfirmationCodeType,
        secret_hash: SecretHashType = None,
        force_alias_creation: ForceAliasCreation = None,
        analytics_metadata: AnalyticsMetadataType = None,
        user_context_data: UserContextDataType = None,
        client_metadata: ClientMetadataType = None,
    ) -> ConfirmSignUpResponse:
        raise NotImplementedError

    @handler("CreateGroup")
    def create_group(
        self,
        context: RequestContext,
        group_name: GroupNameType,
        user_pool_id: UserPoolIdType,
        description: DescriptionType = None,
        role_arn: ArnType = None,
        precedence: PrecedenceType = None,
    ) -> CreateGroupResponse:
        raise NotImplementedError

    @handler("CreateIdentityProvider")
    def create_identity_provider(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        provider_name: ProviderNameTypeV1,
        provider_type: IdentityProviderTypeType,
        provider_details: ProviderDetailsType,
        attribute_mapping: AttributeMappingType = None,
        idp_identifiers: IdpIdentifiersListType = None,
    ) -> CreateIdentityProviderResponse:
        raise NotImplementedError

    @handler("CreateResourceServer")
    def create_resource_server(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        identifier: ResourceServerIdentifierType,
        name: ResourceServerNameType,
        scopes: ResourceServerScopeListType = None,
    ) -> CreateResourceServerResponse:
        raise NotImplementedError

    @handler("CreateUserImportJob")
    def create_user_import_job(
        self,
        context: RequestContext,
        job_name: UserImportJobNameType,
        user_pool_id: UserPoolIdType,
        cloud_watch_logs_role_arn: ArnType,
    ) -> CreateUserImportJobResponse:
        raise NotImplementedError

    @handler("CreateUserPool")
    def create_user_pool(
        self,
        context: RequestContext,
        pool_name: UserPoolNameType,
        policies: UserPoolPolicyType = None,
        lambda_config: LambdaConfigType = None,
        auto_verified_attributes: VerifiedAttributesListType = None,
        alias_attributes: AliasAttributesListType = None,
        username_attributes: UsernameAttributesListType = None,
        sms_verification_message: SmsVerificationMessageType = None,
        email_verification_message: EmailVerificationMessageType = None,
        email_verification_subject: EmailVerificationSubjectType = None,
        verification_message_template: VerificationMessageTemplateType = None,
        sms_authentication_message: SmsVerificationMessageType = None,
        mfa_configuration: UserPoolMfaType = None,
        device_configuration: DeviceConfigurationType = None,
        email_configuration: EmailConfigurationType = None,
        sms_configuration: SmsConfigurationType = None,
        user_pool_tags: UserPoolTagsType = None,
        admin_create_user_config: AdminCreateUserConfigType = None,
        schema: SchemaAttributesListType = None,
        user_pool_add_ons: UserPoolAddOnsType = None,
        username_configuration: UsernameConfigurationType = None,
        account_recovery_setting: AccountRecoverySettingType = None,
    ) -> CreateUserPoolResponse:
        raise NotImplementedError

    @handler("CreateUserPoolClient")
    def create_user_pool_client(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        client_name: ClientNameType,
        generate_secret: GenerateSecret = None,
        refresh_token_validity: RefreshTokenValidityType = None,
        access_token_validity: AccessTokenValidityType = None,
        id_token_validity: IdTokenValidityType = None,
        token_validity_units: TokenValidityUnitsType = None,
        read_attributes: ClientPermissionListType = None,
        write_attributes: ClientPermissionListType = None,
        explicit_auth_flows: ExplicitAuthFlowsListType = None,
        supported_identity_providers: SupportedIdentityProvidersListType = None,
        callback_urls: CallbackURLsListType = None,
        logout_urls: LogoutURLsListType = None,
        default_redirect_uri: RedirectUrlType = None,
        allowed_o_auth_flows: OAuthFlowsType = None,
        allowed_o_auth_scopes: ScopeListType = None,
        allowed_o_auth_flows_user_pool_client: BooleanType = None,
        analytics_configuration: AnalyticsConfigurationType = None,
        prevent_user_existence_errors: PreventUserExistenceErrorTypes = None,
        enable_token_revocation: WrappedBooleanType = None,
    ) -> CreateUserPoolClientResponse:
        raise NotImplementedError

    @handler("CreateUserPoolDomain")
    def create_user_pool_domain(
        self,
        context: RequestContext,
        domain: DomainType,
        user_pool_id: UserPoolIdType,
        custom_domain_config: CustomDomainConfigType = None,
    ) -> CreateUserPoolDomainResponse:
        raise NotImplementedError

    @handler("DeleteGroup")
    def delete_group(
        self, context: RequestContext, group_name: GroupNameType, user_pool_id: UserPoolIdType
    ) -> None:
        raise NotImplementedError

    @handler("DeleteIdentityProvider")
    def delete_identity_provider(
        self, context: RequestContext, user_pool_id: UserPoolIdType, provider_name: ProviderNameType
    ) -> None:
        raise NotImplementedError

    @handler("DeleteResourceServer")
    def delete_resource_server(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        identifier: ResourceServerIdentifierType,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUser")
    def delete_user(self, context: RequestContext, access_token: TokenModelType) -> None:
        raise NotImplementedError

    @handler("DeleteUserAttributes")
    def delete_user_attributes(
        self,
        context: RequestContext,
        user_attribute_names: AttributeNameListType,
        access_token: TokenModelType,
    ) -> DeleteUserAttributesResponse:
        raise NotImplementedError

    @handler("DeleteUserPool")
    def delete_user_pool(self, context: RequestContext, user_pool_id: UserPoolIdType) -> None:
        raise NotImplementedError

    @handler("DeleteUserPoolClient")
    def delete_user_pool_client(
        self, context: RequestContext, user_pool_id: UserPoolIdType, client_id: ClientIdType
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUserPoolDomain")
    def delete_user_pool_domain(
        self, context: RequestContext, domain: DomainType, user_pool_id: UserPoolIdType
    ) -> DeleteUserPoolDomainResponse:
        raise NotImplementedError

    @handler("DescribeIdentityProvider")
    def describe_identity_provider(
        self, context: RequestContext, user_pool_id: UserPoolIdType, provider_name: ProviderNameType
    ) -> DescribeIdentityProviderResponse:
        raise NotImplementedError

    @handler("DescribeResourceServer")
    def describe_resource_server(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        identifier: ResourceServerIdentifierType,
    ) -> DescribeResourceServerResponse:
        raise NotImplementedError

    @handler("DescribeRiskConfiguration")
    def describe_risk_configuration(
        self, context: RequestContext, user_pool_id: UserPoolIdType, client_id: ClientIdType = None
    ) -> DescribeRiskConfigurationResponse:
        raise NotImplementedError

    @handler("DescribeUserImportJob")
    def describe_user_import_job(
        self, context: RequestContext, user_pool_id: UserPoolIdType, job_id: UserImportJobIdType
    ) -> DescribeUserImportJobResponse:
        raise NotImplementedError

    @handler("DescribeUserPool")
    def describe_user_pool(
        self, context: RequestContext, user_pool_id: UserPoolIdType
    ) -> DescribeUserPoolResponse:
        raise NotImplementedError

    @handler("DescribeUserPoolClient")
    def describe_user_pool_client(
        self, context: RequestContext, user_pool_id: UserPoolIdType, client_id: ClientIdType
    ) -> DescribeUserPoolClientResponse:
        raise NotImplementedError

    @handler("DescribeUserPoolDomain")
    def describe_user_pool_domain(
        self, context: RequestContext, domain: DomainType
    ) -> DescribeUserPoolDomainResponse:
        raise NotImplementedError

    @handler("ForgetDevice")
    def forget_device(
        self,
        context: RequestContext,
        device_key: DeviceKeyType,
        access_token: TokenModelType = None,
    ) -> None:
        raise NotImplementedError

    @handler("ForgotPassword")
    def forgot_password(
        self,
        context: RequestContext,
        client_id: ClientIdType,
        username: UsernameType,
        secret_hash: SecretHashType = None,
        user_context_data: UserContextDataType = None,
        analytics_metadata: AnalyticsMetadataType = None,
        client_metadata: ClientMetadataType = None,
    ) -> ForgotPasswordResponse:
        raise NotImplementedError

    @handler("GetCSVHeader")
    def get_csv_header(
        self, context: RequestContext, user_pool_id: UserPoolIdType
    ) -> GetCSVHeaderResponse:
        raise NotImplementedError

    @handler("GetDevice")
    def get_device(
        self,
        context: RequestContext,
        device_key: DeviceKeyType,
        access_token: TokenModelType = None,
    ) -> GetDeviceResponse:
        raise NotImplementedError

    @handler("GetGroup")
    def get_group(
        self, context: RequestContext, group_name: GroupNameType, user_pool_id: UserPoolIdType
    ) -> GetGroupResponse:
        raise NotImplementedError

    @handler("GetIdentityProviderByIdentifier")
    def get_identity_provider_by_identifier(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        idp_identifier: IdpIdentifierType,
    ) -> GetIdentityProviderByIdentifierResponse:
        raise NotImplementedError

    @handler("GetSigningCertificate")
    def get_signing_certificate(
        self, context: RequestContext, user_pool_id: UserPoolIdType
    ) -> GetSigningCertificateResponse:
        raise NotImplementedError

    @handler("GetUICustomization")
    def get_ui_customization(
        self, context: RequestContext, user_pool_id: UserPoolIdType, client_id: ClientIdType = None
    ) -> GetUICustomizationResponse:
        raise NotImplementedError

    @handler("GetUser")
    def get_user(self, context: RequestContext, access_token: TokenModelType) -> GetUserResponse:
        raise NotImplementedError

    @handler("GetUserAttributeVerificationCode")
    def get_user_attribute_verification_code(
        self,
        context: RequestContext,
        access_token: TokenModelType,
        attribute_name: AttributeNameType,
        client_metadata: ClientMetadataType = None,
    ) -> GetUserAttributeVerificationCodeResponse:
        raise NotImplementedError

    @handler("GetUserPoolMfaConfig")
    def get_user_pool_mfa_config(
        self, context: RequestContext, user_pool_id: UserPoolIdType
    ) -> GetUserPoolMfaConfigResponse:
        raise NotImplementedError

    @handler("GlobalSignOut")
    def global_sign_out(
        self, context: RequestContext, access_token: TokenModelType
    ) -> GlobalSignOutResponse:
        raise NotImplementedError

    @handler("InitiateAuth")
    def initiate_auth(
        self,
        context: RequestContext,
        auth_flow: AuthFlowType,
        client_id: ClientIdType,
        auth_parameters: AuthParametersType = None,
        client_metadata: ClientMetadataType = None,
        analytics_metadata: AnalyticsMetadataType = None,
        user_context_data: UserContextDataType = None,
    ) -> InitiateAuthResponse:
        raise NotImplementedError

    @handler("ListDevices")
    def list_devices(
        self,
        context: RequestContext,
        access_token: TokenModelType,
        limit: QueryLimitType = None,
        pagination_token: SearchPaginationTokenType = None,
    ) -> ListDevicesResponse:
        raise NotImplementedError

    @handler("ListGroups")
    def list_groups(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        limit: QueryLimitType = None,
        next_token: PaginationKey = None,
    ) -> ListGroupsResponse:
        raise NotImplementedError

    @handler("ListIdentityProviders")
    def list_identity_providers(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        max_results: ListProvidersLimitType = None,
        next_token: PaginationKeyType = None,
    ) -> ListIdentityProvidersResponse:
        raise NotImplementedError

    @handler("ListResourceServers")
    def list_resource_servers(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        max_results: ListResourceServersLimitType = None,
        next_token: PaginationKeyType = None,
    ) -> ListResourceServersResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ArnType
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListUserImportJobs")
    def list_user_import_jobs(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        max_results: PoolQueryLimitType,
        pagination_token: PaginationKeyType = None,
    ) -> ListUserImportJobsResponse:
        raise NotImplementedError

    @handler("ListUserPoolClients")
    def list_user_pool_clients(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        max_results: QueryLimit = None,
        next_token: PaginationKey = None,
    ) -> ListUserPoolClientsResponse:
        raise NotImplementedError

    @handler("ListUserPools")
    def list_user_pools(
        self,
        context: RequestContext,
        max_results: PoolQueryLimitType,
        next_token: PaginationKeyType = None,
    ) -> ListUserPoolsResponse:
        raise NotImplementedError

    @handler("ListUsers")
    def list_users(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        attributes_to_get: SearchedAttributeNamesListType = None,
        limit: QueryLimitType = None,
        pagination_token: SearchPaginationTokenType = None,
        filter: UserFilterType = None,
    ) -> ListUsersResponse:
        raise NotImplementedError

    @handler("ListUsersInGroup")
    def list_users_in_group(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        group_name: GroupNameType,
        limit: QueryLimitType = None,
        next_token: PaginationKey = None,
    ) -> ListUsersInGroupResponse:
        raise NotImplementedError

    @handler("ResendConfirmationCode")
    def resend_confirmation_code(
        self,
        context: RequestContext,
        client_id: ClientIdType,
        username: UsernameType,
        secret_hash: SecretHashType = None,
        user_context_data: UserContextDataType = None,
        analytics_metadata: AnalyticsMetadataType = None,
        client_metadata: ClientMetadataType = None,
    ) -> ResendConfirmationCodeResponse:
        raise NotImplementedError

    @handler("RespondToAuthChallenge")
    def respond_to_auth_challenge(
        self,
        context: RequestContext,
        client_id: ClientIdType,
        challenge_name: ChallengeNameType,
        session: SessionType = None,
        challenge_responses: ChallengeResponsesType = None,
        analytics_metadata: AnalyticsMetadataType = None,
        user_context_data: UserContextDataType = None,
        client_metadata: ClientMetadataType = None,
    ) -> RespondToAuthChallengeResponse:
        raise NotImplementedError

    @handler("RevokeToken")
    def revoke_token(
        self,
        context: RequestContext,
        token: TokenModelType,
        client_id: ClientIdType,
        client_secret: ClientSecretType = None,
    ) -> RevokeTokenResponse:
        raise NotImplementedError

    @handler("SetRiskConfiguration")
    def set_risk_configuration(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        client_id: ClientIdType = None,
        compromised_credentials_risk_configuration: CompromisedCredentialsRiskConfigurationType = None,
        account_takeover_risk_configuration: AccountTakeoverRiskConfigurationType = None,
        risk_exception_configuration: RiskExceptionConfigurationType = None,
    ) -> SetRiskConfigurationResponse:
        raise NotImplementedError

    @handler("SetUICustomization")
    def set_ui_customization(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        client_id: ClientIdType = None,
        css: CSSType = None,
        image_file: ImageFileType = None,
    ) -> SetUICustomizationResponse:
        raise NotImplementedError

    @handler("SetUserMFAPreference")
    def set_user_mfa_preference(
        self,
        context: RequestContext,
        access_token: TokenModelType,
        sms_mfa_settings: SMSMfaSettingsType = None,
        software_token_mfa_settings: SoftwareTokenMfaSettingsType = None,
    ) -> SetUserMFAPreferenceResponse:
        raise NotImplementedError

    @handler("SetUserPoolMfaConfig")
    def set_user_pool_mfa_config(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        sms_mfa_configuration: SmsMfaConfigType = None,
        software_token_mfa_configuration: SoftwareTokenMfaConfigType = None,
        mfa_configuration: UserPoolMfaType = None,
    ) -> SetUserPoolMfaConfigResponse:
        raise NotImplementedError

    @handler("SetUserSettings")
    def set_user_settings(
        self, context: RequestContext, access_token: TokenModelType, mfa_options: MFAOptionListType
    ) -> SetUserSettingsResponse:
        raise NotImplementedError

    @handler("SignUp")
    def sign_up(
        self,
        context: RequestContext,
        client_id: ClientIdType,
        username: UsernameType,
        password: PasswordType,
        secret_hash: SecretHashType = None,
        user_attributes: AttributeListType = None,
        validation_data: AttributeListType = None,
        analytics_metadata: AnalyticsMetadataType = None,
        user_context_data: UserContextDataType = None,
        client_metadata: ClientMetadataType = None,
    ) -> SignUpResponse:
        raise NotImplementedError

    @handler("StartUserImportJob")
    def start_user_import_job(
        self, context: RequestContext, user_pool_id: UserPoolIdType, job_id: UserImportJobIdType
    ) -> StartUserImportJobResponse:
        raise NotImplementedError

    @handler("StopUserImportJob")
    def stop_user_import_job(
        self, context: RequestContext, user_pool_id: UserPoolIdType, job_id: UserImportJobIdType
    ) -> StopUserImportJobResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ArnType, tags: UserPoolTagsType
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ArnType, tag_keys: UserPoolTagsListType
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateAuthEventFeedback")
    def update_auth_event_feedback(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        username: UsernameType,
        event_id: EventIdType,
        feedback_token: TokenModelType,
        feedback_value: FeedbackValueType,
    ) -> UpdateAuthEventFeedbackResponse:
        raise NotImplementedError

    @handler("UpdateDeviceStatus")
    def update_device_status(
        self,
        context: RequestContext,
        access_token: TokenModelType,
        device_key: DeviceKeyType,
        device_remembered_status: DeviceRememberedStatusType = None,
    ) -> UpdateDeviceStatusResponse:
        raise NotImplementedError

    @handler("UpdateGroup")
    def update_group(
        self,
        context: RequestContext,
        group_name: GroupNameType,
        user_pool_id: UserPoolIdType,
        description: DescriptionType = None,
        role_arn: ArnType = None,
        precedence: PrecedenceType = None,
    ) -> UpdateGroupResponse:
        raise NotImplementedError

    @handler("UpdateIdentityProvider")
    def update_identity_provider(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        provider_name: ProviderNameType,
        provider_details: ProviderDetailsType = None,
        attribute_mapping: AttributeMappingType = None,
        idp_identifiers: IdpIdentifiersListType = None,
    ) -> UpdateIdentityProviderResponse:
        raise NotImplementedError

    @handler("UpdateResourceServer")
    def update_resource_server(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        identifier: ResourceServerIdentifierType,
        name: ResourceServerNameType,
        scopes: ResourceServerScopeListType = None,
    ) -> UpdateResourceServerResponse:
        raise NotImplementedError

    @handler("UpdateUserAttributes")
    def update_user_attributes(
        self,
        context: RequestContext,
        user_attributes: AttributeListType,
        access_token: TokenModelType,
        client_metadata: ClientMetadataType = None,
    ) -> UpdateUserAttributesResponse:
        raise NotImplementedError

    @handler("UpdateUserPool")
    def update_user_pool(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        policies: UserPoolPolicyType = None,
        lambda_config: LambdaConfigType = None,
        auto_verified_attributes: VerifiedAttributesListType = None,
        sms_verification_message: SmsVerificationMessageType = None,
        email_verification_message: EmailVerificationMessageType = None,
        email_verification_subject: EmailVerificationSubjectType = None,
        verification_message_template: VerificationMessageTemplateType = None,
        sms_authentication_message: SmsVerificationMessageType = None,
        mfa_configuration: UserPoolMfaType = None,
        device_configuration: DeviceConfigurationType = None,
        email_configuration: EmailConfigurationType = None,
        sms_configuration: SmsConfigurationType = None,
        user_pool_tags: UserPoolTagsType = None,
        admin_create_user_config: AdminCreateUserConfigType = None,
        user_pool_add_ons: UserPoolAddOnsType = None,
        account_recovery_setting: AccountRecoverySettingType = None,
    ) -> UpdateUserPoolResponse:
        raise NotImplementedError

    @handler("UpdateUserPoolClient")
    def update_user_pool_client(
        self,
        context: RequestContext,
        user_pool_id: UserPoolIdType,
        client_id: ClientIdType,
        client_name: ClientNameType = None,
        refresh_token_validity: RefreshTokenValidityType = None,
        access_token_validity: AccessTokenValidityType = None,
        id_token_validity: IdTokenValidityType = None,
        token_validity_units: TokenValidityUnitsType = None,
        read_attributes: ClientPermissionListType = None,
        write_attributes: ClientPermissionListType = None,
        explicit_auth_flows: ExplicitAuthFlowsListType = None,
        supported_identity_providers: SupportedIdentityProvidersListType = None,
        callback_urls: CallbackURLsListType = None,
        logout_urls: LogoutURLsListType = None,
        default_redirect_uri: RedirectUrlType = None,
        allowed_o_auth_flows: OAuthFlowsType = None,
        allowed_o_auth_scopes: ScopeListType = None,
        allowed_o_auth_flows_user_pool_client: BooleanType = None,
        analytics_configuration: AnalyticsConfigurationType = None,
        prevent_user_existence_errors: PreventUserExistenceErrorTypes = None,
        enable_token_revocation: WrappedBooleanType = None,
    ) -> UpdateUserPoolClientResponse:
        raise NotImplementedError

    @handler("UpdateUserPoolDomain")
    def update_user_pool_domain(
        self,
        context: RequestContext,
        domain: DomainType,
        user_pool_id: UserPoolIdType,
        custom_domain_config: CustomDomainConfigType,
    ) -> UpdateUserPoolDomainResponse:
        raise NotImplementedError

    @handler("VerifySoftwareToken")
    def verify_software_token(
        self,
        context: RequestContext,
        user_code: SoftwareTokenMFAUserCodeType,
        access_token: TokenModelType = None,
        session: SessionType = None,
        friendly_device_name: StringType = None,
    ) -> VerifySoftwareTokenResponse:
        raise NotImplementedError

    @handler("VerifyUserAttribute")
    def verify_user_attribute(
        self,
        context: RequestContext,
        access_token: TokenModelType,
        attribute_name: AttributeNameType,
        code: ConfirmationCodeType,
    ) -> VerifyUserAttributeResponse:
        raise NotImplementedError
