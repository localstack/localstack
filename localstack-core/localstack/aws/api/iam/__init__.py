from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ActionNameType = str
CertificationKeyType = str
CertificationValueType = str
ColumnNumber = int
ConcurrentModificationMessage = str
ContextKeyNameType = str
ContextKeyValueType = str
DeletionTaskIdType = str
EvalDecisionSourceType = str
FeatureDisabledMessage = str
FeatureEnabledMessage = str
LineNumber = int
OpenIDConnectProviderUrlType = str
OrganizationIdType = str
PolicyIdentifierType = str
ReasonType = str
RegionNameType = str
ReportStateDescriptionType = str
ResourceHandlingOptionType = str
ResourceNameType = str
SAMLMetadataDocumentType = str
SAMLProviderNameType = str
accessKeyIdType = str
accessKeySecretType = str
accountAliasType = str
accountIdType = str
allUsers = bool
arnType = str
attachmentCountType = int
authenticationCodeType = str
booleanObjectType = bool
booleanType = bool
certificateBodyType = str
certificateChainType = str
certificateIdType = str
clientIDType = str
consoleDeepLinkType = str
credentialAgeDays = int
credentialReportExpiredExceptionMessage = str
credentialReportNotPresentExceptionMessage = str
credentialReportNotReadyExceptionMessage = str
customSuffixType = str
delegationRequestDescriptionType = str
delegationRequestIdType = str
deleteConflictMessage = str
duplicateCertificateMessage = str
duplicateSSHPublicKeyMessage = str
entityAlreadyExistsMessage = str
entityNameType = str
entityTemporarilyUnmodifiableMessage = str
existingUserNameType = str
groupNameType = str
idType = str
instanceProfileNameType = str
integerType = int
invalidAuthenticationCodeMessage = str
invalidCertificateMessage = str
invalidInputMessage = str
invalidPublicKeyMessage = str
invalidUserTypeMessage = str
jobIDType = str
keyPairMismatchMessage = str
limitExceededMessage = str
localeType = str
malformedCertificateMessage = str
malformedPolicyDocumentMessage = str
markerType = str
maxItemsType = int
maxPasswordAgeType = int
minimumPasswordLengthType = int
noSuchEntityMessage = str
notesType = str
notificationChannelType = str
openIdIdpCommunicationErrorExceptionMessage = str
organizationsEntityPathType = str
organizationsPolicyIdType = str
ownerIdType = str
passwordPolicyViolationMessage = str
passwordReusePreventionType = int
passwordType = str
pathPrefixType = str
pathType = str
permissionType = str
policyDescriptionType = str
policyDocumentType = str
policyEvaluationErrorMessage = str
policyNameType = str
policyNotAttachableMessage = str
policyParameterNameType = str
policyParameterValueType = str
policyPathType = str
policyVersionIdType = str
privateKeyIdType = str
privateKeyType = str
publicKeyFingerprintType = str
publicKeyIdType = str
publicKeyMaterialType = str
redirectUrlType = str
reportGenerationLimitExceededMessage = str
requestMessageType = str
requestorNameType = str
requestorWorkflowIdType = str
responseMarkerType = str
roleDescriptionType = str
roleMaxSessionDurationType = int
roleNameType = str
serialNumberType = str
serverCertificateNameType = str
serviceCredentialAlias = str
serviceCredentialSecret = str
serviceFailureExceptionMessage = str
serviceName = str
serviceNameType = str
serviceNamespaceType = str
serviceNotSupportedMessage = str
servicePassword = str
serviceSpecificCredentialId = str
serviceUserName = str
sessionDurationType = int
stringType = str
summaryContentType = str
summaryValueType = int
tagKeyType = str
tagValueType = str
thumbprintType = str
unmodifiableEntityMessage = str
unrecognizedPublicKeyEncodingMessage = str
userNameType = str
virtualMFADeviceName = str


class AccessAdvisorUsageGranularityType(StrEnum):
    SERVICE_LEVEL = "SERVICE_LEVEL"
    ACTION_LEVEL = "ACTION_LEVEL"


class ContextKeyTypeEnum(StrEnum):
    string = "string"
    stringList = "stringList"
    numeric = "numeric"
    numericList = "numericList"
    boolean = "boolean"
    booleanList = "booleanList"
    ip = "ip"
    ipList = "ipList"
    binary = "binary"
    binaryList = "binaryList"
    date = "date"
    dateList = "dateList"


class DeletionTaskStatusType(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    NOT_STARTED = "NOT_STARTED"


class EntityType(StrEnum):
    User = "User"
    Role = "Role"
    Group = "Group"
    LocalManagedPolicy = "LocalManagedPolicy"
    AWSManagedPolicy = "AWSManagedPolicy"


class FeatureType(StrEnum):
    RootCredentialsManagement = "RootCredentialsManagement"
    RootSessions = "RootSessions"


class PermissionsBoundaryAttachmentType(StrEnum):
    PermissionsBoundaryPolicy = "PermissionsBoundaryPolicy"


class PolicyEvaluationDecisionType(StrEnum):
    allowed = "allowed"
    explicitDeny = "explicitDeny"
    implicitDeny = "implicitDeny"


class PolicyParameterTypeEnum(StrEnum):
    string = "string"
    stringList = "stringList"


class PolicySourceType(StrEnum):
    user = "user"
    group = "group"
    role = "role"
    aws_managed = "aws-managed"
    user_managed = "user-managed"
    resource = "resource"
    none = "none"


class PolicyUsageType(StrEnum):
    PermissionsPolicy = "PermissionsPolicy"
    PermissionsBoundary = "PermissionsBoundary"


class ReportFormatType(StrEnum):
    text_csv = "text/csv"


class ReportStateType(StrEnum):
    STARTED = "STARTED"
    INPROGRESS = "INPROGRESS"
    COMPLETE = "COMPLETE"


class assertionEncryptionModeType(StrEnum):
    Required = "Required"
    Allowed = "Allowed"


class assignmentStatusType(StrEnum):
    Assigned = "Assigned"
    Unassigned = "Unassigned"
    Any = "Any"


class encodingType(StrEnum):
    SSH = "SSH"
    PEM = "PEM"


class globalEndpointTokenVersion(StrEnum):
    v1Token = "v1Token"
    v2Token = "v2Token"


class jobStatusType(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class permissionCheckResultType(StrEnum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    UNSURE = "UNSURE"


class permissionCheckStatusType(StrEnum):
    COMPLETE = "COMPLETE"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"


class policyOwnerEntityType(StrEnum):
    USER = "USER"
    ROLE = "ROLE"
    GROUP = "GROUP"


class policyScopeType(StrEnum):
    All = "All"
    AWS = "AWS"
    Local = "Local"


class policyType(StrEnum):
    INLINE = "INLINE"
    MANAGED = "MANAGED"


class sortKeyType(StrEnum):
    SERVICE_NAMESPACE_ASCENDING = "SERVICE_NAMESPACE_ASCENDING"
    SERVICE_NAMESPACE_DESCENDING = "SERVICE_NAMESPACE_DESCENDING"
    LAST_AUTHENTICATED_TIME_ASCENDING = "LAST_AUTHENTICATED_TIME_ASCENDING"
    LAST_AUTHENTICATED_TIME_DESCENDING = "LAST_AUTHENTICATED_TIME_DESCENDING"


class stateType(StrEnum):
    UNASSIGNED = "UNASSIGNED"
    ASSIGNED = "ASSIGNED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    FINALIZED = "FINALIZED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class statusType(StrEnum):
    Active = "Active"
    Inactive = "Inactive"
    Expired = "Expired"


class summaryKeyType(StrEnum):
    Users = "Users"
    UsersQuota = "UsersQuota"
    Groups = "Groups"
    GroupsQuota = "GroupsQuota"
    ServerCertificates = "ServerCertificates"
    ServerCertificatesQuota = "ServerCertificatesQuota"
    UserPolicySizeQuota = "UserPolicySizeQuota"
    GroupPolicySizeQuota = "GroupPolicySizeQuota"
    GroupsPerUserQuota = "GroupsPerUserQuota"
    SigningCertificatesPerUserQuota = "SigningCertificatesPerUserQuota"
    AccessKeysPerUserQuota = "AccessKeysPerUserQuota"
    MFADevices = "MFADevices"
    MFADevicesInUse = "MFADevicesInUse"
    AccountMFAEnabled = "AccountMFAEnabled"
    AccountAccessKeysPresent = "AccountAccessKeysPresent"
    AccountPasswordPresent = "AccountPasswordPresent"
    AccountSigningCertificatesPresent = "AccountSigningCertificatesPresent"
    AttachedPoliciesPerGroupQuota = "AttachedPoliciesPerGroupQuota"
    AttachedPoliciesPerRoleQuota = "AttachedPoliciesPerRoleQuota"
    AttachedPoliciesPerUserQuota = "AttachedPoliciesPerUserQuota"
    Policies = "Policies"
    PoliciesQuota = "PoliciesQuota"
    PolicySizeQuota = "PolicySizeQuota"
    PolicyVersionsInUse = "PolicyVersionsInUse"
    PolicyVersionsInUseQuota = "PolicyVersionsInUseQuota"
    VersionsPerPolicyQuota = "VersionsPerPolicyQuota"
    GlobalEndpointTokenVersion = "GlobalEndpointTokenVersion"
    AssumeRolePolicySizeQuota = "AssumeRolePolicySizeQuota"
    InstanceProfiles = "InstanceProfiles"
    InstanceProfilesQuota = "InstanceProfilesQuota"
    Providers = "Providers"
    RolePolicySizeQuota = "RolePolicySizeQuota"
    Roles = "Roles"
    RolesQuota = "RolesQuota"


class summaryStateType(StrEnum):
    AVAILABLE = "AVAILABLE"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    FAILED = "FAILED"


class AccountNotManagementOrDelegatedAdministratorException(ServiceException):
    code: str = "AccountNotManagementOrDelegatedAdministratorException"
    sender_fault: bool = False
    status_code: int = 400


class CallerIsNotManagementAccountException(ServiceException):
    code: str = "CallerIsNotManagementAccountException"
    sender_fault: bool = False
    status_code: int = 400


class ConcurrentModificationException(ServiceException):
    code: str = "ConcurrentModification"
    sender_fault: bool = True
    status_code: int = 409


class CredentialReportExpiredException(ServiceException):
    code: str = "ReportExpired"
    sender_fault: bool = True
    status_code: int = 410


class CredentialReportNotPresentException(ServiceException):
    code: str = "ReportNotPresent"
    sender_fault: bool = True
    status_code: int = 410


class CredentialReportNotReadyException(ServiceException):
    code: str = "ReportInProgress"
    sender_fault: bool = True
    status_code: int = 404


class DeleteConflictException(ServiceException):
    code: str = "DeleteConflict"
    sender_fault: bool = True
    status_code: int = 409


class DuplicateCertificateException(ServiceException):
    code: str = "DuplicateCertificate"
    sender_fault: bool = True
    status_code: int = 409


class DuplicateSSHPublicKeyException(ServiceException):
    code: str = "DuplicateSSHPublicKey"
    sender_fault: bool = True
    status_code: int = 400


class EntityAlreadyExistsException(ServiceException):
    code: str = "EntityAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409


class EntityTemporarilyUnmodifiableException(ServiceException):
    code: str = "EntityTemporarilyUnmodifiable"
    sender_fault: bool = True
    status_code: int = 409


class FeatureDisabledException(ServiceException):
    code: str = "FeatureDisabled"
    sender_fault: bool = True
    status_code: int = 404


class FeatureEnabledException(ServiceException):
    code: str = "FeatureEnabled"
    sender_fault: bool = True
    status_code: int = 409


class InvalidAuthenticationCodeException(ServiceException):
    code: str = "InvalidAuthenticationCode"
    sender_fault: bool = True
    status_code: int = 403


class InvalidCertificateException(ServiceException):
    code: str = "InvalidCertificate"
    sender_fault: bool = True
    status_code: int = 400


class InvalidInputException(ServiceException):
    code: str = "InvalidInput"
    sender_fault: bool = True
    status_code: int = 400


class InvalidPublicKeyException(ServiceException):
    code: str = "InvalidPublicKey"
    sender_fault: bool = True
    status_code: int = 400


class InvalidUserTypeException(ServiceException):
    code: str = "InvalidUserType"
    sender_fault: bool = True
    status_code: int = 400


class KeyPairMismatchException(ServiceException):
    code: str = "KeyPairMismatch"
    sender_fault: bool = True
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceeded"
    sender_fault: bool = True
    status_code: int = 409


class MalformedCertificateException(ServiceException):
    code: str = "MalformedCertificate"
    sender_fault: bool = True
    status_code: int = 400


class MalformedPolicyDocumentException(ServiceException):
    code: str = "MalformedPolicyDocument"
    sender_fault: bool = True
    status_code: int = 400


class NoSuchEntityException(ServiceException):
    code: str = "NoSuchEntity"
    sender_fault: bool = True
    status_code: int = 404


class OpenIdIdpCommunicationErrorException(ServiceException):
    code: str = "OpenIdIdpCommunicationError"
    sender_fault: bool = True
    status_code: int = 400


class OrganizationNotFoundException(ServiceException):
    code: str = "OrganizationNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class OrganizationNotInAllFeaturesModeException(ServiceException):
    code: str = "OrganizationNotInAllFeaturesModeException"
    sender_fault: bool = False
    status_code: int = 400


class PasswordPolicyViolationException(ServiceException):
    code: str = "PasswordPolicyViolation"
    sender_fault: bool = True
    status_code: int = 400


class PolicyEvaluationException(ServiceException):
    code: str = "PolicyEvaluation"
    sender_fault: bool = False
    status_code: int = 500


class PolicyNotAttachableException(ServiceException):
    code: str = "PolicyNotAttachable"
    sender_fault: bool = True
    status_code: int = 400


class ReportGenerationLimitExceededException(ServiceException):
    code: str = "ReportGenerationLimitExceeded"
    sender_fault: bool = True
    status_code: int = 409


class ServiceAccessNotEnabledException(ServiceException):
    code: str = "ServiceAccessNotEnabledException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceFailureException(ServiceException):
    code: str = "ServiceFailure"
    sender_fault: bool = False
    status_code: int = 500


class ServiceNotSupportedException(ServiceException):
    code: str = "NotSupportedService"
    sender_fault: bool = True
    status_code: int = 404


class UnmodifiableEntityException(ServiceException):
    code: str = "UnmodifiableEntity"
    sender_fault: bool = True
    status_code: int = 400


class UnrecognizedPublicKeyEncodingException(ServiceException):
    code: str = "UnrecognizedPublicKeyEncoding"
    sender_fault: bool = True
    status_code: int = 400


class AcceptDelegationRequestRequest(ServiceRequest):
    DelegationRequestId: delegationRequestIdType


dateType = datetime


class AccessDetail(TypedDict, total=False):
    ServiceName: serviceNameType
    ServiceNamespace: serviceNamespaceType
    Region: stringType | None
    EntityPath: organizationsEntityPathType | None
    LastAuthenticatedTime: dateType | None
    TotalAuthenticatedEntities: integerType | None


AccessDetails = list[AccessDetail]


class AccessKey(TypedDict, total=False):
    UserName: userNameType
    AccessKeyId: accessKeyIdType
    Status: statusType
    SecretAccessKey: accessKeySecretType
    CreateDate: dateType | None


class AccessKeyLastUsed(TypedDict, total=False):
    LastUsedDate: dateType | None
    ServiceName: stringType
    Region: stringType


class AccessKeyMetadata(TypedDict, total=False):
    UserName: userNameType | None
    AccessKeyId: accessKeyIdType | None
    Status: statusType | None
    CreateDate: dateType | None


ActionNameListType = list[ActionNameType]


class AddClientIDToOpenIDConnectProviderRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    ClientID: clientIDType


class AddRoleToInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    RoleName: roleNameType


class AddUserToGroupRequest(ServiceRequest):
    GroupName: groupNameType
    UserName: existingUserNameType


ArnListType = list[arnType]


class AssociateDelegationRequestRequest(ServiceRequest):
    DelegationRequestId: delegationRequestIdType


class AttachGroupPolicyRequest(ServiceRequest):
    GroupName: groupNameType
    PolicyArn: arnType


class AttachRolePolicyRequest(ServiceRequest):
    RoleName: roleNameType
    PolicyArn: arnType


class AttachUserPolicyRequest(ServiceRequest):
    UserName: userNameType
    PolicyArn: arnType


class AttachedPermissionsBoundary(TypedDict, total=False):
    PermissionsBoundaryType: PermissionsBoundaryAttachmentType | None
    PermissionsBoundaryArn: arnType | None


class AttachedPolicy(TypedDict, total=False):
    PolicyName: policyNameType | None
    PolicyArn: arnType | None


BootstrapDatum = bytes
CertificationMapType = dict[CertificationKeyType, CertificationValueType]


class ChangePasswordRequest(ServiceRequest):
    OldPassword: passwordType
    NewPassword: passwordType


ContextKeyValueListType = list[ContextKeyValueType]


class ContextEntry(TypedDict, total=False):
    ContextKeyName: ContextKeyNameType | None
    ContextKeyValues: ContextKeyValueListType | None
    ContextKeyType: ContextKeyTypeEnum | None


ContextEntryListType = list[ContextEntry]
ContextKeyNamesResultListType = list[ContextKeyNameType]


class CreateAccessKeyRequest(ServiceRequest):
    UserName: existingUserNameType | None


class CreateAccessKeyResponse(TypedDict, total=False):
    AccessKey: AccessKey


class CreateAccountAliasRequest(ServiceRequest):
    AccountAlias: accountAliasType


policyParameterValuesListType = list[policyParameterValueType]


class PolicyParameter(TypedDict, total=False):
    Name: policyParameterNameType | None
    Values: policyParameterValuesListType | None
    Type: PolicyParameterTypeEnum | None


policyParameterListType = list[PolicyParameter]


class DelegationPermission(TypedDict, total=False):
    PolicyTemplateArn: arnType | None
    Parameters: policyParameterListType | None


class CreateDelegationRequestRequest(ServiceRequest):
    OwnerAccountId: accountIdType | None
    Description: delegationRequestDescriptionType
    Permissions: DelegationPermission
    RequestMessage: requestMessageType | None
    RequestorWorkflowId: requestorWorkflowIdType
    RedirectUrl: redirectUrlType | None
    NotificationChannel: notificationChannelType
    SessionDuration: sessionDurationType
    OnlySendByOwner: booleanType | None


class CreateDelegationRequestResponse(TypedDict, total=False):
    ConsoleDeepLink: consoleDeepLinkType | None
    DelegationRequestId: delegationRequestIdType | None


class CreateGroupRequest(ServiceRequest):
    Path: pathType | None
    GroupName: groupNameType


class Group(TypedDict, total=False):
    Path: pathType
    GroupName: groupNameType
    GroupId: idType
    Arn: arnType
    CreateDate: dateType


class CreateGroupResponse(TypedDict, total=False):
    Group: Group


class Tag(TypedDict, total=False):
    Key: tagKeyType
    Value: tagValueType


tagListType = list[Tag]


class CreateInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    Path: pathType | None
    Tags: tagListType | None


class RoleLastUsed(TypedDict, total=False):
    LastUsedDate: dateType | None
    Region: stringType | None


class Role(TypedDict, total=False):
    Path: pathType
    RoleName: roleNameType
    RoleId: idType
    Arn: arnType
    CreateDate: dateType
    AssumeRolePolicyDocument: policyDocumentType | None
    Description: roleDescriptionType | None
    MaxSessionDuration: roleMaxSessionDurationType | None
    PermissionsBoundary: AttachedPermissionsBoundary | None
    Tags: tagListType | None
    RoleLastUsed: RoleLastUsed | None


roleListType = list[Role]


class InstanceProfile(TypedDict, total=False):
    Path: pathType
    InstanceProfileName: instanceProfileNameType
    InstanceProfileId: idType
    Arn: arnType
    CreateDate: dateType
    Roles: roleListType
    Tags: tagListType | None


class CreateInstanceProfileResponse(TypedDict, total=False):
    InstanceProfile: InstanceProfile


class CreateLoginProfileRequest(ServiceRequest):
    UserName: userNameType | None
    Password: passwordType | None
    PasswordResetRequired: booleanType | None


class LoginProfile(TypedDict, total=False):
    UserName: userNameType
    CreateDate: dateType
    PasswordResetRequired: booleanType | None


class CreateLoginProfileResponse(TypedDict, total=False):
    LoginProfile: LoginProfile


thumbprintListType = list[thumbprintType]
clientIDListType = list[clientIDType]


class CreateOpenIDConnectProviderRequest(ServiceRequest):
    Url: OpenIDConnectProviderUrlType
    ClientIDList: clientIDListType | None
    ThumbprintList: thumbprintListType | None
    Tags: tagListType | None


class CreateOpenIDConnectProviderResponse(TypedDict, total=False):
    OpenIDConnectProviderArn: arnType | None
    Tags: tagListType | None


class CreatePolicyRequest(ServiceRequest):
    PolicyName: policyNameType
    Path: policyPathType | None
    PolicyDocument: policyDocumentType
    Description: policyDescriptionType | None
    Tags: tagListType | None


class Policy(TypedDict, total=False):
    PolicyName: policyNameType | None
    PolicyId: idType | None
    Arn: arnType | None
    Path: policyPathType | None
    DefaultVersionId: policyVersionIdType | None
    AttachmentCount: attachmentCountType | None
    PermissionsBoundaryUsageCount: attachmentCountType | None
    IsAttachable: booleanType | None
    Description: policyDescriptionType | None
    CreateDate: dateType | None
    UpdateDate: dateType | None
    Tags: tagListType | None


class CreatePolicyResponse(TypedDict, total=False):
    Policy: Policy | None


class CreatePolicyVersionRequest(ServiceRequest):
    PolicyArn: arnType
    PolicyDocument: policyDocumentType
    SetAsDefault: booleanType | None


class PolicyVersion(TypedDict, total=False):
    Document: policyDocumentType | None
    VersionId: policyVersionIdType | None
    IsDefaultVersion: booleanType | None
    CreateDate: dateType | None


class CreatePolicyVersionResponse(TypedDict, total=False):
    PolicyVersion: PolicyVersion | None


class CreateRoleRequest(ServiceRequest):
    Path: pathType | None
    RoleName: roleNameType
    AssumeRolePolicyDocument: policyDocumentType
    Description: roleDescriptionType | None
    MaxSessionDuration: roleMaxSessionDurationType | None
    PermissionsBoundary: arnType | None
    Tags: tagListType | None


class CreateRoleResponse(TypedDict, total=False):
    Role: Role


class CreateSAMLProviderRequest(ServiceRequest):
    SAMLMetadataDocument: SAMLMetadataDocumentType
    Name: SAMLProviderNameType
    Tags: tagListType | None
    AssertionEncryptionMode: assertionEncryptionModeType | None
    AddPrivateKey: privateKeyType | None


class CreateSAMLProviderResponse(TypedDict, total=False):
    SAMLProviderArn: arnType | None
    Tags: tagListType | None


class CreateServiceLinkedRoleRequest(ServiceRequest):
    AWSServiceName: groupNameType
    Description: roleDescriptionType | None
    CustomSuffix: customSuffixType | None


class CreateServiceLinkedRoleResponse(TypedDict, total=False):
    Role: Role | None


class CreateServiceSpecificCredentialRequest(ServiceRequest):
    UserName: userNameType
    ServiceName: serviceName
    CredentialAgeDays: credentialAgeDays | None


class ServiceSpecificCredential(TypedDict, total=False):
    CreateDate: dateType
    ExpirationDate: dateType | None
    ServiceName: serviceName
    ServiceUserName: serviceUserName | None
    ServicePassword: servicePassword | None
    ServiceCredentialAlias: serviceCredentialAlias | None
    ServiceCredentialSecret: serviceCredentialSecret | None
    ServiceSpecificCredentialId: serviceSpecificCredentialId
    UserName: userNameType
    Status: statusType


class CreateServiceSpecificCredentialResponse(TypedDict, total=False):
    ServiceSpecificCredential: ServiceSpecificCredential | None


class CreateUserRequest(ServiceRequest):
    Path: pathType | None
    UserName: userNameType
    PermissionsBoundary: arnType | None
    Tags: tagListType | None


class User(TypedDict, total=False):
    Path: pathType
    UserName: userNameType
    UserId: idType
    Arn: arnType
    CreateDate: dateType
    PasswordLastUsed: dateType | None
    PermissionsBoundary: AttachedPermissionsBoundary | None
    Tags: tagListType | None


class CreateUserResponse(TypedDict, total=False):
    User: User | None


class CreateVirtualMFADeviceRequest(ServiceRequest):
    Path: pathType | None
    VirtualMFADeviceName: virtualMFADeviceName
    Tags: tagListType | None


class VirtualMFADevice(TypedDict, total=False):
    SerialNumber: serialNumberType
    Base32StringSeed: BootstrapDatum | None
    QRCodePNG: BootstrapDatum | None
    User: User | None
    EnableDate: dateType | None
    Tags: tagListType | None


class CreateVirtualMFADeviceResponse(TypedDict, total=False):
    VirtualMFADevice: VirtualMFADevice


class DeactivateMFADeviceRequest(ServiceRequest):
    UserName: existingUserNameType | None
    SerialNumber: serialNumberType


rolePermissionRestrictionArnListType = list[arnType]


class DelegationRequest(TypedDict, total=False):
    DelegationRequestId: delegationRequestIdType | None
    OwnerAccountId: accountIdType | None
    Description: delegationRequestDescriptionType | None
    RequestMessage: requestMessageType | None
    Permissions: DelegationPermission | None
    PermissionPolicy: permissionType | None
    RolePermissionRestrictionArns: rolePermissionRestrictionArnListType | None
    OwnerId: ownerIdType | None
    ApproverId: arnType | None
    State: stateType | None
    ExpirationTime: dateType | None
    RequestorId: accountIdType | None
    RequestorName: requestorNameType | None
    CreateDate: dateType | None
    SessionDuration: sessionDurationType | None
    RedirectUrl: redirectUrlType | None
    Notes: notesType | None
    RejectionReason: notesType | None
    OnlySendByOwner: booleanType | None
    UpdatedTime: dateType | None


class DeleteAccessKeyRequest(ServiceRequest):
    UserName: existingUserNameType | None
    AccessKeyId: accessKeyIdType


class DeleteAccountAliasRequest(ServiceRequest):
    AccountAlias: accountAliasType


class DeleteGroupPolicyRequest(ServiceRequest):
    GroupName: groupNameType
    PolicyName: policyNameType


class DeleteGroupRequest(ServiceRequest):
    GroupName: groupNameType


class DeleteInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType


class DeleteLoginProfileRequest(ServiceRequest):
    UserName: userNameType | None


class DeleteOpenIDConnectProviderRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType


class DeletePolicyRequest(ServiceRequest):
    PolicyArn: arnType


class DeletePolicyVersionRequest(ServiceRequest):
    PolicyArn: arnType
    VersionId: policyVersionIdType


class DeleteRolePermissionsBoundaryRequest(ServiceRequest):
    RoleName: roleNameType


class DeleteRolePolicyRequest(ServiceRequest):
    RoleName: roleNameType
    PolicyName: policyNameType


class DeleteRoleRequest(ServiceRequest):
    RoleName: roleNameType


class DeleteSAMLProviderRequest(ServiceRequest):
    SAMLProviderArn: arnType


class DeleteSSHPublicKeyRequest(ServiceRequest):
    UserName: userNameType
    SSHPublicKeyId: publicKeyIdType


class DeleteServerCertificateRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType


class DeleteServiceLinkedRoleRequest(ServiceRequest):
    RoleName: roleNameType


class DeleteServiceLinkedRoleResponse(TypedDict, total=False):
    DeletionTaskId: DeletionTaskIdType


class DeleteServiceSpecificCredentialRequest(ServiceRequest):
    UserName: userNameType | None
    ServiceSpecificCredentialId: serviceSpecificCredentialId


class DeleteSigningCertificateRequest(ServiceRequest):
    UserName: existingUserNameType | None
    CertificateId: certificateIdType


class DeleteUserPermissionsBoundaryRequest(ServiceRequest):
    UserName: userNameType


class DeleteUserPolicyRequest(ServiceRequest):
    UserName: existingUserNameType
    PolicyName: policyNameType


class DeleteUserRequest(ServiceRequest):
    UserName: existingUserNameType


class DeleteVirtualMFADeviceRequest(ServiceRequest):
    SerialNumber: serialNumberType


class RoleUsageType(TypedDict, total=False):
    Region: RegionNameType | None
    Resources: ArnListType | None


RoleUsageListType = list[RoleUsageType]


class DeletionTaskFailureReasonType(TypedDict, total=False):
    Reason: ReasonType | None
    RoleUsageList: RoleUsageListType | None


class DetachGroupPolicyRequest(ServiceRequest):
    GroupName: groupNameType
    PolicyArn: arnType


class DetachRolePolicyRequest(ServiceRequest):
    RoleName: roleNameType
    PolicyArn: arnType


class DetachUserPolicyRequest(ServiceRequest):
    UserName: userNameType
    PolicyArn: arnType


class DisableOrganizationsRootCredentialsManagementRequest(ServiceRequest):
    pass


FeaturesListType = list[FeatureType]


class DisableOrganizationsRootCredentialsManagementResponse(TypedDict, total=False):
    OrganizationId: OrganizationIdType | None
    EnabledFeatures: FeaturesListType | None


class DisableOrganizationsRootSessionsRequest(ServiceRequest):
    pass


class DisableOrganizationsRootSessionsResponse(TypedDict, total=False):
    OrganizationId: OrganizationIdType | None
    EnabledFeatures: FeaturesListType | None


class EnableMFADeviceRequest(ServiceRequest):
    UserName: existingUserNameType
    SerialNumber: serialNumberType
    AuthenticationCode1: authenticationCodeType
    AuthenticationCode2: authenticationCodeType


class EnableOrganizationsRootCredentialsManagementRequest(ServiceRequest):
    pass


class EnableOrganizationsRootCredentialsManagementResponse(TypedDict, total=False):
    OrganizationId: OrganizationIdType | None
    EnabledFeatures: FeaturesListType | None


class EnableOrganizationsRootSessionsRequest(ServiceRequest):
    pass


class EnableOrganizationsRootSessionsResponse(TypedDict, total=False):
    OrganizationId: OrganizationIdType | None
    EnabledFeatures: FeaturesListType | None


class EnableOutboundWebIdentityFederationResponse(TypedDict, total=False):
    IssuerIdentifier: stringType | None


class EntityInfo(TypedDict, total=False):
    Arn: arnType
    Name: userNameType
    Type: policyOwnerEntityType
    Id: idType
    Path: pathType | None


class EntityDetails(TypedDict, total=False):
    EntityInfo: EntityInfo
    LastAuthenticated: dateType | None


class ErrorDetails(TypedDict, total=False):
    Message: stringType
    Code: stringType


EvalDecisionDetailsType = dict[EvalDecisionSourceType, PolicyEvaluationDecisionType]


class PermissionsBoundaryDecisionDetail(TypedDict, total=False):
    AllowedByPermissionsBoundary: booleanType | None


class Position(TypedDict, total=False):
    Line: LineNumber | None
    Column: ColumnNumber | None


class Statement(TypedDict, total=False):
    SourcePolicyId: PolicyIdentifierType | None
    SourcePolicyType: PolicySourceType | None
    StartPosition: Position | None
    EndPosition: Position | None


StatementListType = list[Statement]


class ResourceSpecificResult(TypedDict, total=False):
    EvalResourceName: ResourceNameType
    EvalResourceDecision: PolicyEvaluationDecisionType
    MatchedStatements: StatementListType | None
    MissingContextValues: ContextKeyNamesResultListType | None
    EvalDecisionDetails: EvalDecisionDetailsType | None
    PermissionsBoundaryDecisionDetail: PermissionsBoundaryDecisionDetail | None


ResourceSpecificResultListType = list[ResourceSpecificResult]


class OrganizationsDecisionDetail(TypedDict, total=False):
    AllowedByOrganizations: booleanType | None


class EvaluationResult(TypedDict, total=False):
    EvalActionName: ActionNameType
    EvalResourceName: ResourceNameType | None
    EvalDecision: PolicyEvaluationDecisionType
    MatchedStatements: StatementListType | None
    MissingContextValues: ContextKeyNamesResultListType | None
    OrganizationsDecisionDetail: OrganizationsDecisionDetail | None
    PermissionsBoundaryDecisionDetail: PermissionsBoundaryDecisionDetail | None
    EvalDecisionDetails: EvalDecisionDetailsType | None
    ResourceSpecificResults: ResourceSpecificResultListType | None


EvaluationResultsListType = list[EvaluationResult]


class GenerateCredentialReportResponse(TypedDict, total=False):
    State: ReportStateType | None
    Description: ReportStateDescriptionType | None


class GenerateOrganizationsAccessReportRequest(ServiceRequest):
    EntityPath: organizationsEntityPathType
    OrganizationsPolicyId: organizationsPolicyIdType | None


class GenerateOrganizationsAccessReportResponse(TypedDict, total=False):
    JobId: jobIDType | None


class GenerateServiceLastAccessedDetailsRequest(ServiceRequest):
    Arn: arnType
    Granularity: AccessAdvisorUsageGranularityType | None


class GenerateServiceLastAccessedDetailsResponse(TypedDict, total=False):
    JobId: jobIDType | None


class GetAccessKeyLastUsedRequest(ServiceRequest):
    AccessKeyId: accessKeyIdType


class GetAccessKeyLastUsedResponse(TypedDict, total=False):
    UserName: existingUserNameType | None
    AccessKeyLastUsed: AccessKeyLastUsed | None


entityListType = list[EntityType]


class GetAccountAuthorizationDetailsRequest(ServiceRequest):
    Filter: entityListType | None
    MaxItems: maxItemsType | None
    Marker: markerType | None


policyDocumentVersionListType = list[PolicyVersion]


class ManagedPolicyDetail(TypedDict, total=False):
    PolicyName: policyNameType | None
    PolicyId: idType | None
    Arn: arnType | None
    Path: policyPathType | None
    DefaultVersionId: policyVersionIdType | None
    AttachmentCount: attachmentCountType | None
    PermissionsBoundaryUsageCount: attachmentCountType | None
    IsAttachable: booleanType | None
    Description: policyDescriptionType | None
    CreateDate: dateType | None
    UpdateDate: dateType | None
    PolicyVersionList: policyDocumentVersionListType | None


ManagedPolicyDetailListType = list[ManagedPolicyDetail]
attachedPoliciesListType = list[AttachedPolicy]


class PolicyDetail(TypedDict, total=False):
    PolicyName: policyNameType | None
    PolicyDocument: policyDocumentType | None


policyDetailListType = list[PolicyDetail]
instanceProfileListType = list[InstanceProfile]


class RoleDetail(TypedDict, total=False):
    Path: pathType | None
    RoleName: roleNameType | None
    RoleId: idType | None
    Arn: arnType | None
    CreateDate: dateType | None
    AssumeRolePolicyDocument: policyDocumentType | None
    InstanceProfileList: instanceProfileListType | None
    RolePolicyList: policyDetailListType | None
    AttachedManagedPolicies: attachedPoliciesListType | None
    PermissionsBoundary: AttachedPermissionsBoundary | None
    Tags: tagListType | None
    RoleLastUsed: RoleLastUsed | None


roleDetailListType = list[RoleDetail]


class GroupDetail(TypedDict, total=False):
    Path: pathType | None
    GroupName: groupNameType | None
    GroupId: idType | None
    Arn: arnType | None
    CreateDate: dateType | None
    GroupPolicyList: policyDetailListType | None
    AttachedManagedPolicies: attachedPoliciesListType | None


groupDetailListType = list[GroupDetail]
groupNameListType = list[groupNameType]


class UserDetail(TypedDict, total=False):
    Path: pathType | None
    UserName: userNameType | None
    UserId: idType | None
    Arn: arnType | None
    CreateDate: dateType | None
    UserPolicyList: policyDetailListType | None
    GroupList: groupNameListType | None
    AttachedManagedPolicies: attachedPoliciesListType | None
    PermissionsBoundary: AttachedPermissionsBoundary | None
    Tags: tagListType | None


userDetailListType = list[UserDetail]


class GetAccountAuthorizationDetailsResponse(TypedDict, total=False):
    UserDetailList: userDetailListType | None
    GroupDetailList: groupDetailListType | None
    RoleDetailList: roleDetailListType | None
    Policies: ManagedPolicyDetailListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class PasswordPolicy(TypedDict, total=False):
    MinimumPasswordLength: minimumPasswordLengthType | None
    RequireSymbols: booleanType | None
    RequireNumbers: booleanType | None
    RequireUppercaseCharacters: booleanType | None
    RequireLowercaseCharacters: booleanType | None
    AllowUsersToChangePassword: booleanType | None
    ExpirePasswords: booleanType | None
    MaxPasswordAge: maxPasswordAgeType | None
    PasswordReusePrevention: passwordReusePreventionType | None
    HardExpiry: booleanObjectType | None


class GetAccountPasswordPolicyResponse(TypedDict, total=False):
    PasswordPolicy: PasswordPolicy


summaryMapType = dict[summaryKeyType, summaryValueType]


class GetAccountSummaryResponse(TypedDict, total=False):
    SummaryMap: summaryMapType | None


SimulationPolicyListType = list[policyDocumentType]


class GetContextKeysForCustomPolicyRequest(ServiceRequest):
    PolicyInputList: SimulationPolicyListType


class GetContextKeysForPolicyResponse(TypedDict, total=False):
    ContextKeyNames: ContextKeyNamesResultListType | None


class GetContextKeysForPrincipalPolicyRequest(ServiceRequest):
    PolicySourceArn: arnType
    PolicyInputList: SimulationPolicyListType | None


ReportContentType = bytes


class GetCredentialReportResponse(TypedDict, total=False):
    Content: ReportContentType | None
    ReportFormat: ReportFormatType | None
    GeneratedTime: dateType | None


class GetDelegationRequestRequest(ServiceRequest):
    DelegationRequestId: delegationRequestIdType
    DelegationPermissionCheck: booleanType | None


class GetDelegationRequestResponse(TypedDict, total=False):
    DelegationRequest: DelegationRequest | None
    PermissionCheckStatus: permissionCheckStatusType | None
    PermissionCheckResult: permissionCheckResultType | None


class GetGroupPolicyRequest(ServiceRequest):
    GroupName: groupNameType
    PolicyName: policyNameType


class GetGroupPolicyResponse(TypedDict, total=False):
    GroupName: groupNameType
    PolicyName: policyNameType
    PolicyDocument: policyDocumentType


class GetGroupRequest(ServiceRequest):
    GroupName: groupNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


userListType = list[User]


class GetGroupResponse(TypedDict, total=False):
    Group: Group
    Users: userListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class GetHumanReadableSummaryRequest(ServiceRequest):
    EntityArn: arnType
    Locale: localeType | None


class GetHumanReadableSummaryResponse(TypedDict, total=False):
    SummaryContent: summaryContentType | None
    Locale: localeType | None
    SummaryState: summaryStateType | None


class GetInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType


class GetInstanceProfileResponse(TypedDict, total=False):
    InstanceProfile: InstanceProfile


class GetLoginProfileRequest(ServiceRequest):
    UserName: userNameType | None


class GetLoginProfileResponse(TypedDict, total=False):
    LoginProfile: LoginProfile


class GetMFADeviceRequest(ServiceRequest):
    SerialNumber: serialNumberType
    UserName: userNameType | None


class GetMFADeviceResponse(TypedDict, total=False):
    UserName: userNameType | None
    SerialNumber: serialNumberType
    EnableDate: dateType | None
    Certifications: CertificationMapType | None


class GetOpenIDConnectProviderRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType


class GetOpenIDConnectProviderResponse(TypedDict, total=False):
    Url: OpenIDConnectProviderUrlType | None
    ClientIDList: clientIDListType | None
    ThumbprintList: thumbprintListType | None
    CreateDate: dateType | None
    Tags: tagListType | None


class GetOrganizationsAccessReportRequest(ServiceRequest):
    JobId: jobIDType
    MaxItems: maxItemsType | None
    Marker: markerType | None
    SortKey: sortKeyType | None


class GetOrganizationsAccessReportResponse(TypedDict, total=False):
    JobStatus: jobStatusType
    JobCreationDate: dateType
    JobCompletionDate: dateType | None
    NumberOfServicesAccessible: integerType | None
    NumberOfServicesNotAccessed: integerType | None
    AccessDetails: AccessDetails | None
    IsTruncated: booleanType | None
    Marker: markerType | None
    ErrorDetails: ErrorDetails | None


class GetOutboundWebIdentityFederationInfoResponse(TypedDict, total=False):
    IssuerIdentifier: stringType | None
    JwtVendingEnabled: booleanType | None


class GetPolicyRequest(ServiceRequest):
    PolicyArn: arnType


class GetPolicyResponse(TypedDict, total=False):
    Policy: Policy | None


class GetPolicyVersionRequest(ServiceRequest):
    PolicyArn: arnType
    VersionId: policyVersionIdType


class GetPolicyVersionResponse(TypedDict, total=False):
    PolicyVersion: PolicyVersion | None


class GetRolePolicyRequest(ServiceRequest):
    RoleName: roleNameType
    PolicyName: policyNameType


class GetRolePolicyResponse(TypedDict, total=False):
    RoleName: roleNameType
    PolicyName: policyNameType
    PolicyDocument: policyDocumentType


class GetRoleRequest(ServiceRequest):
    RoleName: roleNameType


class GetRoleResponse(TypedDict, total=False):
    Role: Role


class GetSAMLProviderRequest(ServiceRequest):
    SAMLProviderArn: arnType


class SAMLPrivateKey(TypedDict, total=False):
    KeyId: privateKeyIdType | None
    Timestamp: dateType | None


privateKeyList = list[SAMLPrivateKey]


class GetSAMLProviderResponse(TypedDict, total=False):
    SAMLProviderUUID: privateKeyIdType | None
    SAMLMetadataDocument: SAMLMetadataDocumentType | None
    CreateDate: dateType | None
    ValidUntil: dateType | None
    Tags: tagListType | None
    AssertionEncryptionMode: assertionEncryptionModeType | None
    PrivateKeyList: privateKeyList | None


class GetSSHPublicKeyRequest(ServiceRequest):
    UserName: userNameType
    SSHPublicKeyId: publicKeyIdType
    Encoding: encodingType


class SSHPublicKey(TypedDict, total=False):
    UserName: userNameType
    SSHPublicKeyId: publicKeyIdType
    Fingerprint: publicKeyFingerprintType
    SSHPublicKeyBody: publicKeyMaterialType
    Status: statusType
    UploadDate: dateType | None


class GetSSHPublicKeyResponse(TypedDict, total=False):
    SSHPublicKey: SSHPublicKey | None


class GetServerCertificateRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType


class ServerCertificateMetadata(TypedDict, total=False):
    Path: pathType
    ServerCertificateName: serverCertificateNameType
    ServerCertificateId: idType
    Arn: arnType
    UploadDate: dateType | None
    Expiration: dateType | None


class ServerCertificate(TypedDict, total=False):
    ServerCertificateMetadata: ServerCertificateMetadata
    CertificateBody: certificateBodyType
    CertificateChain: certificateChainType | None
    Tags: tagListType | None


class GetServerCertificateResponse(TypedDict, total=False):
    ServerCertificate: ServerCertificate


class GetServiceLastAccessedDetailsRequest(ServiceRequest):
    JobId: jobIDType
    MaxItems: maxItemsType | None
    Marker: markerType | None


class TrackedActionLastAccessed(TypedDict, total=False):
    ActionName: stringType | None
    LastAccessedEntity: arnType | None
    LastAccessedTime: dateType | None
    LastAccessedRegion: stringType | None


TrackedActionsLastAccessed = list[TrackedActionLastAccessed]


class ServiceLastAccessed(TypedDict, total=False):
    ServiceName: serviceNameType
    LastAuthenticated: dateType | None
    ServiceNamespace: serviceNamespaceType
    LastAuthenticatedEntity: arnType | None
    LastAuthenticatedRegion: stringType | None
    TotalAuthenticatedEntities: integerType | None
    TrackedActionsLastAccessed: TrackedActionsLastAccessed | None


ServicesLastAccessed = list[ServiceLastAccessed]


class GetServiceLastAccessedDetailsResponse(TypedDict, total=False):
    JobStatus: jobStatusType
    JobType: AccessAdvisorUsageGranularityType | None
    JobCreationDate: dateType
    ServicesLastAccessed: ServicesLastAccessed
    JobCompletionDate: dateType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None
    Error: ErrorDetails | None


class GetServiceLastAccessedDetailsWithEntitiesRequest(ServiceRequest):
    JobId: jobIDType
    ServiceNamespace: serviceNamespaceType
    MaxItems: maxItemsType | None
    Marker: markerType | None


entityDetailsListType = list[EntityDetails]


class GetServiceLastAccessedDetailsWithEntitiesResponse(TypedDict, total=False):
    JobStatus: jobStatusType
    JobCreationDate: dateType
    JobCompletionDate: dateType
    EntityDetailsList: entityDetailsListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None
    Error: ErrorDetails | None


class GetServiceLinkedRoleDeletionStatusRequest(ServiceRequest):
    DeletionTaskId: DeletionTaskIdType


class GetServiceLinkedRoleDeletionStatusResponse(TypedDict, total=False):
    Status: DeletionTaskStatusType
    Reason: DeletionTaskFailureReasonType | None


class GetUserPolicyRequest(ServiceRequest):
    UserName: existingUserNameType
    PolicyName: policyNameType


class GetUserPolicyResponse(TypedDict, total=False):
    UserName: existingUserNameType
    PolicyName: policyNameType
    PolicyDocument: policyDocumentType


class GetUserRequest(ServiceRequest):
    UserName: existingUserNameType | None


class GetUserResponse(TypedDict, total=False):
    User: User


class ListAccessKeysRequest(ServiceRequest):
    UserName: existingUserNameType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


accessKeyMetadataListType = list[AccessKeyMetadata]


class ListAccessKeysResponse(TypedDict, total=False):
    AccessKeyMetadata: accessKeyMetadataListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListAccountAliasesRequest(ServiceRequest):
    Marker: markerType | None
    MaxItems: maxItemsType | None


accountAliasListType = list[accountAliasType]


class ListAccountAliasesResponse(TypedDict, total=False):
    AccountAliases: accountAliasListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListAttachedGroupPoliciesRequest(ServiceRequest):
    GroupName: groupNameType
    PathPrefix: policyPathType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListAttachedGroupPoliciesResponse(TypedDict, total=False):
    AttachedPolicies: attachedPoliciesListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListAttachedRolePoliciesRequest(ServiceRequest):
    RoleName: roleNameType
    PathPrefix: policyPathType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListAttachedRolePoliciesResponse(TypedDict, total=False):
    AttachedPolicies: attachedPoliciesListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListAttachedUserPoliciesRequest(ServiceRequest):
    UserName: userNameType
    PathPrefix: policyPathType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListAttachedUserPoliciesResponse(TypedDict, total=False):
    AttachedPolicies: attachedPoliciesListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListDelegationRequestsRequest(ServiceRequest):
    OwnerId: ownerIdType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


delegationRequestsListType = list[DelegationRequest]


class ListDelegationRequestsResponse(TypedDict, total=False):
    DelegationRequests: delegationRequestsListType | None
    Marker: markerType | None
    isTruncated: booleanType | None


class ListEntitiesForPolicyRequest(ServiceRequest):
    PolicyArn: arnType
    EntityFilter: EntityType | None
    PathPrefix: pathType | None
    PolicyUsageFilter: PolicyUsageType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class PolicyRole(TypedDict, total=False):
    RoleName: roleNameType | None
    RoleId: idType | None


PolicyRoleListType = list[PolicyRole]


class PolicyUser(TypedDict, total=False):
    UserName: userNameType | None
    UserId: idType | None


PolicyUserListType = list[PolicyUser]


class PolicyGroup(TypedDict, total=False):
    GroupName: groupNameType | None
    GroupId: idType | None


PolicyGroupListType = list[PolicyGroup]


class ListEntitiesForPolicyResponse(TypedDict, total=False):
    PolicyGroups: PolicyGroupListType | None
    PolicyUsers: PolicyUserListType | None
    PolicyRoles: PolicyRoleListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListGroupPoliciesRequest(ServiceRequest):
    GroupName: groupNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


policyNameListType = list[policyNameType]


class ListGroupPoliciesResponse(TypedDict, total=False):
    PolicyNames: policyNameListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListGroupsForUserRequest(ServiceRequest):
    UserName: existingUserNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


groupListType = list[Group]


class ListGroupsForUserResponse(TypedDict, total=False):
    Groups: groupListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListGroupsRequest(ServiceRequest):
    PathPrefix: pathPrefixType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListGroupsResponse(TypedDict, total=False):
    Groups: groupListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListInstanceProfileTagsRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListInstanceProfileTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListInstanceProfilesForRoleRequest(ServiceRequest):
    RoleName: roleNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListInstanceProfilesForRoleResponse(TypedDict, total=False):
    InstanceProfiles: instanceProfileListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListInstanceProfilesRequest(ServiceRequest):
    PathPrefix: pathPrefixType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListInstanceProfilesResponse(TypedDict, total=False):
    InstanceProfiles: instanceProfileListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListMFADeviceTagsRequest(ServiceRequest):
    SerialNumber: serialNumberType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListMFADeviceTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListMFADevicesRequest(ServiceRequest):
    UserName: existingUserNameType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class MFADevice(TypedDict, total=False):
    UserName: userNameType
    SerialNumber: serialNumberType
    EnableDate: dateType


mfaDeviceListType = list[MFADevice]


class ListMFADevicesResponse(TypedDict, total=False):
    MFADevices: mfaDeviceListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListOpenIDConnectProviderTagsRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListOpenIDConnectProviderTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListOpenIDConnectProvidersRequest(ServiceRequest):
    pass


class OpenIDConnectProviderListEntry(TypedDict, total=False):
    Arn: arnType | None


OpenIDConnectProviderListType = list[OpenIDConnectProviderListEntry]


class ListOpenIDConnectProvidersResponse(TypedDict, total=False):
    OpenIDConnectProviderList: OpenIDConnectProviderListType | None


class ListOrganizationsFeaturesRequest(ServiceRequest):
    pass


class ListOrganizationsFeaturesResponse(TypedDict, total=False):
    OrganizationId: OrganizationIdType | None
    EnabledFeatures: FeaturesListType | None


class PolicyGrantingServiceAccess(TypedDict, total=False):
    PolicyName: policyNameType
    PolicyType: policyType
    PolicyArn: arnType | None
    EntityType: policyOwnerEntityType | None
    EntityName: entityNameType | None


policyGrantingServiceAccessListType = list[PolicyGrantingServiceAccess]


class ListPoliciesGrantingServiceAccessEntry(TypedDict, total=False):
    ServiceNamespace: serviceNamespaceType | None
    Policies: policyGrantingServiceAccessListType | None


serviceNamespaceListType = list[serviceNamespaceType]


class ListPoliciesGrantingServiceAccessRequest(ServiceRequest):
    Marker: markerType | None
    Arn: arnType
    ServiceNamespaces: serviceNamespaceListType


listPolicyGrantingServiceAccessResponseListType = list[ListPoliciesGrantingServiceAccessEntry]


class ListPoliciesGrantingServiceAccessResponse(TypedDict, total=False):
    PoliciesGrantingServiceAccess: listPolicyGrantingServiceAccessResponseListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListPoliciesRequest(ServiceRequest):
    Scope: policyScopeType | None
    OnlyAttached: booleanType | None
    PathPrefix: policyPathType | None
    PolicyUsageFilter: PolicyUsageType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


policyListType = list[Policy]


class ListPoliciesResponse(TypedDict, total=False):
    Policies: policyListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListPolicyTagsRequest(ServiceRequest):
    PolicyArn: arnType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListPolicyTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListPolicyVersionsRequest(ServiceRequest):
    PolicyArn: arnType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListPolicyVersionsResponse(TypedDict, total=False):
    Versions: policyDocumentVersionListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListRolePoliciesRequest(ServiceRequest):
    RoleName: roleNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListRolePoliciesResponse(TypedDict, total=False):
    PolicyNames: policyNameListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListRoleTagsRequest(ServiceRequest):
    RoleName: roleNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListRoleTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListRolesRequest(ServiceRequest):
    PathPrefix: pathPrefixType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListRolesResponse(TypedDict, total=False):
    Roles: roleListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListSAMLProviderTagsRequest(ServiceRequest):
    SAMLProviderArn: arnType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListSAMLProviderTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListSAMLProvidersRequest(ServiceRequest):
    pass


class SAMLProviderListEntry(TypedDict, total=False):
    Arn: arnType | None
    ValidUntil: dateType | None
    CreateDate: dateType | None


SAMLProviderListType = list[SAMLProviderListEntry]


class ListSAMLProvidersResponse(TypedDict, total=False):
    SAMLProviderList: SAMLProviderListType | None


class ListSSHPublicKeysRequest(ServiceRequest):
    UserName: userNameType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class SSHPublicKeyMetadata(TypedDict, total=False):
    UserName: userNameType
    SSHPublicKeyId: publicKeyIdType
    Status: statusType
    UploadDate: dateType


SSHPublicKeyListType = list[SSHPublicKeyMetadata]


class ListSSHPublicKeysResponse(TypedDict, total=False):
    SSHPublicKeys: SSHPublicKeyListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListServerCertificateTagsRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListServerCertificateTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListServerCertificatesRequest(ServiceRequest):
    PathPrefix: pathPrefixType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


serverCertificateMetadataListType = list[ServerCertificateMetadata]


class ListServerCertificatesResponse(TypedDict, total=False):
    ServerCertificateMetadataList: serverCertificateMetadataListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListServiceSpecificCredentialsRequest(ServiceRequest):
    UserName: userNameType | None
    ServiceName: serviceName | None
    AllUsers: allUsers | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ServiceSpecificCredentialMetadata(TypedDict, total=False):
    UserName: userNameType
    Status: statusType
    ServiceUserName: serviceUserName | None
    ServiceCredentialAlias: serviceCredentialAlias | None
    CreateDate: dateType
    ExpirationDate: dateType | None
    ServiceSpecificCredentialId: serviceSpecificCredentialId
    ServiceName: serviceName


ServiceSpecificCredentialsListType = list[ServiceSpecificCredentialMetadata]


class ListServiceSpecificCredentialsResponse(TypedDict, total=False):
    ServiceSpecificCredentials: ServiceSpecificCredentialsListType | None
    Marker: responseMarkerType | None
    IsTruncated: booleanType | None


class ListSigningCertificatesRequest(ServiceRequest):
    UserName: existingUserNameType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class SigningCertificate(TypedDict, total=False):
    UserName: userNameType
    CertificateId: certificateIdType
    CertificateBody: certificateBodyType
    Status: statusType
    UploadDate: dateType | None


certificateListType = list[SigningCertificate]


class ListSigningCertificatesResponse(TypedDict, total=False):
    Certificates: certificateListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListUserPoliciesRequest(ServiceRequest):
    UserName: existingUserNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListUserPoliciesResponse(TypedDict, total=False):
    PolicyNames: policyNameListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListUserTagsRequest(ServiceRequest):
    UserName: existingUserNameType
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListUserTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListUsersRequest(ServiceRequest):
    PathPrefix: pathPrefixType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


class ListUsersResponse(TypedDict, total=False):
    Users: userListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class ListVirtualMFADevicesRequest(ServiceRequest):
    AssignmentStatus: assignmentStatusType | None
    Marker: markerType | None
    MaxItems: maxItemsType | None


virtualMFADeviceListType = list[VirtualMFADevice]


class ListVirtualMFADevicesResponse(TypedDict, total=False):
    VirtualMFADevices: virtualMFADeviceListType
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class PutGroupPolicyRequest(ServiceRequest):
    GroupName: groupNameType
    PolicyName: policyNameType
    PolicyDocument: policyDocumentType


class PutRolePermissionsBoundaryRequest(ServiceRequest):
    RoleName: roleNameType
    PermissionsBoundary: arnType


class PutRolePolicyRequest(ServiceRequest):
    RoleName: roleNameType
    PolicyName: policyNameType
    PolicyDocument: policyDocumentType


class PutUserPermissionsBoundaryRequest(ServiceRequest):
    UserName: userNameType
    PermissionsBoundary: arnType


class PutUserPolicyRequest(ServiceRequest):
    UserName: existingUserNameType
    PolicyName: policyNameType
    PolicyDocument: policyDocumentType


class RejectDelegationRequestRequest(ServiceRequest):
    DelegationRequestId: delegationRequestIdType
    Notes: notesType | None


class RemoveClientIDFromOpenIDConnectProviderRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    ClientID: clientIDType


class RemoveRoleFromInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    RoleName: roleNameType


class RemoveUserFromGroupRequest(ServiceRequest):
    GroupName: groupNameType
    UserName: existingUserNameType


class ResetServiceSpecificCredentialRequest(ServiceRequest):
    UserName: userNameType | None
    ServiceSpecificCredentialId: serviceSpecificCredentialId


class ResetServiceSpecificCredentialResponse(TypedDict, total=False):
    ServiceSpecificCredential: ServiceSpecificCredential | None


ResourceNameListType = list[ResourceNameType]


class ResyncMFADeviceRequest(ServiceRequest):
    UserName: existingUserNameType
    SerialNumber: serialNumberType
    AuthenticationCode1: authenticationCodeType
    AuthenticationCode2: authenticationCodeType


class SendDelegationTokenRequest(ServiceRequest):
    DelegationRequestId: delegationRequestIdType


class SetDefaultPolicyVersionRequest(ServiceRequest):
    PolicyArn: arnType
    VersionId: policyVersionIdType


class SetSecurityTokenServicePreferencesRequest(ServiceRequest):
    GlobalEndpointTokenVersion: globalEndpointTokenVersion


class SimulateCustomPolicyRequest(ServiceRequest):
    PolicyInputList: SimulationPolicyListType
    PermissionsBoundaryPolicyInputList: SimulationPolicyListType | None
    ActionNames: ActionNameListType
    ResourceArns: ResourceNameListType | None
    ResourcePolicy: policyDocumentType | None
    ResourceOwner: ResourceNameType | None
    CallerArn: ResourceNameType | None
    ContextEntries: ContextEntryListType | None
    ResourceHandlingOption: ResourceHandlingOptionType | None
    MaxItems: maxItemsType | None
    Marker: markerType | None


class SimulatePolicyResponse(TypedDict, total=False):
    EvaluationResults: EvaluationResultsListType | None
    IsTruncated: booleanType | None
    Marker: responseMarkerType | None


class SimulatePrincipalPolicyRequest(ServiceRequest):
    PolicySourceArn: arnType
    PolicyInputList: SimulationPolicyListType | None
    PermissionsBoundaryPolicyInputList: SimulationPolicyListType | None
    ActionNames: ActionNameListType
    ResourceArns: ResourceNameListType | None
    ResourcePolicy: policyDocumentType | None
    ResourceOwner: ResourceNameType | None
    CallerArn: ResourceNameType | None
    ContextEntries: ContextEntryListType | None
    ResourceHandlingOption: ResourceHandlingOptionType | None
    MaxItems: maxItemsType | None
    Marker: markerType | None


class TagInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    Tags: tagListType


class TagMFADeviceRequest(ServiceRequest):
    SerialNumber: serialNumberType
    Tags: tagListType


class TagOpenIDConnectProviderRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    Tags: tagListType


class TagPolicyRequest(ServiceRequest):
    PolicyArn: arnType
    Tags: tagListType


class TagRoleRequest(ServiceRequest):
    RoleName: roleNameType
    Tags: tagListType


class TagSAMLProviderRequest(ServiceRequest):
    SAMLProviderArn: arnType
    Tags: tagListType


class TagServerCertificateRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType
    Tags: tagListType


class TagUserRequest(ServiceRequest):
    UserName: existingUserNameType
    Tags: tagListType


tagKeyListType = list[tagKeyType]


class UntagInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    TagKeys: tagKeyListType


class UntagMFADeviceRequest(ServiceRequest):
    SerialNumber: serialNumberType
    TagKeys: tagKeyListType


class UntagOpenIDConnectProviderRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    TagKeys: tagKeyListType


class UntagPolicyRequest(ServiceRequest):
    PolicyArn: arnType
    TagKeys: tagKeyListType


class UntagRoleRequest(ServiceRequest):
    RoleName: roleNameType
    TagKeys: tagKeyListType


class UntagSAMLProviderRequest(ServiceRequest):
    SAMLProviderArn: arnType
    TagKeys: tagKeyListType


class UntagServerCertificateRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType
    TagKeys: tagKeyListType


class UntagUserRequest(ServiceRequest):
    UserName: existingUserNameType
    TagKeys: tagKeyListType


class UpdateAccessKeyRequest(ServiceRequest):
    UserName: existingUserNameType | None
    AccessKeyId: accessKeyIdType
    Status: statusType


class UpdateAccountPasswordPolicyRequest(ServiceRequest):
    MinimumPasswordLength: minimumPasswordLengthType | None
    RequireSymbols: booleanType | None
    RequireNumbers: booleanType | None
    RequireUppercaseCharacters: booleanType | None
    RequireLowercaseCharacters: booleanType | None
    AllowUsersToChangePassword: booleanType | None
    MaxPasswordAge: maxPasswordAgeType | None
    PasswordReusePrevention: passwordReusePreventionType | None
    HardExpiry: booleanObjectType | None


class UpdateAssumeRolePolicyRequest(ServiceRequest):
    RoleName: roleNameType
    PolicyDocument: policyDocumentType


class UpdateDelegationRequestRequest(ServiceRequest):
    DelegationRequestId: delegationRequestIdType
    Notes: notesType | None


class UpdateGroupRequest(ServiceRequest):
    GroupName: groupNameType
    NewPath: pathType | None
    NewGroupName: groupNameType | None


class UpdateLoginProfileRequest(ServiceRequest):
    UserName: userNameType
    Password: passwordType | None
    PasswordResetRequired: booleanObjectType | None


class UpdateOpenIDConnectProviderThumbprintRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    ThumbprintList: thumbprintListType


class UpdateRoleDescriptionRequest(ServiceRequest):
    RoleName: roleNameType
    Description: roleDescriptionType


class UpdateRoleDescriptionResponse(TypedDict, total=False):
    Role: Role | None


class UpdateRoleRequest(ServiceRequest):
    RoleName: roleNameType
    Description: roleDescriptionType | None
    MaxSessionDuration: roleMaxSessionDurationType | None


class UpdateRoleResponse(TypedDict, total=False):
    pass


class UpdateSAMLProviderRequest(ServiceRequest):
    SAMLMetadataDocument: SAMLMetadataDocumentType | None
    SAMLProviderArn: arnType
    AssertionEncryptionMode: assertionEncryptionModeType | None
    AddPrivateKey: privateKeyType | None
    RemovePrivateKey: privateKeyIdType | None


class UpdateSAMLProviderResponse(TypedDict, total=False):
    SAMLProviderArn: arnType | None


class UpdateSSHPublicKeyRequest(ServiceRequest):
    UserName: userNameType
    SSHPublicKeyId: publicKeyIdType
    Status: statusType


class UpdateServerCertificateRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType
    NewPath: pathType | None
    NewServerCertificateName: serverCertificateNameType | None


class UpdateServiceSpecificCredentialRequest(ServiceRequest):
    UserName: userNameType | None
    ServiceSpecificCredentialId: serviceSpecificCredentialId
    Status: statusType


class UpdateSigningCertificateRequest(ServiceRequest):
    UserName: existingUserNameType | None
    CertificateId: certificateIdType
    Status: statusType


class UpdateUserRequest(ServiceRequest):
    UserName: existingUserNameType
    NewPath: pathType | None
    NewUserName: userNameType | None


class UploadSSHPublicKeyRequest(ServiceRequest):
    UserName: userNameType
    SSHPublicKeyBody: publicKeyMaterialType


class UploadSSHPublicKeyResponse(TypedDict, total=False):
    SSHPublicKey: SSHPublicKey | None


class UploadServerCertificateRequest(ServiceRequest):
    Path: pathType | None
    ServerCertificateName: serverCertificateNameType
    CertificateBody: certificateBodyType
    PrivateKey: privateKeyType
    CertificateChain: certificateChainType | None
    Tags: tagListType | None


class UploadServerCertificateResponse(TypedDict, total=False):
    ServerCertificateMetadata: ServerCertificateMetadata | None
    Tags: tagListType | None


class UploadSigningCertificateRequest(ServiceRequest):
    UserName: existingUserNameType | None
    CertificateBody: certificateBodyType


class UploadSigningCertificateResponse(TypedDict, total=False):
    Certificate: SigningCertificate


class IamApi:
    service: str = "iam"
    version: str = "2010-05-08"

    @handler("AcceptDelegationRequest")
    def accept_delegation_request(
        self, context: RequestContext, delegation_request_id: delegationRequestIdType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("AddClientIDToOpenIDConnectProvider")
    def add_client_id_to_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        client_id: clientIDType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("AddRoleToInstanceProfile")
    def add_role_to_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        role_name: roleNameType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("AddUserToGroup")
    def add_user_to_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        user_name: existingUserNameType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("AssociateDelegationRequest")
    def associate_delegation_request(
        self, context: RequestContext, delegation_request_id: delegationRequestIdType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("AttachGroupPolicy")
    def attach_group_policy(
        self, context: RequestContext, group_name: groupNameType, policy_arn: arnType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("AttachRolePolicy")
    def attach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("AttachUserPolicy")
    def attach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("ChangePassword")
    def change_password(
        self,
        context: RequestContext,
        old_password: passwordType,
        new_password: passwordType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateAccessKey")
    def create_access_key(
        self, context: RequestContext, user_name: existingUserNameType | None = None, **kwargs
    ) -> CreateAccessKeyResponse:
        raise NotImplementedError

    @handler("CreateAccountAlias")
    def create_account_alias(
        self, context: RequestContext, account_alias: accountAliasType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("CreateDelegationRequest")
    def create_delegation_request(
        self,
        context: RequestContext,
        description: delegationRequestDescriptionType,
        permissions: DelegationPermission,
        requestor_workflow_id: requestorWorkflowIdType,
        notification_channel: notificationChannelType,
        session_duration: sessionDurationType,
        owner_account_id: accountIdType | None = None,
        request_message: requestMessageType | None = None,
        redirect_url: redirectUrlType | None = None,
        only_send_by_owner: booleanType | None = None,
        **kwargs,
    ) -> CreateDelegationRequestResponse:
        raise NotImplementedError

    @handler("CreateGroup")
    def create_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        path: pathType | None = None,
        **kwargs,
    ) -> CreateGroupResponse:
        raise NotImplementedError

    @handler("CreateInstanceProfile")
    def create_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        path: pathType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateInstanceProfileResponse:
        raise NotImplementedError

    @handler("CreateLoginProfile")
    def create_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType | None = None,
        password: passwordType | None = None,
        password_reset_required: booleanType | None = None,
        **kwargs,
    ) -> CreateLoginProfileResponse:
        raise NotImplementedError

    @handler("CreateOpenIDConnectProvider")
    def create_open_id_connect_provider(
        self,
        context: RequestContext,
        url: OpenIDConnectProviderUrlType,
        client_id_list: clientIDListType | None = None,
        thumbprint_list: thumbprintListType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateOpenIDConnectProviderResponse:
        raise NotImplementedError

    @handler("CreatePolicy")
    def create_policy(
        self,
        context: RequestContext,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        path: policyPathType | None = None,
        description: policyDescriptionType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreatePolicyResponse:
        raise NotImplementedError

    @handler("CreatePolicyVersion")
    def create_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        policy_document: policyDocumentType,
        set_as_default: booleanType | None = None,
        **kwargs,
    ) -> CreatePolicyVersionResponse:
        raise NotImplementedError

    @handler("CreateRole")
    def create_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        assume_role_policy_document: policyDocumentType,
        path: pathType | None = None,
        description: roleDescriptionType | None = None,
        max_session_duration: roleMaxSessionDurationType | None = None,
        permissions_boundary: arnType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateRoleResponse:
        raise NotImplementedError

    @handler("CreateSAMLProvider")
    def create_saml_provider(
        self,
        context: RequestContext,
        saml_metadata_document: SAMLMetadataDocumentType,
        name: SAMLProviderNameType,
        tags: tagListType | None = None,
        assertion_encryption_mode: assertionEncryptionModeType | None = None,
        add_private_key: privateKeyType | None = None,
        **kwargs,
    ) -> CreateSAMLProviderResponse:
        raise NotImplementedError

    @handler("CreateServiceLinkedRole")
    def create_service_linked_role(
        self,
        context: RequestContext,
        aws_service_name: groupNameType,
        description: roleDescriptionType | None = None,
        custom_suffix: customSuffixType | None = None,
        **kwargs,
    ) -> CreateServiceLinkedRoleResponse:
        raise NotImplementedError

    @handler("CreateServiceSpecificCredential")
    def create_service_specific_credential(
        self,
        context: RequestContext,
        user_name: userNameType,
        service_name: serviceName,
        credential_age_days: credentialAgeDays | None = None,
        **kwargs,
    ) -> CreateServiceSpecificCredentialResponse:
        raise NotImplementedError

    @handler("CreateUser")
    def create_user(
        self,
        context: RequestContext,
        user_name: userNameType,
        path: pathType | None = None,
        permissions_boundary: arnType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateUserResponse:
        raise NotImplementedError

    @handler("CreateVirtualMFADevice")
    def create_virtual_mfa_device(
        self,
        context: RequestContext,
        virtual_mfa_device_name: virtualMFADeviceName,
        path: pathType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> CreateVirtualMFADeviceResponse:
        raise NotImplementedError

    @handler("DeactivateMFADevice")
    def deactivate_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessKey")
    def delete_access_key(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccountAlias")
    def delete_account_alias(
        self, context: RequestContext, account_alias: accountAliasType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccountPasswordPolicy")
    def delete_account_password_policy(self, context: RequestContext, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteGroup")
    def delete_group(self, context: RequestContext, group_name: groupNameType, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteGroupPolicy")
    def delete_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteInstanceProfile")
    def delete_instance_profile(
        self, context: RequestContext, instance_profile_name: instanceProfileNameType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteLoginProfile")
    def delete_login_profile(
        self, context: RequestContext, user_name: userNameType | None = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteOpenIDConnectProvider")
    def delete_open_id_connect_provider(
        self, context: RequestContext, open_id_connect_provider_arn: arnType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeletePolicy")
    def delete_policy(self, context: RequestContext, policy_arn: arnType, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeletePolicyVersion")
    def delete_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRole")
    def delete_role(self, context: RequestContext, role_name: roleNameType, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteRolePermissionsBoundary")
    def delete_role_permissions_boundary(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRolePolicy")
    def delete_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSAMLProvider")
    def delete_saml_provider(
        self, context: RequestContext, saml_provider_arn: arnType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSSHPublicKey")
    def delete_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteServerCertificate")
    def delete_server_certificate(
        self, context: RequestContext, server_certificate_name: serverCertificateNameType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteServiceLinkedRole")
    def delete_service_linked_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> DeleteServiceLinkedRoleResponse:
        raise NotImplementedError

    @handler("DeleteServiceSpecificCredential")
    def delete_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        user_name: userNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSigningCertificate")
    def delete_signing_certificate(
        self,
        context: RequestContext,
        certificate_id: certificateIdType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUser")
    def delete_user(
        self, context: RequestContext, user_name: existingUserNameType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUserPermissionsBoundary")
    def delete_user_permissions_boundary(
        self, context: RequestContext, user_name: userNameType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteUserPolicy")
    def delete_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVirtualMFADevice")
    def delete_virtual_mfa_device(
        self, context: RequestContext, serial_number: serialNumberType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DetachGroupPolicy")
    def detach_group_policy(
        self, context: RequestContext, group_name: groupNameType, policy_arn: arnType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DetachRolePolicy")
    def detach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DetachUserPolicy")
    def detach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DisableOrganizationsRootCredentialsManagement")
    def disable_organizations_root_credentials_management(
        self, context: RequestContext, **kwargs
    ) -> DisableOrganizationsRootCredentialsManagementResponse:
        raise NotImplementedError

    @handler("DisableOrganizationsRootSessions")
    def disable_organizations_root_sessions(
        self, context: RequestContext, **kwargs
    ) -> DisableOrganizationsRootSessionsResponse:
        raise NotImplementedError

    @handler("DisableOutboundWebIdentityFederation")
    def disable_outbound_web_identity_federation(self, context: RequestContext, **kwargs) -> None:
        raise NotImplementedError

    @handler("EnableMFADevice")
    def enable_mfa_device(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        serial_number: serialNumberType,
        authentication_code1: authenticationCodeType,
        authentication_code2: authenticationCodeType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("EnableOrganizationsRootCredentialsManagement")
    def enable_organizations_root_credentials_management(
        self, context: RequestContext, **kwargs
    ) -> EnableOrganizationsRootCredentialsManagementResponse:
        raise NotImplementedError

    @handler("EnableOrganizationsRootSessions")
    def enable_organizations_root_sessions(
        self, context: RequestContext, **kwargs
    ) -> EnableOrganizationsRootSessionsResponse:
        raise NotImplementedError

    @handler("EnableOutboundWebIdentityFederation")
    def enable_outbound_web_identity_federation(
        self, context: RequestContext, **kwargs
    ) -> EnableOutboundWebIdentityFederationResponse:
        raise NotImplementedError

    @handler("GenerateCredentialReport")
    def generate_credential_report(
        self, context: RequestContext, **kwargs
    ) -> GenerateCredentialReportResponse:
        raise NotImplementedError

    @handler("GenerateOrganizationsAccessReport")
    def generate_organizations_access_report(
        self,
        context: RequestContext,
        entity_path: organizationsEntityPathType,
        organizations_policy_id: organizationsPolicyIdType | None = None,
        **kwargs,
    ) -> GenerateOrganizationsAccessReportResponse:
        raise NotImplementedError

    @handler("GenerateServiceLastAccessedDetails")
    def generate_service_last_accessed_details(
        self,
        context: RequestContext,
        arn: arnType,
        granularity: AccessAdvisorUsageGranularityType | None = None,
        **kwargs,
    ) -> GenerateServiceLastAccessedDetailsResponse:
        raise NotImplementedError

    @handler("GetAccessKeyLastUsed")
    def get_access_key_last_used(
        self, context: RequestContext, access_key_id: accessKeyIdType, **kwargs
    ) -> GetAccessKeyLastUsedResponse:
        raise NotImplementedError

    @handler("GetAccountAuthorizationDetails")
    def get_account_authorization_details(
        self,
        context: RequestContext,
        filter: entityListType | None = None,
        max_items: maxItemsType | None = None,
        marker: markerType | None = None,
        **kwargs,
    ) -> GetAccountAuthorizationDetailsResponse:
        raise NotImplementedError

    @handler("GetAccountPasswordPolicy")
    def get_account_password_policy(
        self, context: RequestContext, **kwargs
    ) -> GetAccountPasswordPolicyResponse:
        raise NotImplementedError

    @handler("GetAccountSummary")
    def get_account_summary(self, context: RequestContext, **kwargs) -> GetAccountSummaryResponse:
        raise NotImplementedError

    @handler("GetContextKeysForCustomPolicy")
    def get_context_keys_for_custom_policy(
        self, context: RequestContext, policy_input_list: SimulationPolicyListType, **kwargs
    ) -> GetContextKeysForPolicyResponse:
        raise NotImplementedError

    @handler("GetContextKeysForPrincipalPolicy")
    def get_context_keys_for_principal_policy(
        self,
        context: RequestContext,
        policy_source_arn: arnType,
        policy_input_list: SimulationPolicyListType | None = None,
        **kwargs,
    ) -> GetContextKeysForPolicyResponse:
        raise NotImplementedError

    @handler("GetCredentialReport")
    def get_credential_report(
        self, context: RequestContext, **kwargs
    ) -> GetCredentialReportResponse:
        raise NotImplementedError

    @handler("GetDelegationRequest")
    def get_delegation_request(
        self,
        context: RequestContext,
        delegation_request_id: delegationRequestIdType,
        delegation_permission_check: booleanType | None = None,
        **kwargs,
    ) -> GetDelegationRequestResponse:
        raise NotImplementedError

    @handler("GetGroup")
    def get_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> GetGroupResponse:
        raise NotImplementedError

    @handler("GetGroupPolicy")
    def get_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetGroupPolicyResponse:
        raise NotImplementedError

    @handler("GetHumanReadableSummary")
    def get_human_readable_summary(
        self,
        context: RequestContext,
        entity_arn: arnType,
        locale: localeType | None = None,
        **kwargs,
    ) -> GetHumanReadableSummaryResponse:
        raise NotImplementedError

    @handler("GetInstanceProfile")
    def get_instance_profile(
        self, context: RequestContext, instance_profile_name: instanceProfileNameType, **kwargs
    ) -> GetInstanceProfileResponse:
        raise NotImplementedError

    @handler("GetLoginProfile")
    def get_login_profile(
        self, context: RequestContext, user_name: userNameType | None = None, **kwargs
    ) -> GetLoginProfileResponse:
        raise NotImplementedError

    @handler("GetMFADevice")
    def get_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        user_name: userNameType | None = None,
        **kwargs,
    ) -> GetMFADeviceResponse:
        raise NotImplementedError

    @handler("GetOpenIDConnectProvider")
    def get_open_id_connect_provider(
        self, context: RequestContext, open_id_connect_provider_arn: arnType, **kwargs
    ) -> GetOpenIDConnectProviderResponse:
        raise NotImplementedError

    @handler("GetOrganizationsAccessReport")
    def get_organizations_access_report(
        self,
        context: RequestContext,
        job_id: jobIDType,
        max_items: maxItemsType | None = None,
        marker: markerType | None = None,
        sort_key: sortKeyType | None = None,
        **kwargs,
    ) -> GetOrganizationsAccessReportResponse:
        raise NotImplementedError

    @handler("GetOutboundWebIdentityFederationInfo")
    def get_outbound_web_identity_federation_info(
        self, context: RequestContext, **kwargs
    ) -> GetOutboundWebIdentityFederationInfoResponse:
        raise NotImplementedError

    @handler("GetPolicy")
    def get_policy(
        self, context: RequestContext, policy_arn: arnType, **kwargs
    ) -> GetPolicyResponse:
        raise NotImplementedError

    @handler("GetPolicyVersion")
    def get_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> GetPolicyVersionResponse:
        raise NotImplementedError

    @handler("GetRole")
    def get_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> GetRoleResponse:
        raise NotImplementedError

    @handler("GetRolePolicy")
    def get_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetRolePolicyResponse:
        raise NotImplementedError

    @handler("GetSAMLProvider")
    def get_saml_provider(
        self, context: RequestContext, saml_provider_arn: arnType, **kwargs
    ) -> GetSAMLProviderResponse:
        raise NotImplementedError

    @handler("GetSSHPublicKey")
    def get_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        encoding: encodingType,
        **kwargs,
    ) -> GetSSHPublicKeyResponse:
        raise NotImplementedError

    @handler("GetServerCertificate")
    def get_server_certificate(
        self, context: RequestContext, server_certificate_name: serverCertificateNameType, **kwargs
    ) -> GetServerCertificateResponse:
        raise NotImplementedError

    @handler("GetServiceLastAccessedDetails")
    def get_service_last_accessed_details(
        self,
        context: RequestContext,
        job_id: jobIDType,
        max_items: maxItemsType | None = None,
        marker: markerType | None = None,
        **kwargs,
    ) -> GetServiceLastAccessedDetailsResponse:
        raise NotImplementedError

    @handler("GetServiceLastAccessedDetailsWithEntities")
    def get_service_last_accessed_details_with_entities(
        self,
        context: RequestContext,
        job_id: jobIDType,
        service_namespace: serviceNamespaceType,
        max_items: maxItemsType | None = None,
        marker: markerType | None = None,
        **kwargs,
    ) -> GetServiceLastAccessedDetailsWithEntitiesResponse:
        raise NotImplementedError

    @handler("GetServiceLinkedRoleDeletionStatus")
    def get_service_linked_role_deletion_status(
        self, context: RequestContext, deletion_task_id: DeletionTaskIdType, **kwargs
    ) -> GetServiceLinkedRoleDeletionStatusResponse:
        raise NotImplementedError

    @handler("GetUser")
    def get_user(
        self, context: RequestContext, user_name: existingUserNameType | None = None, **kwargs
    ) -> GetUserResponse:
        raise NotImplementedError

    @handler("GetUserPolicy")
    def get_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        **kwargs,
    ) -> GetUserPolicyResponse:
        raise NotImplementedError

    @handler("ListAccessKeys")
    def list_access_keys(
        self,
        context: RequestContext,
        user_name: existingUserNameType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListAccessKeysResponse:
        raise NotImplementedError

    @handler("ListAccountAliases")
    def list_account_aliases(
        self,
        context: RequestContext,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListAccountAliasesResponse:
        raise NotImplementedError

    @handler("ListAttachedGroupPolicies")
    def list_attached_group_policies(
        self,
        context: RequestContext,
        group_name: groupNameType,
        path_prefix: policyPathType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListAttachedGroupPoliciesResponse:
        raise NotImplementedError

    @handler("ListAttachedRolePolicies")
    def list_attached_role_policies(
        self,
        context: RequestContext,
        role_name: roleNameType,
        path_prefix: policyPathType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListAttachedRolePoliciesResponse:
        raise NotImplementedError

    @handler("ListAttachedUserPolicies")
    def list_attached_user_policies(
        self,
        context: RequestContext,
        user_name: userNameType,
        path_prefix: policyPathType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListAttachedUserPoliciesResponse:
        raise NotImplementedError

    @handler("ListDelegationRequests")
    def list_delegation_requests(
        self,
        context: RequestContext,
        owner_id: ownerIdType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListDelegationRequestsResponse:
        raise NotImplementedError

    @handler("ListEntitiesForPolicy")
    def list_entities_for_policy(
        self,
        context: RequestContext,
        policy_arn: arnType,
        entity_filter: EntityType | None = None,
        path_prefix: pathType | None = None,
        policy_usage_filter: PolicyUsageType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListEntitiesForPolicyResponse:
        raise NotImplementedError

    @handler("ListGroupPolicies")
    def list_group_policies(
        self,
        context: RequestContext,
        group_name: groupNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListGroupPoliciesResponse:
        raise NotImplementedError

    @handler("ListGroups")
    def list_groups(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListGroupsResponse:
        raise NotImplementedError

    @handler("ListGroupsForUser")
    def list_groups_for_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListGroupsForUserResponse:
        raise NotImplementedError

    @handler("ListInstanceProfileTags")
    def list_instance_profile_tags(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListInstanceProfileTagsResponse:
        raise NotImplementedError

    @handler("ListInstanceProfiles")
    def list_instance_profiles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListInstanceProfilesResponse:
        raise NotImplementedError

    @handler("ListInstanceProfilesForRole")
    def list_instance_profiles_for_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListInstanceProfilesForRoleResponse:
        raise NotImplementedError

    @handler("ListMFADeviceTags")
    def list_mfa_device_tags(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListMFADeviceTagsResponse:
        raise NotImplementedError

    @handler("ListMFADevices")
    def list_mfa_devices(
        self,
        context: RequestContext,
        user_name: existingUserNameType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListMFADevicesResponse:
        raise NotImplementedError

    @handler("ListOpenIDConnectProviderTags")
    def list_open_id_connect_provider_tags(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListOpenIDConnectProviderTagsResponse:
        raise NotImplementedError

    @handler("ListOpenIDConnectProviders")
    def list_open_id_connect_providers(
        self, context: RequestContext, **kwargs
    ) -> ListOpenIDConnectProvidersResponse:
        raise NotImplementedError

    @handler("ListOrganizationsFeatures")
    def list_organizations_features(
        self, context: RequestContext, **kwargs
    ) -> ListOrganizationsFeaturesResponse:
        raise NotImplementedError

    @handler("ListPolicies")
    def list_policies(
        self,
        context: RequestContext,
        scope: policyScopeType | None = None,
        only_attached: booleanType | None = None,
        path_prefix: policyPathType | None = None,
        policy_usage_filter: PolicyUsageType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListPoliciesResponse:
        raise NotImplementedError

    @handler("ListPoliciesGrantingServiceAccess")
    def list_policies_granting_service_access(
        self,
        context: RequestContext,
        arn: arnType,
        service_namespaces: serviceNamespaceListType,
        marker: markerType | None = None,
        **kwargs,
    ) -> ListPoliciesGrantingServiceAccessResponse:
        raise NotImplementedError

    @handler("ListPolicyTags")
    def list_policy_tags(
        self,
        context: RequestContext,
        policy_arn: arnType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListPolicyTagsResponse:
        raise NotImplementedError

    @handler("ListPolicyVersions")
    def list_policy_versions(
        self,
        context: RequestContext,
        policy_arn: arnType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListPolicyVersionsResponse:
        raise NotImplementedError

    @handler("ListRolePolicies")
    def list_role_policies(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListRolePoliciesResponse:
        raise NotImplementedError

    @handler("ListRoleTags")
    def list_role_tags(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListRoleTagsResponse:
        raise NotImplementedError

    @handler("ListRoles")
    def list_roles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListRolesResponse:
        raise NotImplementedError

    @handler("ListSAMLProviderTags")
    def list_saml_provider_tags(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListSAMLProviderTagsResponse:
        raise NotImplementedError

    @handler("ListSAMLProviders")
    def list_saml_providers(self, context: RequestContext, **kwargs) -> ListSAMLProvidersResponse:
        raise NotImplementedError

    @handler("ListSSHPublicKeys")
    def list_ssh_public_keys(
        self,
        context: RequestContext,
        user_name: userNameType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListSSHPublicKeysResponse:
        raise NotImplementedError

    @handler("ListServerCertificateTags")
    def list_server_certificate_tags(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListServerCertificateTagsResponse:
        raise NotImplementedError

    @handler("ListServerCertificates")
    def list_server_certificates(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListServerCertificatesResponse:
        raise NotImplementedError

    @handler("ListServiceSpecificCredentials")
    def list_service_specific_credentials(
        self,
        context: RequestContext,
        user_name: userNameType | None = None,
        service_name: serviceName | None = None,
        all_users: allUsers | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListServiceSpecificCredentialsResponse:
        raise NotImplementedError

    @handler("ListSigningCertificates")
    def list_signing_certificates(
        self,
        context: RequestContext,
        user_name: existingUserNameType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListSigningCertificatesResponse:
        raise NotImplementedError

    @handler("ListUserPolicies")
    def list_user_policies(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListUserPoliciesResponse:
        raise NotImplementedError

    @handler("ListUserTags")
    def list_user_tags(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListUserTagsResponse:
        raise NotImplementedError

    @handler("ListUsers")
    def list_users(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListUsersResponse:
        raise NotImplementedError

    @handler("ListVirtualMFADevices")
    def list_virtual_mfa_devices(
        self,
        context: RequestContext,
        assignment_status: assignmentStatusType | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListVirtualMFADevicesResponse:
        raise NotImplementedError

    @handler("PutGroupPolicy")
    def put_group_policy(
        self,
        context: RequestContext,
        group_name: groupNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutRolePermissionsBoundary")
    def put_role_permissions_boundary(
        self,
        context: RequestContext,
        role_name: roleNameType,
        permissions_boundary: arnType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutRolePolicy")
    def put_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutUserPermissionsBoundary")
    def put_user_permissions_boundary(
        self,
        context: RequestContext,
        user_name: userNameType,
        permissions_boundary: arnType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutUserPolicy")
    def put_user_policy(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RejectDelegationRequest")
    def reject_delegation_request(
        self,
        context: RequestContext,
        delegation_request_id: delegationRequestIdType,
        notes: notesType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RemoveClientIDFromOpenIDConnectProvider")
    def remove_client_id_from_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        client_id: clientIDType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RemoveRoleFromInstanceProfile")
    def remove_role_from_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        role_name: roleNameType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RemoveUserFromGroup")
    def remove_user_from_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        user_name: existingUserNameType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ResetServiceSpecificCredential")
    def reset_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        user_name: userNameType | None = None,
        **kwargs,
    ) -> ResetServiceSpecificCredentialResponse:
        raise NotImplementedError

    @handler("ResyncMFADevice")
    def resync_mfa_device(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        serial_number: serialNumberType,
        authentication_code1: authenticationCodeType,
        authentication_code2: authenticationCodeType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("SendDelegationToken")
    def send_delegation_token(
        self, context: RequestContext, delegation_request_id: delegationRequestIdType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("SetDefaultPolicyVersion")
    def set_default_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        version_id: policyVersionIdType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("SetSecurityTokenServicePreferences")
    def set_security_token_service_preferences(
        self,
        context: RequestContext,
        global_endpoint_token_version: globalEndpointTokenVersion,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("SimulateCustomPolicy")
    def simulate_custom_policy(
        self,
        context: RequestContext,
        policy_input_list: SimulationPolicyListType,
        action_names: ActionNameListType,
        permissions_boundary_policy_input_list: SimulationPolicyListType | None = None,
        resource_arns: ResourceNameListType | None = None,
        resource_policy: policyDocumentType | None = None,
        resource_owner: ResourceNameType | None = None,
        caller_arn: ResourceNameType | None = None,
        context_entries: ContextEntryListType | None = None,
        resource_handling_option: ResourceHandlingOptionType | None = None,
        max_items: maxItemsType | None = None,
        marker: markerType | None = None,
        **kwargs,
    ) -> SimulatePolicyResponse:
        raise NotImplementedError

    @handler("SimulatePrincipalPolicy")
    def simulate_principal_policy(
        self,
        context: RequestContext,
        policy_source_arn: arnType,
        action_names: ActionNameListType,
        policy_input_list: SimulationPolicyListType | None = None,
        permissions_boundary_policy_input_list: SimulationPolicyListType | None = None,
        resource_arns: ResourceNameListType | None = None,
        resource_policy: policyDocumentType | None = None,
        resource_owner: ResourceNameType | None = None,
        caller_arn: ResourceNameType | None = None,
        context_entries: ContextEntryListType | None = None,
        resource_handling_option: ResourceHandlingOptionType | None = None,
        max_items: maxItemsType | None = None,
        marker: markerType | None = None,
        **kwargs,
    ) -> SimulatePolicyResponse:
        raise NotImplementedError

    @handler("TagInstanceProfile")
    def tag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("TagMFADevice")
    def tag_mfa_device(
        self, context: RequestContext, serial_number: serialNumberType, tags: tagListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TagOpenIDConnectProvider")
    def tag_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("TagPolicy")
    def tag_policy(
        self, context: RequestContext, policy_arn: arnType, tags: tagListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TagRole")
    def tag_role(
        self, context: RequestContext, role_name: roleNameType, tags: tagListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TagSAMLProvider")
    def tag_saml_provider(
        self, context: RequestContext, saml_provider_arn: arnType, tags: tagListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TagServerCertificate")
    def tag_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("TagUser")
    def tag_user(
        self, context: RequestContext, user_name: existingUserNameType, tags: tagListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagInstanceProfile")
    def untag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UntagMFADevice")
    def untag_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UntagOpenIDConnectProvider")
    def untag_open_id_connect_provider(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UntagPolicy")
    def untag_policy(
        self, context: RequestContext, policy_arn: arnType, tag_keys: tagKeyListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagRole")
    def untag_role(
        self, context: RequestContext, role_name: roleNameType, tag_keys: tagKeyListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagSAMLProvider")
    def untag_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UntagServerCertificate")
    def untag_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UntagUser")
    def untag_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAccessKey")
    def update_access_key(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        status: statusType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAccountPasswordPolicy")
    def update_account_password_policy(
        self,
        context: RequestContext,
        minimum_password_length: minimumPasswordLengthType | None = None,
        require_symbols: booleanType | None = None,
        require_numbers: booleanType | None = None,
        require_uppercase_characters: booleanType | None = None,
        require_lowercase_characters: booleanType | None = None,
        allow_users_to_change_password: booleanType | None = None,
        max_password_age: maxPasswordAgeType | None = None,
        password_reuse_prevention: passwordReusePreventionType | None = None,
        hard_expiry: booleanObjectType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAssumeRolePolicy")
    def update_assume_role_policy(
        self,
        context: RequestContext,
        role_name: roleNameType,
        policy_document: policyDocumentType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateDelegationRequest")
    def update_delegation_request(
        self,
        context: RequestContext,
        delegation_request_id: delegationRequestIdType,
        notes: notesType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateGroup")
    def update_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        new_path: pathType | None = None,
        new_group_name: groupNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateLoginProfile")
    def update_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType,
        password: passwordType | None = None,
        password_reset_required: booleanObjectType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateOpenIDConnectProviderThumbprint")
    def update_open_id_connect_provider_thumbprint(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        thumbprint_list: thumbprintListType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateRole")
    def update_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        description: roleDescriptionType | None = None,
        max_session_duration: roleMaxSessionDurationType | None = None,
        **kwargs,
    ) -> UpdateRoleResponse:
        raise NotImplementedError

    @handler("UpdateRoleDescription")
    def update_role_description(
        self,
        context: RequestContext,
        role_name: roleNameType,
        description: roleDescriptionType,
        **kwargs,
    ) -> UpdateRoleDescriptionResponse:
        raise NotImplementedError

    @handler("UpdateSAMLProvider")
    def update_saml_provider(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        saml_metadata_document: SAMLMetadataDocumentType | None = None,
        assertion_encryption_mode: assertionEncryptionModeType | None = None,
        add_private_key: privateKeyType | None = None,
        remove_private_key: privateKeyIdType | None = None,
        **kwargs,
    ) -> UpdateSAMLProviderResponse:
        raise NotImplementedError

    @handler("UpdateSSHPublicKey")
    def update_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_id: publicKeyIdType,
        status: statusType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateServerCertificate")
    def update_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        new_path: pathType | None = None,
        new_server_certificate_name: serverCertificateNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateServiceSpecificCredential")
    def update_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        status: statusType,
        user_name: userNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateSigningCertificate")
    def update_signing_certificate(
        self,
        context: RequestContext,
        certificate_id: certificateIdType,
        status: statusType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateUser")
    def update_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        new_path: pathType | None = None,
        new_user_name: userNameType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UploadSSHPublicKey")
    def upload_ssh_public_key(
        self,
        context: RequestContext,
        user_name: userNameType,
        ssh_public_key_body: publicKeyMaterialType,
        **kwargs,
    ) -> UploadSSHPublicKeyResponse:
        raise NotImplementedError

    @handler("UploadServerCertificate")
    def upload_server_certificate(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        certificate_body: certificateBodyType,
        private_key: privateKeyType,
        path: pathType | None = None,
        certificate_chain: certificateChainType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> UploadServerCertificateResponse:
        raise NotImplementedError

    @handler("UploadSigningCertificate")
    def upload_signing_certificate(
        self,
        context: RequestContext,
        certificate_body: certificateBodyType,
        user_name: existingUserNameType | None = None,
        **kwargs,
    ) -> UploadSigningCertificateResponse:
        raise NotImplementedError
