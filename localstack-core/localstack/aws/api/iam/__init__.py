from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

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
LineNumber = int
OpenIDConnectProviderUrlType = str
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
arnType = str
attachmentCountType = int
authenticationCodeType = str
booleanObjectType = bool
booleanType = bool
certificateBodyType = str
certificateChainType = str
certificateIdType = str
clientIDType = str
credentialReportExpiredExceptionMessage = str
credentialReportNotPresentExceptionMessage = str
credentialReportNotReadyExceptionMessage = str
customSuffixType = str
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
malformedCertificateMessage = str
malformedPolicyDocumentMessage = str
markerType = str
maxItemsType = int
maxPasswordAgeType = int
minimumPasswordLengthType = int
noSuchEntityMessage = str
openIdIdpCommunicationErrorExceptionMessage = str
organizationsEntityPathType = str
organizationsPolicyIdType = str
passwordPolicyViolationMessage = str
passwordReusePreventionType = int
passwordType = str
pathPrefixType = str
pathType = str
policyDescriptionType = str
policyDocumentType = str
policyEvaluationErrorMessage = str
policyNameType = str
policyNotAttachableMessage = str
policyPathType = str
policyVersionIdType = str
privateKeyType = str
publicKeyFingerprintType = str
publicKeyIdType = str
publicKeyMaterialType = str
reportGenerationLimitExceededMessage = str
responseMarkerType = str
roleDescriptionType = str
roleMaxSessionDurationType = int
roleNameType = str
serialNumberType = str
serverCertificateNameType = str
serviceFailureExceptionMessage = str
serviceName = str
serviceNameType = str
serviceNamespaceType = str
serviceNotSupportedMessage = str
servicePassword = str
serviceSpecificCredentialId = str
serviceUserName = str
stringType = str
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


class PermissionsBoundaryAttachmentType(StrEnum):
    PermissionsBoundaryPolicy = "PermissionsBoundaryPolicy"


class PolicyEvaluationDecisionType(StrEnum):
    allowed = "allowed"
    explicitDeny = "explicitDeny"
    implicitDeny = "implicitDeny"


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


class statusType(StrEnum):
    Active = "Active"
    Inactive = "Inactive"


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


dateType = datetime


class AccessDetail(TypedDict, total=False):
    ServiceName: serviceNameType
    ServiceNamespace: serviceNamespaceType
    Region: Optional[stringType]
    EntityPath: Optional[organizationsEntityPathType]
    LastAuthenticatedTime: Optional[dateType]
    TotalAuthenticatedEntities: Optional[integerType]


AccessDetails = List[AccessDetail]


class AccessKey(TypedDict, total=False):
    UserName: userNameType
    AccessKeyId: accessKeyIdType
    Status: statusType
    SecretAccessKey: accessKeySecretType
    CreateDate: Optional[dateType]


class AccessKeyLastUsed(TypedDict, total=False):
    LastUsedDate: dateType
    ServiceName: stringType
    Region: stringType


class AccessKeyMetadata(TypedDict, total=False):
    UserName: Optional[userNameType]
    AccessKeyId: Optional[accessKeyIdType]
    Status: Optional[statusType]
    CreateDate: Optional[dateType]


ActionNameListType = List[ActionNameType]


class AddClientIDToOpenIDConnectProviderRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    ClientID: clientIDType


class AddRoleToInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    RoleName: roleNameType


class AddUserToGroupRequest(ServiceRequest):
    GroupName: groupNameType
    UserName: existingUserNameType


ArnListType = List[arnType]


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
    PermissionsBoundaryType: Optional[PermissionsBoundaryAttachmentType]
    PermissionsBoundaryArn: Optional[arnType]


class AttachedPolicy(TypedDict, total=False):
    PolicyName: Optional[policyNameType]
    PolicyArn: Optional[arnType]


BootstrapDatum = bytes
CertificationMapType = Dict[CertificationKeyType, CertificationValueType]


class ChangePasswordRequest(ServiceRequest):
    OldPassword: passwordType
    NewPassword: passwordType


ContextKeyValueListType = List[ContextKeyValueType]


class ContextEntry(TypedDict, total=False):
    ContextKeyName: Optional[ContextKeyNameType]
    ContextKeyValues: Optional[ContextKeyValueListType]
    ContextKeyType: Optional[ContextKeyTypeEnum]


ContextEntryListType = List[ContextEntry]
ContextKeyNamesResultListType = List[ContextKeyNameType]


class CreateAccessKeyRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]


class CreateAccessKeyResponse(TypedDict, total=False):
    AccessKey: AccessKey


class CreateAccountAliasRequest(ServiceRequest):
    AccountAlias: accountAliasType


class CreateGroupRequest(ServiceRequest):
    Path: Optional[pathType]
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


tagListType = List[Tag]


class CreateInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    Path: Optional[pathType]
    Tags: Optional[tagListType]


class RoleLastUsed(TypedDict, total=False):
    LastUsedDate: Optional[dateType]
    Region: Optional[stringType]


class Role(TypedDict, total=False):
    Path: pathType
    RoleName: roleNameType
    RoleId: idType
    Arn: arnType
    CreateDate: dateType
    AssumeRolePolicyDocument: Optional[policyDocumentType]
    Description: Optional[roleDescriptionType]
    MaxSessionDuration: Optional[roleMaxSessionDurationType]
    PermissionsBoundary: Optional[AttachedPermissionsBoundary]
    Tags: Optional[tagListType]
    RoleLastUsed: Optional[RoleLastUsed]


roleListType = List[Role]


class InstanceProfile(TypedDict, total=False):
    Path: pathType
    InstanceProfileName: instanceProfileNameType
    InstanceProfileId: idType
    Arn: arnType
    CreateDate: dateType
    Roles: roleListType
    Tags: Optional[tagListType]


class CreateInstanceProfileResponse(TypedDict, total=False):
    InstanceProfile: InstanceProfile


class CreateLoginProfileRequest(ServiceRequest):
    UserName: userNameType
    Password: passwordType
    PasswordResetRequired: Optional[booleanType]


class LoginProfile(TypedDict, total=False):
    UserName: userNameType
    CreateDate: dateType
    PasswordResetRequired: Optional[booleanType]


class CreateLoginProfileResponse(TypedDict, total=False):
    LoginProfile: LoginProfile


thumbprintListType = List[thumbprintType]
clientIDListType = List[clientIDType]


class CreateOpenIDConnectProviderRequest(ServiceRequest):
    Url: OpenIDConnectProviderUrlType
    ClientIDList: Optional[clientIDListType]
    ThumbprintList: Optional[thumbprintListType]
    Tags: Optional[tagListType]


class CreateOpenIDConnectProviderResponse(TypedDict, total=False):
    OpenIDConnectProviderArn: Optional[arnType]
    Tags: Optional[tagListType]


class CreatePolicyRequest(ServiceRequest):
    PolicyName: policyNameType
    Path: Optional[policyPathType]
    PolicyDocument: policyDocumentType
    Description: Optional[policyDescriptionType]
    Tags: Optional[tagListType]


class Policy(TypedDict, total=False):
    PolicyName: Optional[policyNameType]
    PolicyId: Optional[idType]
    Arn: Optional[arnType]
    Path: Optional[policyPathType]
    DefaultVersionId: Optional[policyVersionIdType]
    AttachmentCount: Optional[attachmentCountType]
    PermissionsBoundaryUsageCount: Optional[attachmentCountType]
    IsAttachable: Optional[booleanType]
    Description: Optional[policyDescriptionType]
    CreateDate: Optional[dateType]
    UpdateDate: Optional[dateType]
    Tags: Optional[tagListType]


class CreatePolicyResponse(TypedDict, total=False):
    Policy: Optional[Policy]


class CreatePolicyVersionRequest(ServiceRequest):
    PolicyArn: arnType
    PolicyDocument: policyDocumentType
    SetAsDefault: Optional[booleanType]


class PolicyVersion(TypedDict, total=False):
    Document: Optional[policyDocumentType]
    VersionId: Optional[policyVersionIdType]
    IsDefaultVersion: Optional[booleanType]
    CreateDate: Optional[dateType]


class CreatePolicyVersionResponse(TypedDict, total=False):
    PolicyVersion: Optional[PolicyVersion]


class CreateRoleRequest(ServiceRequest):
    Path: Optional[pathType]
    RoleName: roleNameType
    AssumeRolePolicyDocument: policyDocumentType
    Description: Optional[roleDescriptionType]
    MaxSessionDuration: Optional[roleMaxSessionDurationType]
    PermissionsBoundary: Optional[arnType]
    Tags: Optional[tagListType]


class CreateRoleResponse(TypedDict, total=False):
    Role: Role


class CreateSAMLProviderRequest(ServiceRequest):
    SAMLMetadataDocument: SAMLMetadataDocumentType
    Name: SAMLProviderNameType
    Tags: Optional[tagListType]


class CreateSAMLProviderResponse(TypedDict, total=False):
    SAMLProviderArn: Optional[arnType]
    Tags: Optional[tagListType]


class CreateServiceLinkedRoleRequest(ServiceRequest):
    AWSServiceName: groupNameType
    Description: Optional[roleDescriptionType]
    CustomSuffix: Optional[customSuffixType]


class CreateServiceLinkedRoleResponse(TypedDict, total=False):
    Role: Optional[Role]


class CreateServiceSpecificCredentialRequest(ServiceRequest):
    UserName: userNameType
    ServiceName: serviceName


class ServiceSpecificCredential(TypedDict, total=False):
    CreateDate: dateType
    ServiceName: serviceName
    ServiceUserName: serviceUserName
    ServicePassword: servicePassword
    ServiceSpecificCredentialId: serviceSpecificCredentialId
    UserName: userNameType
    Status: statusType


class CreateServiceSpecificCredentialResponse(TypedDict, total=False):
    ServiceSpecificCredential: Optional[ServiceSpecificCredential]


class CreateUserRequest(ServiceRequest):
    Path: Optional[pathType]
    UserName: userNameType
    PermissionsBoundary: Optional[arnType]
    Tags: Optional[tagListType]


class User(TypedDict, total=False):
    Path: pathType
    UserName: userNameType
    UserId: idType
    Arn: arnType
    CreateDate: dateType
    PasswordLastUsed: Optional[dateType]
    PermissionsBoundary: Optional[AttachedPermissionsBoundary]
    Tags: Optional[tagListType]


class CreateUserResponse(TypedDict, total=False):
    User: Optional[User]


class CreateVirtualMFADeviceRequest(ServiceRequest):
    Path: Optional[pathType]
    VirtualMFADeviceName: virtualMFADeviceName
    Tags: Optional[tagListType]


class VirtualMFADevice(TypedDict, total=False):
    SerialNumber: serialNumberType
    Base32StringSeed: Optional[BootstrapDatum]
    QRCodePNG: Optional[BootstrapDatum]
    User: Optional[User]
    EnableDate: Optional[dateType]
    Tags: Optional[tagListType]


class CreateVirtualMFADeviceResponse(TypedDict, total=False):
    VirtualMFADevice: VirtualMFADevice


class DeactivateMFADeviceRequest(ServiceRequest):
    UserName: existingUserNameType
    SerialNumber: serialNumberType


class DeleteAccessKeyRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]
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
    UserName: userNameType


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
    UserName: Optional[userNameType]
    ServiceSpecificCredentialId: serviceSpecificCredentialId


class DeleteSigningCertificateRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]
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
    Region: Optional[RegionNameType]
    Resources: Optional[ArnListType]


RoleUsageListType = List[RoleUsageType]


class DeletionTaskFailureReasonType(TypedDict, total=False):
    Reason: Optional[ReasonType]
    RoleUsageList: Optional[RoleUsageListType]


class DetachGroupPolicyRequest(ServiceRequest):
    GroupName: groupNameType
    PolicyArn: arnType


class DetachRolePolicyRequest(ServiceRequest):
    RoleName: roleNameType
    PolicyArn: arnType


class DetachUserPolicyRequest(ServiceRequest):
    UserName: userNameType
    PolicyArn: arnType


class EnableMFADeviceRequest(ServiceRequest):
    UserName: existingUserNameType
    SerialNumber: serialNumberType
    AuthenticationCode1: authenticationCodeType
    AuthenticationCode2: authenticationCodeType


class EntityInfo(TypedDict, total=False):
    Arn: arnType
    Name: userNameType
    Type: policyOwnerEntityType
    Id: idType
    Path: Optional[pathType]


class EntityDetails(TypedDict, total=False):
    EntityInfo: EntityInfo
    LastAuthenticated: Optional[dateType]


class ErrorDetails(TypedDict, total=False):
    Message: stringType
    Code: stringType


EvalDecisionDetailsType = Dict[EvalDecisionSourceType, PolicyEvaluationDecisionType]


class PermissionsBoundaryDecisionDetail(TypedDict, total=False):
    AllowedByPermissionsBoundary: Optional[booleanType]


class Position(TypedDict, total=False):
    Line: Optional[LineNumber]
    Column: Optional[ColumnNumber]


class Statement(TypedDict, total=False):
    SourcePolicyId: Optional[PolicyIdentifierType]
    SourcePolicyType: Optional[PolicySourceType]
    StartPosition: Optional[Position]
    EndPosition: Optional[Position]


StatementListType = List[Statement]


class ResourceSpecificResult(TypedDict, total=False):
    EvalResourceName: ResourceNameType
    EvalResourceDecision: PolicyEvaluationDecisionType
    MatchedStatements: Optional[StatementListType]
    MissingContextValues: Optional[ContextKeyNamesResultListType]
    EvalDecisionDetails: Optional[EvalDecisionDetailsType]
    PermissionsBoundaryDecisionDetail: Optional[PermissionsBoundaryDecisionDetail]


ResourceSpecificResultListType = List[ResourceSpecificResult]


class OrganizationsDecisionDetail(TypedDict, total=False):
    AllowedByOrganizations: Optional[booleanType]


class EvaluationResult(TypedDict, total=False):
    EvalActionName: ActionNameType
    EvalResourceName: Optional[ResourceNameType]
    EvalDecision: PolicyEvaluationDecisionType
    MatchedStatements: Optional[StatementListType]
    MissingContextValues: Optional[ContextKeyNamesResultListType]
    OrganizationsDecisionDetail: Optional[OrganizationsDecisionDetail]
    PermissionsBoundaryDecisionDetail: Optional[PermissionsBoundaryDecisionDetail]
    EvalDecisionDetails: Optional[EvalDecisionDetailsType]
    ResourceSpecificResults: Optional[ResourceSpecificResultListType]


EvaluationResultsListType = List[EvaluationResult]


class GenerateCredentialReportResponse(TypedDict, total=False):
    State: Optional[ReportStateType]
    Description: Optional[ReportStateDescriptionType]


class GenerateOrganizationsAccessReportRequest(ServiceRequest):
    EntityPath: organizationsEntityPathType
    OrganizationsPolicyId: Optional[organizationsPolicyIdType]


class GenerateOrganizationsAccessReportResponse(TypedDict, total=False):
    JobId: Optional[jobIDType]


class GenerateServiceLastAccessedDetailsRequest(ServiceRequest):
    Arn: arnType
    Granularity: Optional[AccessAdvisorUsageGranularityType]


class GenerateServiceLastAccessedDetailsResponse(TypedDict, total=False):
    JobId: Optional[jobIDType]


class GetAccessKeyLastUsedRequest(ServiceRequest):
    AccessKeyId: accessKeyIdType


class GetAccessKeyLastUsedResponse(TypedDict, total=False):
    UserName: Optional[existingUserNameType]
    AccessKeyLastUsed: Optional[AccessKeyLastUsed]


entityListType = List[EntityType]


class GetAccountAuthorizationDetailsRequest(ServiceRequest):
    Filter: Optional[entityListType]
    MaxItems: Optional[maxItemsType]
    Marker: Optional[markerType]


policyDocumentVersionListType = List[PolicyVersion]


class ManagedPolicyDetail(TypedDict, total=False):
    PolicyName: Optional[policyNameType]
    PolicyId: Optional[idType]
    Arn: Optional[arnType]
    Path: Optional[policyPathType]
    DefaultVersionId: Optional[policyVersionIdType]
    AttachmentCount: Optional[attachmentCountType]
    PermissionsBoundaryUsageCount: Optional[attachmentCountType]
    IsAttachable: Optional[booleanType]
    Description: Optional[policyDescriptionType]
    CreateDate: Optional[dateType]
    UpdateDate: Optional[dateType]
    PolicyVersionList: Optional[policyDocumentVersionListType]


ManagedPolicyDetailListType = List[ManagedPolicyDetail]
attachedPoliciesListType = List[AttachedPolicy]


class PolicyDetail(TypedDict, total=False):
    PolicyName: Optional[policyNameType]
    PolicyDocument: Optional[policyDocumentType]


policyDetailListType = List[PolicyDetail]
instanceProfileListType = List[InstanceProfile]


class RoleDetail(TypedDict, total=False):
    Path: Optional[pathType]
    RoleName: Optional[roleNameType]
    RoleId: Optional[idType]
    Arn: Optional[arnType]
    CreateDate: Optional[dateType]
    AssumeRolePolicyDocument: Optional[policyDocumentType]
    InstanceProfileList: Optional[instanceProfileListType]
    RolePolicyList: Optional[policyDetailListType]
    AttachedManagedPolicies: Optional[attachedPoliciesListType]
    PermissionsBoundary: Optional[AttachedPermissionsBoundary]
    Tags: Optional[tagListType]
    RoleLastUsed: Optional[RoleLastUsed]


roleDetailListType = List[RoleDetail]


class GroupDetail(TypedDict, total=False):
    Path: Optional[pathType]
    GroupName: Optional[groupNameType]
    GroupId: Optional[idType]
    Arn: Optional[arnType]
    CreateDate: Optional[dateType]
    GroupPolicyList: Optional[policyDetailListType]
    AttachedManagedPolicies: Optional[attachedPoliciesListType]


groupDetailListType = List[GroupDetail]
groupNameListType = List[groupNameType]


class UserDetail(TypedDict, total=False):
    Path: Optional[pathType]
    UserName: Optional[userNameType]
    UserId: Optional[idType]
    Arn: Optional[arnType]
    CreateDate: Optional[dateType]
    UserPolicyList: Optional[policyDetailListType]
    GroupList: Optional[groupNameListType]
    AttachedManagedPolicies: Optional[attachedPoliciesListType]
    PermissionsBoundary: Optional[AttachedPermissionsBoundary]
    Tags: Optional[tagListType]


userDetailListType = List[UserDetail]


class GetAccountAuthorizationDetailsResponse(TypedDict, total=False):
    UserDetailList: Optional[userDetailListType]
    GroupDetailList: Optional[groupDetailListType]
    RoleDetailList: Optional[roleDetailListType]
    Policies: Optional[ManagedPolicyDetailListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class PasswordPolicy(TypedDict, total=False):
    MinimumPasswordLength: Optional[minimumPasswordLengthType]
    RequireSymbols: Optional[booleanType]
    RequireNumbers: Optional[booleanType]
    RequireUppercaseCharacters: Optional[booleanType]
    RequireLowercaseCharacters: Optional[booleanType]
    AllowUsersToChangePassword: Optional[booleanType]
    ExpirePasswords: Optional[booleanType]
    MaxPasswordAge: Optional[maxPasswordAgeType]
    PasswordReusePrevention: Optional[passwordReusePreventionType]
    HardExpiry: Optional[booleanObjectType]


class GetAccountPasswordPolicyResponse(TypedDict, total=False):
    PasswordPolicy: PasswordPolicy


summaryMapType = Dict[summaryKeyType, summaryValueType]


class GetAccountSummaryResponse(TypedDict, total=False):
    SummaryMap: Optional[summaryMapType]


SimulationPolicyListType = List[policyDocumentType]


class GetContextKeysForCustomPolicyRequest(ServiceRequest):
    PolicyInputList: SimulationPolicyListType


class GetContextKeysForPolicyResponse(TypedDict, total=False):
    ContextKeyNames: Optional[ContextKeyNamesResultListType]


class GetContextKeysForPrincipalPolicyRequest(ServiceRequest):
    PolicySourceArn: arnType
    PolicyInputList: Optional[SimulationPolicyListType]


ReportContentType = bytes


class GetCredentialReportResponse(TypedDict, total=False):
    Content: Optional[ReportContentType]
    ReportFormat: Optional[ReportFormatType]
    GeneratedTime: Optional[dateType]


class GetGroupPolicyRequest(ServiceRequest):
    GroupName: groupNameType
    PolicyName: policyNameType


class GetGroupPolicyResponse(TypedDict, total=False):
    GroupName: groupNameType
    PolicyName: policyNameType
    PolicyDocument: policyDocumentType


class GetGroupRequest(ServiceRequest):
    GroupName: groupNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


userListType = List[User]


class GetGroupResponse(TypedDict, total=False):
    Group: Group
    Users: userListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class GetInstanceProfileRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType


class GetInstanceProfileResponse(TypedDict, total=False):
    InstanceProfile: InstanceProfile


class GetLoginProfileRequest(ServiceRequest):
    UserName: userNameType


class GetLoginProfileResponse(TypedDict, total=False):
    LoginProfile: LoginProfile


class GetMFADeviceRequest(ServiceRequest):
    SerialNumber: serialNumberType
    UserName: Optional[userNameType]


class GetMFADeviceResponse(TypedDict, total=False):
    UserName: Optional[userNameType]
    SerialNumber: serialNumberType
    EnableDate: Optional[dateType]
    Certifications: Optional[CertificationMapType]


class GetOpenIDConnectProviderRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType


class GetOpenIDConnectProviderResponse(TypedDict, total=False):
    Url: Optional[OpenIDConnectProviderUrlType]
    ClientIDList: Optional[clientIDListType]
    ThumbprintList: Optional[thumbprintListType]
    CreateDate: Optional[dateType]
    Tags: Optional[tagListType]


class GetOrganizationsAccessReportRequest(ServiceRequest):
    JobId: jobIDType
    MaxItems: Optional[maxItemsType]
    Marker: Optional[markerType]
    SortKey: Optional[sortKeyType]


class GetOrganizationsAccessReportResponse(TypedDict, total=False):
    JobStatus: jobStatusType
    JobCreationDate: dateType
    JobCompletionDate: Optional[dateType]
    NumberOfServicesAccessible: Optional[integerType]
    NumberOfServicesNotAccessed: Optional[integerType]
    AccessDetails: Optional[AccessDetails]
    IsTruncated: Optional[booleanType]
    Marker: Optional[markerType]
    ErrorDetails: Optional[ErrorDetails]


class GetPolicyRequest(ServiceRequest):
    PolicyArn: arnType


class GetPolicyResponse(TypedDict, total=False):
    Policy: Optional[Policy]


class GetPolicyVersionRequest(ServiceRequest):
    PolicyArn: arnType
    VersionId: policyVersionIdType


class GetPolicyVersionResponse(TypedDict, total=False):
    PolicyVersion: Optional[PolicyVersion]


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


class GetSAMLProviderResponse(TypedDict, total=False):
    SAMLMetadataDocument: Optional[SAMLMetadataDocumentType]
    CreateDate: Optional[dateType]
    ValidUntil: Optional[dateType]
    Tags: Optional[tagListType]


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
    UploadDate: Optional[dateType]


class GetSSHPublicKeyResponse(TypedDict, total=False):
    SSHPublicKey: Optional[SSHPublicKey]


class GetServerCertificateRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType


class ServerCertificateMetadata(TypedDict, total=False):
    Path: pathType
    ServerCertificateName: serverCertificateNameType
    ServerCertificateId: idType
    Arn: arnType
    UploadDate: Optional[dateType]
    Expiration: Optional[dateType]


class ServerCertificate(TypedDict, total=False):
    ServerCertificateMetadata: ServerCertificateMetadata
    CertificateBody: certificateBodyType
    CertificateChain: Optional[certificateChainType]
    Tags: Optional[tagListType]


class GetServerCertificateResponse(TypedDict, total=False):
    ServerCertificate: ServerCertificate


class GetServiceLastAccessedDetailsRequest(ServiceRequest):
    JobId: jobIDType
    MaxItems: Optional[maxItemsType]
    Marker: Optional[markerType]


class TrackedActionLastAccessed(TypedDict, total=False):
    ActionName: Optional[stringType]
    LastAccessedEntity: Optional[arnType]
    LastAccessedTime: Optional[dateType]
    LastAccessedRegion: Optional[stringType]


TrackedActionsLastAccessed = List[TrackedActionLastAccessed]


class ServiceLastAccessed(TypedDict, total=False):
    ServiceName: serviceNameType
    LastAuthenticated: Optional[dateType]
    ServiceNamespace: serviceNamespaceType
    LastAuthenticatedEntity: Optional[arnType]
    LastAuthenticatedRegion: Optional[stringType]
    TotalAuthenticatedEntities: Optional[integerType]
    TrackedActionsLastAccessed: Optional[TrackedActionsLastAccessed]


ServicesLastAccessed = List[ServiceLastAccessed]


class GetServiceLastAccessedDetailsResponse(TypedDict, total=False):
    JobStatus: jobStatusType
    JobType: Optional[AccessAdvisorUsageGranularityType]
    JobCreationDate: dateType
    ServicesLastAccessed: ServicesLastAccessed
    JobCompletionDate: dateType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]
    Error: Optional[ErrorDetails]


class GetServiceLastAccessedDetailsWithEntitiesRequest(ServiceRequest):
    JobId: jobIDType
    ServiceNamespace: serviceNamespaceType
    MaxItems: Optional[maxItemsType]
    Marker: Optional[markerType]


entityDetailsListType = List[EntityDetails]


class GetServiceLastAccessedDetailsWithEntitiesResponse(TypedDict, total=False):
    JobStatus: jobStatusType
    JobCreationDate: dateType
    JobCompletionDate: dateType
    EntityDetailsList: entityDetailsListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]
    Error: Optional[ErrorDetails]


class GetServiceLinkedRoleDeletionStatusRequest(ServiceRequest):
    DeletionTaskId: DeletionTaskIdType


class GetServiceLinkedRoleDeletionStatusResponse(TypedDict, total=False):
    Status: DeletionTaskStatusType
    Reason: Optional[DeletionTaskFailureReasonType]


class GetUserPolicyRequest(ServiceRequest):
    UserName: existingUserNameType
    PolicyName: policyNameType


class GetUserPolicyResponse(TypedDict, total=False):
    UserName: existingUserNameType
    PolicyName: policyNameType
    PolicyDocument: policyDocumentType


class GetUserRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]


class GetUserResponse(TypedDict, total=False):
    User: User


class ListAccessKeysRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


accessKeyMetadataListType = List[AccessKeyMetadata]


class ListAccessKeysResponse(TypedDict, total=False):
    AccessKeyMetadata: accessKeyMetadataListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListAccountAliasesRequest(ServiceRequest):
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


accountAliasListType = List[accountAliasType]


class ListAccountAliasesResponse(TypedDict, total=False):
    AccountAliases: accountAliasListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListAttachedGroupPoliciesRequest(ServiceRequest):
    GroupName: groupNameType
    PathPrefix: Optional[policyPathType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListAttachedGroupPoliciesResponse(TypedDict, total=False):
    AttachedPolicies: Optional[attachedPoliciesListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListAttachedRolePoliciesRequest(ServiceRequest):
    RoleName: roleNameType
    PathPrefix: Optional[policyPathType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListAttachedRolePoliciesResponse(TypedDict, total=False):
    AttachedPolicies: Optional[attachedPoliciesListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListAttachedUserPoliciesRequest(ServiceRequest):
    UserName: userNameType
    PathPrefix: Optional[policyPathType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListAttachedUserPoliciesResponse(TypedDict, total=False):
    AttachedPolicies: Optional[attachedPoliciesListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListEntitiesForPolicyRequest(ServiceRequest):
    PolicyArn: arnType
    EntityFilter: Optional[EntityType]
    PathPrefix: Optional[pathType]
    PolicyUsageFilter: Optional[PolicyUsageType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class PolicyRole(TypedDict, total=False):
    RoleName: Optional[roleNameType]
    RoleId: Optional[idType]


PolicyRoleListType = List[PolicyRole]


class PolicyUser(TypedDict, total=False):
    UserName: Optional[userNameType]
    UserId: Optional[idType]


PolicyUserListType = List[PolicyUser]


class PolicyGroup(TypedDict, total=False):
    GroupName: Optional[groupNameType]
    GroupId: Optional[idType]


PolicyGroupListType = List[PolicyGroup]


class ListEntitiesForPolicyResponse(TypedDict, total=False):
    PolicyGroups: Optional[PolicyGroupListType]
    PolicyUsers: Optional[PolicyUserListType]
    PolicyRoles: Optional[PolicyRoleListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListGroupPoliciesRequest(ServiceRequest):
    GroupName: groupNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


policyNameListType = List[policyNameType]


class ListGroupPoliciesResponse(TypedDict, total=False):
    PolicyNames: policyNameListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListGroupsForUserRequest(ServiceRequest):
    UserName: existingUserNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


groupListType = List[Group]


class ListGroupsForUserResponse(TypedDict, total=False):
    Groups: groupListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListGroupsRequest(ServiceRequest):
    PathPrefix: Optional[pathPrefixType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListGroupsResponse(TypedDict, total=False):
    Groups: groupListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListInstanceProfileTagsRequest(ServiceRequest):
    InstanceProfileName: instanceProfileNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListInstanceProfileTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListInstanceProfilesForRoleRequest(ServiceRequest):
    RoleName: roleNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListInstanceProfilesForRoleResponse(TypedDict, total=False):
    InstanceProfiles: instanceProfileListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListInstanceProfilesRequest(ServiceRequest):
    PathPrefix: Optional[pathPrefixType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListInstanceProfilesResponse(TypedDict, total=False):
    InstanceProfiles: instanceProfileListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListMFADeviceTagsRequest(ServiceRequest):
    SerialNumber: serialNumberType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListMFADeviceTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListMFADevicesRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class MFADevice(TypedDict, total=False):
    UserName: userNameType
    SerialNumber: serialNumberType
    EnableDate: dateType


mfaDeviceListType = List[MFADevice]


class ListMFADevicesResponse(TypedDict, total=False):
    MFADevices: mfaDeviceListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListOpenIDConnectProviderTagsRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListOpenIDConnectProviderTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListOpenIDConnectProvidersRequest(ServiceRequest):
    pass


class OpenIDConnectProviderListEntry(TypedDict, total=False):
    Arn: Optional[arnType]


OpenIDConnectProviderListType = List[OpenIDConnectProviderListEntry]


class ListOpenIDConnectProvidersResponse(TypedDict, total=False):
    OpenIDConnectProviderList: Optional[OpenIDConnectProviderListType]


class PolicyGrantingServiceAccess(TypedDict, total=False):
    PolicyName: policyNameType
    PolicyType: policyType
    PolicyArn: Optional[arnType]
    EntityType: Optional[policyOwnerEntityType]
    EntityName: Optional[entityNameType]


policyGrantingServiceAccessListType = List[PolicyGrantingServiceAccess]


class ListPoliciesGrantingServiceAccessEntry(TypedDict, total=False):
    ServiceNamespace: Optional[serviceNamespaceType]
    Policies: Optional[policyGrantingServiceAccessListType]


serviceNamespaceListType = List[serviceNamespaceType]


class ListPoliciesGrantingServiceAccessRequest(ServiceRequest):
    Marker: Optional[markerType]
    Arn: arnType
    ServiceNamespaces: serviceNamespaceListType


listPolicyGrantingServiceAccessResponseListType = List[ListPoliciesGrantingServiceAccessEntry]


class ListPoliciesGrantingServiceAccessResponse(TypedDict, total=False):
    PoliciesGrantingServiceAccess: listPolicyGrantingServiceAccessResponseListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListPoliciesRequest(ServiceRequest):
    Scope: Optional[policyScopeType]
    OnlyAttached: Optional[booleanType]
    PathPrefix: Optional[policyPathType]
    PolicyUsageFilter: Optional[PolicyUsageType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


policyListType = List[Policy]


class ListPoliciesResponse(TypedDict, total=False):
    Policies: Optional[policyListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListPolicyTagsRequest(ServiceRequest):
    PolicyArn: arnType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListPolicyTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListPolicyVersionsRequest(ServiceRequest):
    PolicyArn: arnType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListPolicyVersionsResponse(TypedDict, total=False):
    Versions: Optional[policyDocumentVersionListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListRolePoliciesRequest(ServiceRequest):
    RoleName: roleNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListRolePoliciesResponse(TypedDict, total=False):
    PolicyNames: policyNameListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListRoleTagsRequest(ServiceRequest):
    RoleName: roleNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListRoleTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListRolesRequest(ServiceRequest):
    PathPrefix: Optional[pathPrefixType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListRolesResponse(TypedDict, total=False):
    Roles: roleListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListSAMLProviderTagsRequest(ServiceRequest):
    SAMLProviderArn: arnType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListSAMLProviderTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListSAMLProvidersRequest(ServiceRequest):
    pass


class SAMLProviderListEntry(TypedDict, total=False):
    Arn: Optional[arnType]
    ValidUntil: Optional[dateType]
    CreateDate: Optional[dateType]


SAMLProviderListType = List[SAMLProviderListEntry]


class ListSAMLProvidersResponse(TypedDict, total=False):
    SAMLProviderList: Optional[SAMLProviderListType]


class ListSSHPublicKeysRequest(ServiceRequest):
    UserName: Optional[userNameType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class SSHPublicKeyMetadata(TypedDict, total=False):
    UserName: userNameType
    SSHPublicKeyId: publicKeyIdType
    Status: statusType
    UploadDate: dateType


SSHPublicKeyListType = List[SSHPublicKeyMetadata]


class ListSSHPublicKeysResponse(TypedDict, total=False):
    SSHPublicKeys: Optional[SSHPublicKeyListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListServerCertificateTagsRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListServerCertificateTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListServerCertificatesRequest(ServiceRequest):
    PathPrefix: Optional[pathPrefixType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


serverCertificateMetadataListType = List[ServerCertificateMetadata]


class ListServerCertificatesResponse(TypedDict, total=False):
    ServerCertificateMetadataList: serverCertificateMetadataListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListServiceSpecificCredentialsRequest(ServiceRequest):
    UserName: Optional[userNameType]
    ServiceName: Optional[serviceName]


class ServiceSpecificCredentialMetadata(TypedDict, total=False):
    UserName: userNameType
    Status: statusType
    ServiceUserName: serviceUserName
    CreateDate: dateType
    ServiceSpecificCredentialId: serviceSpecificCredentialId
    ServiceName: serviceName


ServiceSpecificCredentialsListType = List[ServiceSpecificCredentialMetadata]


class ListServiceSpecificCredentialsResponse(TypedDict, total=False):
    ServiceSpecificCredentials: Optional[ServiceSpecificCredentialsListType]


class ListSigningCertificatesRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class SigningCertificate(TypedDict, total=False):
    UserName: userNameType
    CertificateId: certificateIdType
    CertificateBody: certificateBodyType
    Status: statusType
    UploadDate: Optional[dateType]


certificateListType = List[SigningCertificate]


class ListSigningCertificatesResponse(TypedDict, total=False):
    Certificates: certificateListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListUserPoliciesRequest(ServiceRequest):
    UserName: existingUserNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListUserPoliciesResponse(TypedDict, total=False):
    PolicyNames: policyNameListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListUserTagsRequest(ServiceRequest):
    UserName: existingUserNameType
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListUserTagsResponse(TypedDict, total=False):
    Tags: tagListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListUsersRequest(ServiceRequest):
    PathPrefix: Optional[pathPrefixType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


class ListUsersResponse(TypedDict, total=False):
    Users: userListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class ListVirtualMFADevicesRequest(ServiceRequest):
    AssignmentStatus: Optional[assignmentStatusType]
    Marker: Optional[markerType]
    MaxItems: Optional[maxItemsType]


virtualMFADeviceListType = List[VirtualMFADevice]


class ListVirtualMFADevicesResponse(TypedDict, total=False):
    VirtualMFADevices: virtualMFADeviceListType
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


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
    UserName: Optional[userNameType]
    ServiceSpecificCredentialId: serviceSpecificCredentialId


class ResetServiceSpecificCredentialResponse(TypedDict, total=False):
    ServiceSpecificCredential: Optional[ServiceSpecificCredential]


ResourceNameListType = List[ResourceNameType]


class ResyncMFADeviceRequest(ServiceRequest):
    UserName: existingUserNameType
    SerialNumber: serialNumberType
    AuthenticationCode1: authenticationCodeType
    AuthenticationCode2: authenticationCodeType


class SetDefaultPolicyVersionRequest(ServiceRequest):
    PolicyArn: arnType
    VersionId: policyVersionIdType


class SetSecurityTokenServicePreferencesRequest(ServiceRequest):
    GlobalEndpointTokenVersion: globalEndpointTokenVersion


class SimulateCustomPolicyRequest(ServiceRequest):
    PolicyInputList: SimulationPolicyListType
    PermissionsBoundaryPolicyInputList: Optional[SimulationPolicyListType]
    ActionNames: ActionNameListType
    ResourceArns: Optional[ResourceNameListType]
    ResourcePolicy: Optional[policyDocumentType]
    ResourceOwner: Optional[ResourceNameType]
    CallerArn: Optional[ResourceNameType]
    ContextEntries: Optional[ContextEntryListType]
    ResourceHandlingOption: Optional[ResourceHandlingOptionType]
    MaxItems: Optional[maxItemsType]
    Marker: Optional[markerType]


class SimulatePolicyResponse(TypedDict, total=False):
    EvaluationResults: Optional[EvaluationResultsListType]
    IsTruncated: Optional[booleanType]
    Marker: Optional[responseMarkerType]


class SimulatePrincipalPolicyRequest(ServiceRequest):
    PolicySourceArn: arnType
    PolicyInputList: Optional[SimulationPolicyListType]
    PermissionsBoundaryPolicyInputList: Optional[SimulationPolicyListType]
    ActionNames: ActionNameListType
    ResourceArns: Optional[ResourceNameListType]
    ResourcePolicy: Optional[policyDocumentType]
    ResourceOwner: Optional[ResourceNameType]
    CallerArn: Optional[ResourceNameType]
    ContextEntries: Optional[ContextEntryListType]
    ResourceHandlingOption: Optional[ResourceHandlingOptionType]
    MaxItems: Optional[maxItemsType]
    Marker: Optional[markerType]


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


tagKeyListType = List[tagKeyType]


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
    UserName: Optional[existingUserNameType]
    AccessKeyId: accessKeyIdType
    Status: statusType


class UpdateAccountPasswordPolicyRequest(ServiceRequest):
    MinimumPasswordLength: Optional[minimumPasswordLengthType]
    RequireSymbols: Optional[booleanType]
    RequireNumbers: Optional[booleanType]
    RequireUppercaseCharacters: Optional[booleanType]
    RequireLowercaseCharacters: Optional[booleanType]
    AllowUsersToChangePassword: Optional[booleanType]
    MaxPasswordAge: Optional[maxPasswordAgeType]
    PasswordReusePrevention: Optional[passwordReusePreventionType]
    HardExpiry: Optional[booleanObjectType]


class UpdateAssumeRolePolicyRequest(ServiceRequest):
    RoleName: roleNameType
    PolicyDocument: policyDocumentType


class UpdateGroupRequest(ServiceRequest):
    GroupName: groupNameType
    NewPath: Optional[pathType]
    NewGroupName: Optional[groupNameType]


class UpdateLoginProfileRequest(ServiceRequest):
    UserName: userNameType
    Password: Optional[passwordType]
    PasswordResetRequired: Optional[booleanObjectType]


class UpdateOpenIDConnectProviderThumbprintRequest(ServiceRequest):
    OpenIDConnectProviderArn: arnType
    ThumbprintList: thumbprintListType


class UpdateRoleDescriptionRequest(ServiceRequest):
    RoleName: roleNameType
    Description: roleDescriptionType


class UpdateRoleDescriptionResponse(TypedDict, total=False):
    Role: Optional[Role]


class UpdateRoleRequest(ServiceRequest):
    RoleName: roleNameType
    Description: Optional[roleDescriptionType]
    MaxSessionDuration: Optional[roleMaxSessionDurationType]


class UpdateRoleResponse(TypedDict, total=False):
    pass


class UpdateSAMLProviderRequest(ServiceRequest):
    SAMLMetadataDocument: SAMLMetadataDocumentType
    SAMLProviderArn: arnType


class UpdateSAMLProviderResponse(TypedDict, total=False):
    SAMLProviderArn: Optional[arnType]


class UpdateSSHPublicKeyRequest(ServiceRequest):
    UserName: userNameType
    SSHPublicKeyId: publicKeyIdType
    Status: statusType


class UpdateServerCertificateRequest(ServiceRequest):
    ServerCertificateName: serverCertificateNameType
    NewPath: Optional[pathType]
    NewServerCertificateName: Optional[serverCertificateNameType]


class UpdateServiceSpecificCredentialRequest(ServiceRequest):
    UserName: Optional[userNameType]
    ServiceSpecificCredentialId: serviceSpecificCredentialId
    Status: statusType


class UpdateSigningCertificateRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]
    CertificateId: certificateIdType
    Status: statusType


class UpdateUserRequest(ServiceRequest):
    UserName: existingUserNameType
    NewPath: Optional[pathType]
    NewUserName: Optional[userNameType]


class UploadSSHPublicKeyRequest(ServiceRequest):
    UserName: userNameType
    SSHPublicKeyBody: publicKeyMaterialType


class UploadSSHPublicKeyResponse(TypedDict, total=False):
    SSHPublicKey: Optional[SSHPublicKey]


class UploadServerCertificateRequest(ServiceRequest):
    Path: Optional[pathType]
    ServerCertificateName: serverCertificateNameType
    CertificateBody: certificateBodyType
    PrivateKey: privateKeyType
    CertificateChain: Optional[certificateChainType]
    Tags: Optional[tagListType]


class UploadServerCertificateResponse(TypedDict, total=False):
    ServerCertificateMetadata: Optional[ServerCertificateMetadata]
    Tags: Optional[tagListType]


class UploadSigningCertificateRequest(ServiceRequest):
    UserName: Optional[existingUserNameType]
    CertificateBody: certificateBodyType


class UploadSigningCertificateResponse(TypedDict, total=False):
    Certificate: SigningCertificate


class IamApi:
    service = "iam"
    version = "2010-05-08"

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
        self, context: RequestContext, user_name: existingUserNameType = None, **kwargs
    ) -> CreateAccessKeyResponse:
        raise NotImplementedError

    @handler("CreateAccountAlias")
    def create_account_alias(
        self, context: RequestContext, account_alias: accountAliasType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("CreateGroup")
    def create_group(
        self, context: RequestContext, group_name: groupNameType, path: pathType = None, **kwargs
    ) -> CreateGroupResponse:
        raise NotImplementedError

    @handler("CreateInstanceProfile")
    def create_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        path: pathType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateInstanceProfileResponse:
        raise NotImplementedError

    @handler("CreateLoginProfile")
    def create_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType,
        password: passwordType,
        password_reset_required: booleanType = None,
        **kwargs,
    ) -> CreateLoginProfileResponse:
        raise NotImplementedError

    @handler("CreateOpenIDConnectProvider")
    def create_open_id_connect_provider(
        self,
        context: RequestContext,
        url: OpenIDConnectProviderUrlType,
        client_id_list: clientIDListType = None,
        thumbprint_list: thumbprintListType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateOpenIDConnectProviderResponse:
        raise NotImplementedError

    @handler("CreatePolicy")
    def create_policy(
        self,
        context: RequestContext,
        policy_name: policyNameType,
        policy_document: policyDocumentType,
        path: policyPathType = None,
        description: policyDescriptionType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreatePolicyResponse:
        raise NotImplementedError

    @handler("CreatePolicyVersion")
    def create_policy_version(
        self,
        context: RequestContext,
        policy_arn: arnType,
        policy_document: policyDocumentType,
        set_as_default: booleanType = None,
        **kwargs,
    ) -> CreatePolicyVersionResponse:
        raise NotImplementedError

    @handler("CreateRole")
    def create_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        assume_role_policy_document: policyDocumentType,
        path: pathType = None,
        description: roleDescriptionType = None,
        max_session_duration: roleMaxSessionDurationType = None,
        permissions_boundary: arnType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateRoleResponse:
        raise NotImplementedError

    @handler("CreateSAMLProvider")
    def create_saml_provider(
        self,
        context: RequestContext,
        saml_metadata_document: SAMLMetadataDocumentType,
        name: SAMLProviderNameType,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateSAMLProviderResponse:
        raise NotImplementedError

    @handler("CreateServiceLinkedRole")
    def create_service_linked_role(
        self,
        context: RequestContext,
        aws_service_name: groupNameType,
        description: roleDescriptionType = None,
        custom_suffix: customSuffixType = None,
        **kwargs,
    ) -> CreateServiceLinkedRoleResponse:
        raise NotImplementedError

    @handler("CreateServiceSpecificCredential")
    def create_service_specific_credential(
        self, context: RequestContext, user_name: userNameType, service_name: serviceName, **kwargs
    ) -> CreateServiceSpecificCredentialResponse:
        raise NotImplementedError

    @handler("CreateUser")
    def create_user(
        self,
        context: RequestContext,
        user_name: userNameType,
        path: pathType = None,
        permissions_boundary: arnType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateUserResponse:
        raise NotImplementedError

    @handler("CreateVirtualMFADevice")
    def create_virtual_mfa_device(
        self,
        context: RequestContext,
        virtual_mfa_device_name: virtualMFADeviceName,
        path: pathType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateVirtualMFADeviceResponse:
        raise NotImplementedError

    @handler("DeactivateMFADevice")
    def deactivate_mfa_device(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        serial_number: serialNumberType,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessKey")
    def delete_access_key(
        self,
        context: RequestContext,
        access_key_id: accessKeyIdType,
        user_name: existingUserNameType = None,
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
        self, context: RequestContext, user_name: userNameType, **kwargs
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
        user_name: userNameType = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSigningCertificate")
    def delete_signing_certificate(
        self,
        context: RequestContext,
        certificate_id: certificateIdType,
        user_name: existingUserNameType = None,
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
        organizations_policy_id: organizationsPolicyIdType = None,
        **kwargs,
    ) -> GenerateOrganizationsAccessReportResponse:
        raise NotImplementedError

    @handler("GenerateServiceLastAccessedDetails")
    def generate_service_last_accessed_details(
        self,
        context: RequestContext,
        arn: arnType,
        granularity: AccessAdvisorUsageGranularityType = None,
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
        filter: entityListType = None,
        max_items: maxItemsType = None,
        marker: markerType = None,
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
        policy_input_list: SimulationPolicyListType = None,
        **kwargs,
    ) -> GetContextKeysForPolicyResponse:
        raise NotImplementedError

    @handler("GetCredentialReport")
    def get_credential_report(
        self, context: RequestContext, **kwargs
    ) -> GetCredentialReportResponse:
        raise NotImplementedError

    @handler("GetGroup")
    def get_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
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

    @handler("GetInstanceProfile")
    def get_instance_profile(
        self, context: RequestContext, instance_profile_name: instanceProfileNameType, **kwargs
    ) -> GetInstanceProfileResponse:
        raise NotImplementedError

    @handler("GetLoginProfile")
    def get_login_profile(
        self, context: RequestContext, user_name: userNameType, **kwargs
    ) -> GetLoginProfileResponse:
        raise NotImplementedError

    @handler("GetMFADevice")
    def get_mfa_device(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        user_name: userNameType = None,
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
        max_items: maxItemsType = None,
        marker: markerType = None,
        sort_key: sortKeyType = None,
        **kwargs,
    ) -> GetOrganizationsAccessReportResponse:
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
        max_items: maxItemsType = None,
        marker: markerType = None,
        **kwargs,
    ) -> GetServiceLastAccessedDetailsResponse:
        raise NotImplementedError

    @handler("GetServiceLastAccessedDetailsWithEntities")
    def get_service_last_accessed_details_with_entities(
        self,
        context: RequestContext,
        job_id: jobIDType,
        service_namespace: serviceNamespaceType,
        max_items: maxItemsType = None,
        marker: markerType = None,
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
        self, context: RequestContext, user_name: existingUserNameType = None, **kwargs
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
        user_name: existingUserNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAccessKeysResponse:
        raise NotImplementedError

    @handler("ListAccountAliases")
    def list_account_aliases(
        self,
        context: RequestContext,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAccountAliasesResponse:
        raise NotImplementedError

    @handler("ListAttachedGroupPolicies")
    def list_attached_group_policies(
        self,
        context: RequestContext,
        group_name: groupNameType,
        path_prefix: policyPathType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAttachedGroupPoliciesResponse:
        raise NotImplementedError

    @handler("ListAttachedRolePolicies")
    def list_attached_role_policies(
        self,
        context: RequestContext,
        role_name: roleNameType,
        path_prefix: policyPathType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAttachedRolePoliciesResponse:
        raise NotImplementedError

    @handler("ListAttachedUserPolicies")
    def list_attached_user_policies(
        self,
        context: RequestContext,
        user_name: userNameType,
        path_prefix: policyPathType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListAttachedUserPoliciesResponse:
        raise NotImplementedError

    @handler("ListEntitiesForPolicy")
    def list_entities_for_policy(
        self,
        context: RequestContext,
        policy_arn: arnType,
        entity_filter: EntityType = None,
        path_prefix: pathType = None,
        policy_usage_filter: PolicyUsageType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListEntitiesForPolicyResponse:
        raise NotImplementedError

    @handler("ListGroupPolicies")
    def list_group_policies(
        self,
        context: RequestContext,
        group_name: groupNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListGroupPoliciesResponse:
        raise NotImplementedError

    @handler("ListGroups")
    def list_groups(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListGroupsResponse:
        raise NotImplementedError

    @handler("ListGroupsForUser")
    def list_groups_for_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListGroupsForUserResponse:
        raise NotImplementedError

    @handler("ListInstanceProfileTags")
    def list_instance_profile_tags(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListInstanceProfileTagsResponse:
        raise NotImplementedError

    @handler("ListInstanceProfiles")
    def list_instance_profiles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListInstanceProfilesResponse:
        raise NotImplementedError

    @handler("ListInstanceProfilesForRole")
    def list_instance_profiles_for_role(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListInstanceProfilesForRoleResponse:
        raise NotImplementedError

    @handler("ListMFADeviceTags")
    def list_mfa_device_tags(
        self,
        context: RequestContext,
        serial_number: serialNumberType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListMFADeviceTagsResponse:
        raise NotImplementedError

    @handler("ListMFADevices")
    def list_mfa_devices(
        self,
        context: RequestContext,
        user_name: existingUserNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListMFADevicesResponse:
        raise NotImplementedError

    @handler("ListOpenIDConnectProviderTags")
    def list_open_id_connect_provider_tags(
        self,
        context: RequestContext,
        open_id_connect_provider_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListOpenIDConnectProviderTagsResponse:
        raise NotImplementedError

    @handler("ListOpenIDConnectProviders")
    def list_open_id_connect_providers(
        self, context: RequestContext, **kwargs
    ) -> ListOpenIDConnectProvidersResponse:
        raise NotImplementedError

    @handler("ListPolicies")
    def list_policies(
        self,
        context: RequestContext,
        scope: policyScopeType = None,
        only_attached: booleanType = None,
        path_prefix: policyPathType = None,
        policy_usage_filter: PolicyUsageType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPoliciesResponse:
        raise NotImplementedError

    @handler("ListPoliciesGrantingServiceAccess")
    def list_policies_granting_service_access(
        self,
        context: RequestContext,
        arn: arnType,
        service_namespaces: serviceNamespaceListType,
        marker: markerType = None,
        **kwargs,
    ) -> ListPoliciesGrantingServiceAccessResponse:
        raise NotImplementedError

    @handler("ListPolicyTags")
    def list_policy_tags(
        self,
        context: RequestContext,
        policy_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPolicyTagsResponse:
        raise NotImplementedError

    @handler("ListPolicyVersions")
    def list_policy_versions(
        self,
        context: RequestContext,
        policy_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListPolicyVersionsResponse:
        raise NotImplementedError

    @handler("ListRolePolicies")
    def list_role_policies(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRolePoliciesResponse:
        raise NotImplementedError

    @handler("ListRoleTags")
    def list_role_tags(
        self,
        context: RequestContext,
        role_name: roleNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRoleTagsResponse:
        raise NotImplementedError

    @handler("ListRoles")
    def list_roles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRolesResponse:
        raise NotImplementedError

    @handler("ListSAMLProviderTags")
    def list_saml_provider_tags(
        self,
        context: RequestContext,
        saml_provider_arn: arnType,
        marker: markerType = None,
        max_items: maxItemsType = None,
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
        user_name: userNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListSSHPublicKeysResponse:
        raise NotImplementedError

    @handler("ListServerCertificateTags")
    def list_server_certificate_tags(
        self,
        context: RequestContext,
        server_certificate_name: serverCertificateNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListServerCertificateTagsResponse:
        raise NotImplementedError

    @handler("ListServerCertificates")
    def list_server_certificates(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListServerCertificatesResponse:
        raise NotImplementedError

    @handler("ListServiceSpecificCredentials")
    def list_service_specific_credentials(
        self,
        context: RequestContext,
        user_name: userNameType = None,
        service_name: serviceName = None,
        **kwargs,
    ) -> ListServiceSpecificCredentialsResponse:
        raise NotImplementedError

    @handler("ListSigningCertificates")
    def list_signing_certificates(
        self,
        context: RequestContext,
        user_name: existingUserNameType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListSigningCertificatesResponse:
        raise NotImplementedError

    @handler("ListUserPolicies")
    def list_user_policies(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListUserPoliciesResponse:
        raise NotImplementedError

    @handler("ListUserTags")
    def list_user_tags(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListUserTagsResponse:
        raise NotImplementedError

    @handler("ListUsers")
    def list_users(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListUsersResponse:
        raise NotImplementedError

    @handler("ListVirtualMFADevices")
    def list_virtual_mfa_devices(
        self,
        context: RequestContext,
        assignment_status: assignmentStatusType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
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
        user_name: userNameType = None,
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
        permissions_boundary_policy_input_list: SimulationPolicyListType = None,
        resource_arns: ResourceNameListType = None,
        resource_policy: policyDocumentType = None,
        resource_owner: ResourceNameType = None,
        caller_arn: ResourceNameType = None,
        context_entries: ContextEntryListType = None,
        resource_handling_option: ResourceHandlingOptionType = None,
        max_items: maxItemsType = None,
        marker: markerType = None,
        **kwargs,
    ) -> SimulatePolicyResponse:
        raise NotImplementedError

    @handler("SimulatePrincipalPolicy")
    def simulate_principal_policy(
        self,
        context: RequestContext,
        policy_source_arn: arnType,
        action_names: ActionNameListType,
        policy_input_list: SimulationPolicyListType = None,
        permissions_boundary_policy_input_list: SimulationPolicyListType = None,
        resource_arns: ResourceNameListType = None,
        resource_policy: policyDocumentType = None,
        resource_owner: ResourceNameType = None,
        caller_arn: ResourceNameType = None,
        context_entries: ContextEntryListType = None,
        resource_handling_option: ResourceHandlingOptionType = None,
        max_items: maxItemsType = None,
        marker: markerType = None,
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
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAccountPasswordPolicy")
    def update_account_password_policy(
        self,
        context: RequestContext,
        minimum_password_length: minimumPasswordLengthType = None,
        require_symbols: booleanType = None,
        require_numbers: booleanType = None,
        require_uppercase_characters: booleanType = None,
        require_lowercase_characters: booleanType = None,
        allow_users_to_change_password: booleanType = None,
        max_password_age: maxPasswordAgeType = None,
        password_reuse_prevention: passwordReusePreventionType = None,
        hard_expiry: booleanObjectType = None,
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

    @handler("UpdateGroup")
    def update_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        new_path: pathType = None,
        new_group_name: groupNameType = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateLoginProfile")
    def update_login_profile(
        self,
        context: RequestContext,
        user_name: userNameType,
        password: passwordType = None,
        password_reset_required: booleanObjectType = None,
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
        description: roleDescriptionType = None,
        max_session_duration: roleMaxSessionDurationType = None,
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
        saml_metadata_document: SAMLMetadataDocumentType,
        saml_provider_arn: arnType,
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
        new_path: pathType = None,
        new_server_certificate_name: serverCertificateNameType = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateServiceSpecificCredential")
    def update_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        status: statusType,
        user_name: userNameType = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateSigningCertificate")
    def update_signing_certificate(
        self,
        context: RequestContext,
        certificate_id: certificateIdType,
        status: statusType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateUser")
    def update_user(
        self,
        context: RequestContext,
        user_name: existingUserNameType,
        new_path: pathType = None,
        new_user_name: userNameType = None,
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
        path: pathType = None,
        certificate_chain: certificateChainType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> UploadServerCertificateResponse:
        raise NotImplementedError

    @handler("UploadSigningCertificate")
    def upload_signing_certificate(
        self,
        context: RequestContext,
        certificate_body: certificateBodyType,
        user_name: existingUserNameType = None,
        **kwargs,
    ) -> UploadSigningCertificateResponse:
        raise NotImplementedError
