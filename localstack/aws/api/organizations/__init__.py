import sys
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccountArn = str
AccountId = str
AccountName = str
AwsManagedPolicy = bool
ChildId = str
CreateAccountRequestId = str
Email = str
ExceptionMessage = str
ExceptionType = str
GenericArn = str
HandshakeArn = str
HandshakeId = str
HandshakeNotes = str
HandshakePartyId = str
HandshakeResourceValue = str
MaxResults = int
NextToken = str
OrganizationArn = str
OrganizationId = str
OrganizationalUnitArn = str
OrganizationalUnitId = str
OrganizationalUnitName = str
ParentId = str
PolicyArn = str
PolicyContent = str
PolicyDescription = str
PolicyId = str
PolicyName = str
PolicyTargetId = str
RoleName = str
RootArn = str
RootId = str
RootName = str
ServicePrincipal = str
TagKey = str
TagValue = str
TaggableResourceId = str
TargetName = str


class AccessDeniedForDependencyExceptionReason(str):
    ACCESS_DENIED_DURING_CREATE_SERVICE_LINKED_ROLE = (
        "ACCESS_DENIED_DURING_CREATE_SERVICE_LINKED_ROLE"
    )


class AccountJoinedMethod(str):
    INVITED = "INVITED"
    CREATED = "CREATED"


class AccountStatus(str):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


class ActionType(str):
    INVITE = "INVITE"
    ENABLE_ALL_FEATURES = "ENABLE_ALL_FEATURES"
    APPROVE_ALL_FEATURES = "APPROVE_ALL_FEATURES"
    ADD_ORGANIZATIONS_SERVICE_LINKED_ROLE = "ADD_ORGANIZATIONS_SERVICE_LINKED_ROLE"


class ChildType(str):
    ACCOUNT = "ACCOUNT"
    ORGANIZATIONAL_UNIT = "ORGANIZATIONAL_UNIT"


class ConstraintViolationExceptionReason(str):
    ACCOUNT_NUMBER_LIMIT_EXCEEDED = "ACCOUNT_NUMBER_LIMIT_EXCEEDED"
    HANDSHAKE_RATE_LIMIT_EXCEEDED = "HANDSHAKE_RATE_LIMIT_EXCEEDED"
    OU_NUMBER_LIMIT_EXCEEDED = "OU_NUMBER_LIMIT_EXCEEDED"
    OU_DEPTH_LIMIT_EXCEEDED = "OU_DEPTH_LIMIT_EXCEEDED"
    POLICY_NUMBER_LIMIT_EXCEEDED = "POLICY_NUMBER_LIMIT_EXCEEDED"
    POLICY_CONTENT_LIMIT_EXCEEDED = "POLICY_CONTENT_LIMIT_EXCEEDED"
    MAX_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED = "MAX_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED"
    MIN_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED = "MIN_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED"
    ACCOUNT_CANNOT_LEAVE_ORGANIZATION = "ACCOUNT_CANNOT_LEAVE_ORGANIZATION"
    ACCOUNT_CANNOT_LEAVE_WITHOUT_EULA = "ACCOUNT_CANNOT_LEAVE_WITHOUT_EULA"
    ACCOUNT_CANNOT_LEAVE_WITHOUT_PHONE_VERIFICATION = (
        "ACCOUNT_CANNOT_LEAVE_WITHOUT_PHONE_VERIFICATION"
    )
    MASTER_ACCOUNT_PAYMENT_INSTRUMENT_REQUIRED = "MASTER_ACCOUNT_PAYMENT_INSTRUMENT_REQUIRED"
    MEMBER_ACCOUNT_PAYMENT_INSTRUMENT_REQUIRED = "MEMBER_ACCOUNT_PAYMENT_INSTRUMENT_REQUIRED"
    ACCOUNT_CREATION_RATE_LIMIT_EXCEEDED = "ACCOUNT_CREATION_RATE_LIMIT_EXCEEDED"
    MASTER_ACCOUNT_ADDRESS_DOES_NOT_MATCH_MARKETPLACE = (
        "MASTER_ACCOUNT_ADDRESS_DOES_NOT_MATCH_MARKETPLACE"
    )
    MASTER_ACCOUNT_MISSING_CONTACT_INFO = "MASTER_ACCOUNT_MISSING_CONTACT_INFO"
    MASTER_ACCOUNT_NOT_GOVCLOUD_ENABLED = "MASTER_ACCOUNT_NOT_GOVCLOUD_ENABLED"
    ORGANIZATION_NOT_IN_ALL_FEATURES_MODE = "ORGANIZATION_NOT_IN_ALL_FEATURES_MODE"
    CREATE_ORGANIZATION_IN_BILLING_MODE_UNSUPPORTED_REGION = (
        "CREATE_ORGANIZATION_IN_BILLING_MODE_UNSUPPORTED_REGION"
    )
    EMAIL_VERIFICATION_CODE_EXPIRED = "EMAIL_VERIFICATION_CODE_EXPIRED"
    WAIT_PERIOD_ACTIVE = "WAIT_PERIOD_ACTIVE"
    MAX_TAG_LIMIT_EXCEEDED = "MAX_TAG_LIMIT_EXCEEDED"
    TAG_POLICY_VIOLATION = "TAG_POLICY_VIOLATION"
    MAX_DELEGATED_ADMINISTRATORS_FOR_SERVICE_LIMIT_EXCEEDED = (
        "MAX_DELEGATED_ADMINISTRATORS_FOR_SERVICE_LIMIT_EXCEEDED"
    )
    CANNOT_REGISTER_MASTER_AS_DELEGATED_ADMINISTRATOR = (
        "CANNOT_REGISTER_MASTER_AS_DELEGATED_ADMINISTRATOR"
    )
    CANNOT_REMOVE_DELEGATED_ADMINISTRATOR_FROM_ORG = (
        "CANNOT_REMOVE_DELEGATED_ADMINISTRATOR_FROM_ORG"
    )
    DELEGATED_ADMINISTRATOR_EXISTS_FOR_THIS_SERVICE = (
        "DELEGATED_ADMINISTRATOR_EXISTS_FOR_THIS_SERVICE"
    )
    MASTER_ACCOUNT_MISSING_BUSINESS_LICENSE = "MASTER_ACCOUNT_MISSING_BUSINESS_LICENSE"


class CreateAccountFailureReason(str):
    ACCOUNT_LIMIT_EXCEEDED = "ACCOUNT_LIMIT_EXCEEDED"
    EMAIL_ALREADY_EXISTS = "EMAIL_ALREADY_EXISTS"
    INVALID_ADDRESS = "INVALID_ADDRESS"
    INVALID_EMAIL = "INVALID_EMAIL"
    CONCURRENT_ACCOUNT_MODIFICATION = "CONCURRENT_ACCOUNT_MODIFICATION"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"
    GOVCLOUD_ACCOUNT_ALREADY_EXISTS = "GOVCLOUD_ACCOUNT_ALREADY_EXISTS"
    MISSING_BUSINESS_VALIDATION = "MISSING_BUSINESS_VALIDATION"
    FAILED_BUSINESS_VALIDATION = "FAILED_BUSINESS_VALIDATION"
    PENDING_BUSINESS_VALIDATION = "PENDING_BUSINESS_VALIDATION"
    INVALID_IDENTITY_FOR_BUSINESS_VALIDATION = "INVALID_IDENTITY_FOR_BUSINESS_VALIDATION"
    UNKNOWN_BUSINESS_VALIDATION = "UNKNOWN_BUSINESS_VALIDATION"
    MISSING_PAYMENT_INSTRUMENT = "MISSING_PAYMENT_INSTRUMENT"


class CreateAccountState(str):
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class EffectivePolicyType(str):
    TAG_POLICY = "TAG_POLICY"
    BACKUP_POLICY = "BACKUP_POLICY"
    AISERVICES_OPT_OUT_POLICY = "AISERVICES_OPT_OUT_POLICY"


class HandshakeConstraintViolationExceptionReason(str):
    ACCOUNT_NUMBER_LIMIT_EXCEEDED = "ACCOUNT_NUMBER_LIMIT_EXCEEDED"
    HANDSHAKE_RATE_LIMIT_EXCEEDED = "HANDSHAKE_RATE_LIMIT_EXCEEDED"
    ALREADY_IN_AN_ORGANIZATION = "ALREADY_IN_AN_ORGANIZATION"
    ORGANIZATION_ALREADY_HAS_ALL_FEATURES = "ORGANIZATION_ALREADY_HAS_ALL_FEATURES"
    ORGANIZATION_IS_ALREADY_PENDING_ALL_FEATURES_MIGRATION = (
        "ORGANIZATION_IS_ALREADY_PENDING_ALL_FEATURES_MIGRATION"
    )
    INVITE_DISABLED_DURING_ENABLE_ALL_FEATURES = "INVITE_DISABLED_DURING_ENABLE_ALL_FEATURES"
    PAYMENT_INSTRUMENT_REQUIRED = "PAYMENT_INSTRUMENT_REQUIRED"
    ORGANIZATION_FROM_DIFFERENT_SELLER_OF_RECORD = "ORGANIZATION_FROM_DIFFERENT_SELLER_OF_RECORD"
    ORGANIZATION_MEMBERSHIP_CHANGE_RATE_LIMIT_EXCEEDED = (
        "ORGANIZATION_MEMBERSHIP_CHANGE_RATE_LIMIT_EXCEEDED"
    )


class HandshakePartyType(str):
    ACCOUNT = "ACCOUNT"
    ORGANIZATION = "ORGANIZATION"
    EMAIL = "EMAIL"


class HandshakeResourceType(str):
    ACCOUNT = "ACCOUNT"
    ORGANIZATION = "ORGANIZATION"
    ORGANIZATION_FEATURE_SET = "ORGANIZATION_FEATURE_SET"
    EMAIL = "EMAIL"
    MASTER_EMAIL = "MASTER_EMAIL"
    MASTER_NAME = "MASTER_NAME"
    NOTES = "NOTES"
    PARENT_HANDSHAKE = "PARENT_HANDSHAKE"


class HandshakeState(str):
    REQUESTED = "REQUESTED"
    OPEN = "OPEN"
    CANCELED = "CANCELED"
    ACCEPTED = "ACCEPTED"
    DECLINED = "DECLINED"
    EXPIRED = "EXPIRED"


class IAMUserAccessToBilling(str):
    ALLOW = "ALLOW"
    DENY = "DENY"


class InvalidInputExceptionReason(str):
    INVALID_PARTY_TYPE_TARGET = "INVALID_PARTY_TYPE_TARGET"
    INVALID_SYNTAX_ORGANIZATION_ARN = "INVALID_SYNTAX_ORGANIZATION_ARN"
    INVALID_SYNTAX_POLICY_ID = "INVALID_SYNTAX_POLICY_ID"
    INVALID_ENUM = "INVALID_ENUM"
    INVALID_ENUM_POLICY_TYPE = "INVALID_ENUM_POLICY_TYPE"
    INVALID_LIST_MEMBER = "INVALID_LIST_MEMBER"
    MAX_LENGTH_EXCEEDED = "MAX_LENGTH_EXCEEDED"
    MAX_VALUE_EXCEEDED = "MAX_VALUE_EXCEEDED"
    MIN_LENGTH_EXCEEDED = "MIN_LENGTH_EXCEEDED"
    MIN_VALUE_EXCEEDED = "MIN_VALUE_EXCEEDED"
    IMMUTABLE_POLICY = "IMMUTABLE_POLICY"
    INVALID_PATTERN = "INVALID_PATTERN"
    INVALID_PATTERN_TARGET_ID = "INVALID_PATTERN_TARGET_ID"
    INPUT_REQUIRED = "INPUT_REQUIRED"
    INVALID_NEXT_TOKEN = "INVALID_NEXT_TOKEN"
    MAX_LIMIT_EXCEEDED_FILTER = "MAX_LIMIT_EXCEEDED_FILTER"
    MOVING_ACCOUNT_BETWEEN_DIFFERENT_ROOTS = "MOVING_ACCOUNT_BETWEEN_DIFFERENT_ROOTS"
    INVALID_FULL_NAME_TARGET = "INVALID_FULL_NAME_TARGET"
    UNRECOGNIZED_SERVICE_PRINCIPAL = "UNRECOGNIZED_SERVICE_PRINCIPAL"
    INVALID_ROLE_NAME = "INVALID_ROLE_NAME"
    INVALID_SYSTEM_TAGS_PARAMETER = "INVALID_SYSTEM_TAGS_PARAMETER"
    DUPLICATE_TAG_KEY = "DUPLICATE_TAG_KEY"
    TARGET_NOT_SUPPORTED = "TARGET_NOT_SUPPORTED"
    INVALID_EMAIL_ADDRESS_TARGET = "INVALID_EMAIL_ADDRESS_TARGET"


class OrganizationFeatureSet(str):
    ALL = "ALL"
    CONSOLIDATED_BILLING = "CONSOLIDATED_BILLING"


class ParentType(str):
    ROOT = "ROOT"
    ORGANIZATIONAL_UNIT = "ORGANIZATIONAL_UNIT"


class PolicyType(str):
    SERVICE_CONTROL_POLICY = "SERVICE_CONTROL_POLICY"
    TAG_POLICY = "TAG_POLICY"
    BACKUP_POLICY = "BACKUP_POLICY"
    AISERVICES_OPT_OUT_POLICY = "AISERVICES_OPT_OUT_POLICY"


class PolicyTypeStatus(str):
    ENABLED = "ENABLED"
    PENDING_ENABLE = "PENDING_ENABLE"
    PENDING_DISABLE = "PENDING_DISABLE"


class TargetType(str):
    ACCOUNT = "ACCOUNT"
    ORGANIZATIONAL_UNIT = "ORGANIZATIONAL_UNIT"
    ROOT = "ROOT"


class AWSOrganizationsNotInUseException(ServiceException):
    Message: Optional[ExceptionMessage]


class AccessDeniedException(ServiceException):
    Message: Optional[ExceptionMessage]


class AccessDeniedForDependencyException(ServiceException):
    Message: Optional[ExceptionMessage]
    Reason: Optional[AccessDeniedForDependencyExceptionReason]


class AccountAlreadyRegisteredException(ServiceException):
    Message: Optional[ExceptionMessage]


class AccountNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class AccountNotRegisteredException(ServiceException):
    Message: Optional[ExceptionMessage]


class AccountOwnerNotVerifiedException(ServiceException):
    Message: Optional[ExceptionMessage]


class AlreadyInOrganizationException(ServiceException):
    Message: Optional[ExceptionMessage]


class ChildNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class ConcurrentModificationException(ServiceException):
    Message: Optional[ExceptionMessage]


class ConstraintViolationException(ServiceException):
    Message: Optional[ExceptionMessage]
    Reason: Optional[ConstraintViolationExceptionReason]


class CreateAccountStatusNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class DestinationParentNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class DuplicateAccountException(ServiceException):
    Message: Optional[ExceptionMessage]


class DuplicateHandshakeException(ServiceException):
    Message: Optional[ExceptionMessage]


class DuplicateOrganizationalUnitException(ServiceException):
    Message: Optional[ExceptionMessage]


class DuplicatePolicyAttachmentException(ServiceException):
    Message: Optional[ExceptionMessage]


class DuplicatePolicyException(ServiceException):
    Message: Optional[ExceptionMessage]


class EffectivePolicyNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class FinalizingOrganizationException(ServiceException):
    Message: Optional[ExceptionMessage]


class HandshakeAlreadyInStateException(ServiceException):
    Message: Optional[ExceptionMessage]


class HandshakeConstraintViolationException(ServiceException):
    Message: Optional[ExceptionMessage]
    Reason: Optional[HandshakeConstraintViolationExceptionReason]


class HandshakeNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class InvalidHandshakeTransitionException(ServiceException):
    Message: Optional[ExceptionMessage]


class InvalidInputException(ServiceException):
    Message: Optional[ExceptionMessage]
    Reason: Optional[InvalidInputExceptionReason]


class MalformedPolicyDocumentException(ServiceException):
    Message: Optional[ExceptionMessage]


class MasterCannotLeaveOrganizationException(ServiceException):
    Message: Optional[ExceptionMessage]


class OrganizationNotEmptyException(ServiceException):
    Message: Optional[ExceptionMessage]


class OrganizationalUnitNotEmptyException(ServiceException):
    Message: Optional[ExceptionMessage]


class OrganizationalUnitNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class ParentNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class PolicyChangesInProgressException(ServiceException):
    Message: Optional[ExceptionMessage]


class PolicyInUseException(ServiceException):
    Message: Optional[ExceptionMessage]


class PolicyNotAttachedException(ServiceException):
    Message: Optional[ExceptionMessage]


class PolicyNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class PolicyTypeAlreadyEnabledException(ServiceException):
    Message: Optional[ExceptionMessage]


class PolicyTypeNotAvailableForOrganizationException(ServiceException):
    Message: Optional[ExceptionMessage]


class PolicyTypeNotEnabledException(ServiceException):
    Message: Optional[ExceptionMessage]


class RootNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class ServiceException(ServiceException):
    Message: Optional[ExceptionMessage]


class SourceParentNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class TargetNotFoundException(ServiceException):
    Message: Optional[ExceptionMessage]


class TooManyRequestsException(ServiceException):
    Type: Optional[ExceptionType]
    Message: Optional[ExceptionMessage]


class UnsupportedAPIEndpointException(ServiceException):
    Message: Optional[ExceptionMessage]


class AcceptHandshakeRequest(ServiceRequest):
    HandshakeId: HandshakeId


HandshakeResources = List["HandshakeResource"]


class HandshakeResource(TypedDict, total=False):
    Value: Optional[HandshakeResourceValue]
    Type: Optional[HandshakeResourceType]
    Resources: Optional[HandshakeResources]


Timestamp = str


class HandshakeParty(TypedDict, total=False):
    Id: HandshakePartyId
    Type: HandshakePartyType


HandshakeParties = List[HandshakeParty]


class Handshake(TypedDict, total=False):
    Id: Optional[HandshakeId]
    Arn: Optional[HandshakeArn]
    Parties: Optional[HandshakeParties]
    State: Optional[HandshakeState]
    RequestedTimestamp: Optional[Timestamp]
    ExpirationTimestamp: Optional[Timestamp]
    Action: Optional[ActionType]
    Resources: Optional[HandshakeResources]


class AcceptHandshakeResponse(TypedDict, total=False):
    Handshake: Optional[Handshake]


class Account(TypedDict, total=False):
    Id: Optional[AccountId]
    Arn: Optional[AccountArn]
    Email: Optional[Email]
    Name: Optional[AccountName]
    Status: Optional[AccountStatus]
    JoinedMethod: Optional[AccountJoinedMethod]
    JoinedTimestamp: Optional[Timestamp]


Accounts = List[Account]


class AttachPolicyRequest(ServiceRequest):
    PolicyId: PolicyId
    TargetId: PolicyTargetId


class CancelHandshakeRequest(ServiceRequest):
    HandshakeId: HandshakeId


class CancelHandshakeResponse(TypedDict, total=False):
    Handshake: Optional[Handshake]


class Child(TypedDict, total=False):
    Id: Optional[ChildId]
    Type: Optional[ChildType]


Children = List[Child]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


Tags = List[Tag]


class CreateAccountRequest(ServiceRequest):
    Email: Email
    AccountName: AccountName
    RoleName: Optional[RoleName]
    IamUserAccessToBilling: Optional[IAMUserAccessToBilling]
    Tags: Optional[Tags]


class CreateAccountStatus(TypedDict, total=False):
    Id: Optional[CreateAccountRequestId]
    AccountName: Optional[AccountName]
    State: Optional[CreateAccountState]
    RequestedTimestamp: Optional[Timestamp]
    CompletedTimestamp: Optional[Timestamp]
    AccountId: Optional[AccountId]
    GovCloudAccountId: Optional[AccountId]
    FailureReason: Optional[CreateAccountFailureReason]


class CreateAccountResponse(TypedDict, total=False):
    CreateAccountStatus: Optional[CreateAccountStatus]


CreateAccountStates = List[CreateAccountState]
CreateAccountStatuses = List[CreateAccountStatus]


class CreateGovCloudAccountRequest(ServiceRequest):
    Email: Email
    AccountName: AccountName
    RoleName: Optional[RoleName]
    IamUserAccessToBilling: Optional[IAMUserAccessToBilling]
    Tags: Optional[Tags]


class CreateGovCloudAccountResponse(TypedDict, total=False):
    CreateAccountStatus: Optional[CreateAccountStatus]


class CreateOrganizationRequest(ServiceRequest):
    FeatureSet: Optional[OrganizationFeatureSet]


class PolicyTypeSummary(TypedDict, total=False):
    Type: Optional[PolicyType]
    Status: Optional[PolicyTypeStatus]


PolicyTypes = List[PolicyTypeSummary]


class Organization(TypedDict, total=False):
    Id: Optional[OrganizationId]
    Arn: Optional[OrganizationArn]
    FeatureSet: Optional[OrganizationFeatureSet]
    MasterAccountArn: Optional[AccountArn]
    MasterAccountId: Optional[AccountId]
    MasterAccountEmail: Optional[Email]
    AvailablePolicyTypes: Optional[PolicyTypes]


class CreateOrganizationResponse(TypedDict, total=False):
    Organization: Optional[Organization]


class CreateOrganizationalUnitRequest(ServiceRequest):
    ParentId: ParentId
    Name: OrganizationalUnitName
    Tags: Optional[Tags]


class OrganizationalUnit(TypedDict, total=False):
    Id: Optional[OrganizationalUnitId]
    Arn: Optional[OrganizationalUnitArn]
    Name: Optional[OrganizationalUnitName]


class CreateOrganizationalUnitResponse(TypedDict, total=False):
    OrganizationalUnit: Optional[OrganizationalUnit]


class CreatePolicyRequest(ServiceRequest):
    Content: PolicyContent
    Description: PolicyDescription
    Name: PolicyName
    Type: PolicyType
    Tags: Optional[Tags]


class PolicySummary(TypedDict, total=False):
    Id: Optional[PolicyId]
    Arn: Optional[PolicyArn]
    Name: Optional[PolicyName]
    Description: Optional[PolicyDescription]
    Type: Optional[PolicyType]
    AwsManaged: Optional[AwsManagedPolicy]


class Policy(TypedDict, total=False):
    PolicySummary: Optional[PolicySummary]
    Content: Optional[PolicyContent]


class CreatePolicyResponse(TypedDict, total=False):
    Policy: Optional[Policy]


class DeclineHandshakeRequest(ServiceRequest):
    HandshakeId: HandshakeId


class DeclineHandshakeResponse(TypedDict, total=False):
    Handshake: Optional[Handshake]


class DelegatedAdministrator(TypedDict, total=False):
    Id: Optional[AccountId]
    Arn: Optional[AccountArn]
    Email: Optional[Email]
    Name: Optional[AccountName]
    Status: Optional[AccountStatus]
    JoinedMethod: Optional[AccountJoinedMethod]
    JoinedTimestamp: Optional[Timestamp]
    DelegationEnabledDate: Optional[Timestamp]


DelegatedAdministrators = List[DelegatedAdministrator]


class DelegatedService(TypedDict, total=False):
    ServicePrincipal: Optional[ServicePrincipal]
    DelegationEnabledDate: Optional[Timestamp]


DelegatedServices = List[DelegatedService]


class DeleteOrganizationalUnitRequest(ServiceRequest):
    OrganizationalUnitId: OrganizationalUnitId


class DeletePolicyRequest(ServiceRequest):
    PolicyId: PolicyId


class DeregisterDelegatedAdministratorRequest(ServiceRequest):
    AccountId: AccountId
    ServicePrincipal: ServicePrincipal


class DescribeAccountRequest(ServiceRequest):
    AccountId: AccountId


class DescribeAccountResponse(TypedDict, total=False):
    Account: Optional[Account]


class DescribeCreateAccountStatusRequest(ServiceRequest):
    CreateAccountRequestId: CreateAccountRequestId


class DescribeCreateAccountStatusResponse(TypedDict, total=False):
    CreateAccountStatus: Optional[CreateAccountStatus]


class DescribeEffectivePolicyRequest(ServiceRequest):
    PolicyType: EffectivePolicyType
    TargetId: Optional[PolicyTargetId]


class EffectivePolicy(TypedDict, total=False):
    PolicyContent: Optional[PolicyContent]
    LastUpdatedTimestamp: Optional[Timestamp]
    TargetId: Optional[PolicyTargetId]
    PolicyType: Optional[EffectivePolicyType]


class DescribeEffectivePolicyResponse(TypedDict, total=False):
    EffectivePolicy: Optional[EffectivePolicy]


class DescribeHandshakeRequest(ServiceRequest):
    HandshakeId: HandshakeId


class DescribeHandshakeResponse(TypedDict, total=False):
    Handshake: Optional[Handshake]


class DescribeOrganizationResponse(TypedDict, total=False):
    Organization: Optional[Organization]


class DescribeOrganizationalUnitRequest(ServiceRequest):
    OrganizationalUnitId: OrganizationalUnitId


class DescribeOrganizationalUnitResponse(TypedDict, total=False):
    OrganizationalUnit: Optional[OrganizationalUnit]


class DescribePolicyRequest(ServiceRequest):
    PolicyId: PolicyId


class DescribePolicyResponse(TypedDict, total=False):
    Policy: Optional[Policy]


class DetachPolicyRequest(ServiceRequest):
    PolicyId: PolicyId
    TargetId: PolicyTargetId


class DisableAWSServiceAccessRequest(ServiceRequest):
    ServicePrincipal: ServicePrincipal


class DisablePolicyTypeRequest(ServiceRequest):
    RootId: RootId
    PolicyType: PolicyType


class Root(TypedDict, total=False):
    Id: Optional[RootId]
    Arn: Optional[RootArn]
    Name: Optional[RootName]
    PolicyTypes: Optional[PolicyTypes]


class DisablePolicyTypeResponse(TypedDict, total=False):
    Root: Optional[Root]


class EnableAWSServiceAccessRequest(ServiceRequest):
    ServicePrincipal: ServicePrincipal


class EnableAllFeaturesRequest(ServiceRequest):
    pass


class EnableAllFeaturesResponse(TypedDict, total=False):
    Handshake: Optional[Handshake]


class EnablePolicyTypeRequest(ServiceRequest):
    RootId: RootId
    PolicyType: PolicyType


class EnablePolicyTypeResponse(TypedDict, total=False):
    Root: Optional[Root]


class EnabledServicePrincipal(TypedDict, total=False):
    ServicePrincipal: Optional[ServicePrincipal]
    DateEnabled: Optional[Timestamp]


EnabledServicePrincipals = List[EnabledServicePrincipal]


class HandshakeFilter(TypedDict, total=False):
    ActionType: Optional[ActionType]
    ParentHandshakeId: Optional[HandshakeId]


Handshakes = List[Handshake]


class InviteAccountToOrganizationRequest(ServiceRequest):
    Target: HandshakeParty
    Notes: Optional[HandshakeNotes]
    Tags: Optional[Tags]


class InviteAccountToOrganizationResponse(TypedDict, total=False):
    Handshake: Optional[Handshake]


class ListAWSServiceAccessForOrganizationRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListAWSServiceAccessForOrganizationResponse(TypedDict, total=False):
    EnabledServicePrincipals: Optional[EnabledServicePrincipals]
    NextToken: Optional[NextToken]


class ListAccountsForParentRequest(ServiceRequest):
    ParentId: ParentId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListAccountsForParentResponse(TypedDict, total=False):
    Accounts: Optional[Accounts]
    NextToken: Optional[NextToken]


class ListAccountsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListAccountsResponse(TypedDict, total=False):
    Accounts: Optional[Accounts]
    NextToken: Optional[NextToken]


class ListChildrenRequest(ServiceRequest):
    ParentId: ParentId
    ChildType: ChildType
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListChildrenResponse(TypedDict, total=False):
    Children: Optional[Children]
    NextToken: Optional[NextToken]


class ListCreateAccountStatusRequest(ServiceRequest):
    States: Optional[CreateAccountStates]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListCreateAccountStatusResponse(TypedDict, total=False):
    CreateAccountStatuses: Optional[CreateAccountStatuses]
    NextToken: Optional[NextToken]


class ListDelegatedAdministratorsRequest(ServiceRequest):
    ServicePrincipal: Optional[ServicePrincipal]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListDelegatedAdministratorsResponse(TypedDict, total=False):
    DelegatedAdministrators: Optional[DelegatedAdministrators]
    NextToken: Optional[NextToken]


class ListDelegatedServicesForAccountRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListDelegatedServicesForAccountResponse(TypedDict, total=False):
    DelegatedServices: Optional[DelegatedServices]
    NextToken: Optional[NextToken]


class ListHandshakesForAccountRequest(ServiceRequest):
    Filter: Optional[HandshakeFilter]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListHandshakesForAccountResponse(TypedDict, total=False):
    Handshakes: Optional[Handshakes]
    NextToken: Optional[NextToken]


class ListHandshakesForOrganizationRequest(ServiceRequest):
    Filter: Optional[HandshakeFilter]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListHandshakesForOrganizationResponse(TypedDict, total=False):
    Handshakes: Optional[Handshakes]
    NextToken: Optional[NextToken]


class ListOrganizationalUnitsForParentRequest(ServiceRequest):
    ParentId: ParentId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


OrganizationalUnits = List[OrganizationalUnit]


class ListOrganizationalUnitsForParentResponse(TypedDict, total=False):
    OrganizationalUnits: Optional[OrganizationalUnits]
    NextToken: Optional[NextToken]


class ListParentsRequest(ServiceRequest):
    ChildId: ChildId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class Parent(TypedDict, total=False):
    Id: Optional[ParentId]
    Type: Optional[ParentType]


Parents = List[Parent]


class ListParentsResponse(TypedDict, total=False):
    Parents: Optional[Parents]
    NextToken: Optional[NextToken]


class ListPoliciesForTargetRequest(ServiceRequest):
    TargetId: PolicyTargetId
    Filter: PolicyType
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


Policies = List[PolicySummary]


class ListPoliciesForTargetResponse(TypedDict, total=False):
    Policies: Optional[Policies]
    NextToken: Optional[NextToken]


class ListPoliciesRequest(ServiceRequest):
    Filter: PolicyType
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListPoliciesResponse(TypedDict, total=False):
    Policies: Optional[Policies]
    NextToken: Optional[NextToken]


class ListRootsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


Roots = List[Root]


class ListRootsResponse(TypedDict, total=False):
    Roots: Optional[Roots]
    NextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceId: TaggableResourceId
    NextToken: Optional[NextToken]


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[Tags]
    NextToken: Optional[NextToken]


class ListTargetsForPolicyRequest(ServiceRequest):
    PolicyId: PolicyId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class PolicyTargetSummary(TypedDict, total=False):
    TargetId: Optional[PolicyTargetId]
    Arn: Optional[GenericArn]
    Name: Optional[TargetName]
    Type: Optional[TargetType]


PolicyTargets = List[PolicyTargetSummary]


class ListTargetsForPolicyResponse(TypedDict, total=False):
    Targets: Optional[PolicyTargets]
    NextToken: Optional[NextToken]


class MoveAccountRequest(ServiceRequest):
    AccountId: AccountId
    SourceParentId: ParentId
    DestinationParentId: ParentId


class RegisterDelegatedAdministratorRequest(ServiceRequest):
    AccountId: AccountId
    ServicePrincipal: ServicePrincipal


class RemoveAccountFromOrganizationRequest(ServiceRequest):
    AccountId: AccountId


TagKeys = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceId: TaggableResourceId
    Tags: Tags


class UntagResourceRequest(ServiceRequest):
    ResourceId: TaggableResourceId
    TagKeys: TagKeys


class UpdateOrganizationalUnitRequest(ServiceRequest):
    OrganizationalUnitId: OrganizationalUnitId
    Name: Optional[OrganizationalUnitName]


class UpdateOrganizationalUnitResponse(TypedDict, total=False):
    OrganizationalUnit: Optional[OrganizationalUnit]


class UpdatePolicyRequest(ServiceRequest):
    PolicyId: PolicyId
    Name: Optional[PolicyName]
    Description: Optional[PolicyDescription]
    Content: Optional[PolicyContent]


class UpdatePolicyResponse(TypedDict, total=False):
    Policy: Optional[Policy]


class OrganizationsApi:

    service = "organizations"
    version = "2016-11-28"

    @handler("AcceptHandshake")
    def accept_handshake(
        self, context: RequestContext, handshake_id: HandshakeId
    ) -> AcceptHandshakeResponse:
        raise NotImplementedError

    @handler("AttachPolicy")
    def attach_policy(
        self, context: RequestContext, policy_id: PolicyId, target_id: PolicyTargetId
    ) -> None:
        raise NotImplementedError

    @handler("CancelHandshake")
    def cancel_handshake(
        self, context: RequestContext, handshake_id: HandshakeId
    ) -> CancelHandshakeResponse:
        raise NotImplementedError

    @handler("CreateAccount")
    def create_account(
        self,
        context: RequestContext,
        email: Email,
        account_name: AccountName,
        role_name: RoleName = None,
        iam_user_access_to_billing: IAMUserAccessToBilling = None,
        tags: Tags = None,
    ) -> CreateAccountResponse:
        raise NotImplementedError

    @handler("CreateGovCloudAccount")
    def create_gov_cloud_account(
        self,
        context: RequestContext,
        email: Email,
        account_name: AccountName,
        role_name: RoleName = None,
        iam_user_access_to_billing: IAMUserAccessToBilling = None,
        tags: Tags = None,
    ) -> CreateGovCloudAccountResponse:
        raise NotImplementedError

    @handler("CreateOrganization")
    def create_organization(
        self, context: RequestContext, feature_set: OrganizationFeatureSet = None
    ) -> CreateOrganizationResponse:
        raise NotImplementedError

    @handler("CreateOrganizationalUnit")
    def create_organizational_unit(
        self,
        context: RequestContext,
        parent_id: ParentId,
        name: OrganizationalUnitName,
        tags: Tags = None,
    ) -> CreateOrganizationalUnitResponse:
        raise NotImplementedError

    @handler("CreatePolicy")
    def create_policy(
        self,
        context: RequestContext,
        content: PolicyContent,
        description: PolicyDescription,
        name: PolicyName,
        type: PolicyType,
        tags: Tags = None,
    ) -> CreatePolicyResponse:
        raise NotImplementedError

    @handler("DeclineHandshake")
    def decline_handshake(
        self, context: RequestContext, handshake_id: HandshakeId
    ) -> DeclineHandshakeResponse:
        raise NotImplementedError

    @handler("DeleteOrganization")
    def delete_organization(
        self,
        context: RequestContext,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteOrganizationalUnit")
    def delete_organizational_unit(
        self, context: RequestContext, organizational_unit_id: OrganizationalUnitId
    ) -> None:
        raise NotImplementedError

    @handler("DeletePolicy")
    def delete_policy(self, context: RequestContext, policy_id: PolicyId) -> None:
        raise NotImplementedError

    @handler("DeregisterDelegatedAdministrator")
    def deregister_delegated_administrator(
        self,
        context: RequestContext,
        account_id: AccountId,
        service_principal: ServicePrincipal,
    ) -> None:
        raise NotImplementedError

    @handler("DescribeAccount")
    def describe_account(
        self, context: RequestContext, account_id: AccountId
    ) -> DescribeAccountResponse:
        raise NotImplementedError

    @handler("DescribeCreateAccountStatus")
    def describe_create_account_status(
        self, context: RequestContext, create_account_request_id: CreateAccountRequestId
    ) -> DescribeCreateAccountStatusResponse:
        raise NotImplementedError

    @handler("DescribeEffectivePolicy")
    def describe_effective_policy(
        self,
        context: RequestContext,
        policy_type: EffectivePolicyType,
        target_id: PolicyTargetId = None,
    ) -> DescribeEffectivePolicyResponse:
        raise NotImplementedError

    @handler("DescribeHandshake")
    def describe_handshake(
        self, context: RequestContext, handshake_id: HandshakeId
    ) -> DescribeHandshakeResponse:
        raise NotImplementedError

    @handler("DescribeOrganization")
    def describe_organization(
        self,
        context: RequestContext,
    ) -> DescribeOrganizationResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationalUnit")
    def describe_organizational_unit(
        self, context: RequestContext, organizational_unit_id: OrganizationalUnitId
    ) -> DescribeOrganizationalUnitResponse:
        raise NotImplementedError

    @handler("DescribePolicy")
    def describe_policy(
        self, context: RequestContext, policy_id: PolicyId
    ) -> DescribePolicyResponse:
        raise NotImplementedError

    @handler("DetachPolicy")
    def detach_policy(
        self, context: RequestContext, policy_id: PolicyId, target_id: PolicyTargetId
    ) -> None:
        raise NotImplementedError

    @handler("DisableAWSServiceAccess")
    def disable_aws_service_access(
        self, context: RequestContext, service_principal: ServicePrincipal
    ) -> None:
        raise NotImplementedError

    @handler("DisablePolicyType")
    def disable_policy_type(
        self, context: RequestContext, root_id: RootId, policy_type: PolicyType
    ) -> DisablePolicyTypeResponse:
        raise NotImplementedError

    @handler("EnableAWSServiceAccess")
    def enable_aws_service_access(
        self, context: RequestContext, service_principal: ServicePrincipal
    ) -> None:
        raise NotImplementedError

    @handler("EnableAllFeatures")
    def enable_all_features(
        self,
        context: RequestContext,
    ) -> EnableAllFeaturesResponse:
        raise NotImplementedError

    @handler("EnablePolicyType")
    def enable_policy_type(
        self, context: RequestContext, root_id: RootId, policy_type: PolicyType
    ) -> EnablePolicyTypeResponse:
        raise NotImplementedError

    @handler("InviteAccountToOrganization")
    def invite_account_to_organization(
        self,
        context: RequestContext,
        target: HandshakeParty,
        notes: HandshakeNotes = None,
        tags: Tags = None,
    ) -> InviteAccountToOrganizationResponse:
        raise NotImplementedError

    @handler("LeaveOrganization")
    def leave_organization(
        self,
        context: RequestContext,
    ) -> None:
        raise NotImplementedError

    @handler("ListAWSServiceAccessForOrganization")
    def list_aws_service_access_for_organization(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAWSServiceAccessForOrganizationResponse:
        raise NotImplementedError

    @handler("ListAccounts")
    def list_accounts(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAccountsResponse:
        raise NotImplementedError

    @handler("ListAccountsForParent")
    def list_accounts_for_parent(
        self,
        context: RequestContext,
        parent_id: ParentId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAccountsForParentResponse:
        raise NotImplementedError

    @handler("ListChildren")
    def list_children(
        self,
        context: RequestContext,
        parent_id: ParentId,
        child_type: ChildType,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListChildrenResponse:
        raise NotImplementedError

    @handler("ListCreateAccountStatus")
    def list_create_account_status(
        self,
        context: RequestContext,
        states: CreateAccountStates = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListCreateAccountStatusResponse:
        raise NotImplementedError

    @handler("ListDelegatedAdministrators")
    def list_delegated_administrators(
        self,
        context: RequestContext,
        service_principal: ServicePrincipal = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListDelegatedAdministratorsResponse:
        raise NotImplementedError

    @handler("ListDelegatedServicesForAccount")
    def list_delegated_services_for_account(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListDelegatedServicesForAccountResponse:
        raise NotImplementedError

    @handler("ListHandshakesForAccount")
    def list_handshakes_for_account(
        self,
        context: RequestContext,
        filter: HandshakeFilter = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListHandshakesForAccountResponse:
        raise NotImplementedError

    @handler("ListHandshakesForOrganization")
    def list_handshakes_for_organization(
        self,
        context: RequestContext,
        filter: HandshakeFilter = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListHandshakesForOrganizationResponse:
        raise NotImplementedError

    @handler("ListOrganizationalUnitsForParent")
    def list_organizational_units_for_parent(
        self,
        context: RequestContext,
        parent_id: ParentId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListOrganizationalUnitsForParentResponse:
        raise NotImplementedError

    @handler("ListParents")
    def list_parents(
        self,
        context: RequestContext,
        child_id: ChildId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListParentsResponse:
        raise NotImplementedError

    @handler("ListPolicies")
    def list_policies(
        self,
        context: RequestContext,
        filter: PolicyType,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListPoliciesResponse:
        raise NotImplementedError

    @handler("ListPoliciesForTarget")
    def list_policies_for_target(
        self,
        context: RequestContext,
        target_id: PolicyTargetId,
        filter: PolicyType,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListPoliciesForTargetResponse:
        raise NotImplementedError

    @handler("ListRoots")
    def list_roots(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListRootsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_id: TaggableResourceId,
        next_token: NextToken = None,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTargetsForPolicy")
    def list_targets_for_policy(
        self,
        context: RequestContext,
        policy_id: PolicyId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListTargetsForPolicyResponse:
        raise NotImplementedError

    @handler("MoveAccount")
    def move_account(
        self,
        context: RequestContext,
        account_id: AccountId,
        source_parent_id: ParentId,
        destination_parent_id: ParentId,
    ) -> None:
        raise NotImplementedError

    @handler("RegisterDelegatedAdministrator")
    def register_delegated_administrator(
        self,
        context: RequestContext,
        account_id: AccountId,
        service_principal: ServicePrincipal,
    ) -> None:
        raise NotImplementedError

    @handler("RemoveAccountFromOrganization")
    def remove_account_from_organization(
        self, context: RequestContext, account_id: AccountId
    ) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_id: TaggableResourceId, tags: Tags
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        resource_id: TaggableResourceId,
        tag_keys: TagKeys,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateOrganizationalUnit")
    def update_organizational_unit(
        self,
        context: RequestContext,
        organizational_unit_id: OrganizationalUnitId,
        name: OrganizationalUnitName = None,
    ) -> UpdateOrganizationalUnitResponse:
        raise NotImplementedError

    @handler("UpdatePolicy")
    def update_policy(
        self,
        context: RequestContext,
        policy_id: PolicyId,
        name: PolicyName = None,
        description: PolicyDescription = None,
        content: PolicyContent = None,
    ) -> UpdatePolicyResponse:
        raise NotImplementedError
