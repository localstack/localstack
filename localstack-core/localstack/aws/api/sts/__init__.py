from datetime import datetime
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Audience = str
Issuer = str
NameQualifier = str
RootDurationSecondsType = int
SAMLAssertionType = str
Subject = str
SubjectType = str
TargetPrincipalType = str
accessKeyIdType = str
accessKeySecretType = str
accountType = str
arnType = str
assumedRoleIdType = str
clientTokenType = str
contextAssertionType = str
decodedMessageType = str
durationSecondsType = int
encodedMessageType = str
expiredIdentityTokenMessage = str
expiredTradeInTokenExceptionMessage = str
externalIdType = str
federatedIdType = str
idpCommunicationErrorMessage = str
idpRejectedClaimMessage = str
invalidAuthorizationMessage = str
invalidIdentityTokenMessage = str
jwtAlgorithmType = str
jwtPayloadSizeExceededException = str
malformedPolicyDocumentMessage = str
nonNegativeIntegerType = int
outboundWebIdentityFederationDisabledException = str
packedPolicyTooLargeMessage = str
regionDisabledMessage = str
roleDurationSecondsType = int
roleSessionNameType = str
serialNumberType = str
sessionDurationEscalationException = str
sessionPolicyDocumentType = str
sourceIdentityType = str
tagKeyType = str
tagValueType = str
tokenCodeType = str
tokenType = str
tradeInTokenType = str
unrestrictedSessionPolicyDocumentType = str
urlType = str
userIdType = str
userNameType = str
webIdentitySubjectType = str
webIdentityTokenAudienceStringType = str
webIdentityTokenDurationSecondsType = int
webIdentityTokenType = str


class ExpiredTokenException(ServiceException):
    code: str = "ExpiredTokenException"
    sender_fault: bool = True
    status_code: int = 400


class ExpiredTradeInTokenException(ServiceException):
    code: str = "ExpiredTradeInTokenException"
    sender_fault: bool = True
    status_code: int = 400


class IDPCommunicationErrorException(ServiceException):
    code: str = "IDPCommunicationError"
    sender_fault: bool = True
    status_code: int = 400


class IDPRejectedClaimException(ServiceException):
    code: str = "IDPRejectedClaim"
    sender_fault: bool = True
    status_code: int = 403


class InvalidAuthorizationMessageException(ServiceException):
    code: str = "InvalidAuthorizationMessageException"
    sender_fault: bool = True
    status_code: int = 400


class InvalidIdentityTokenException(ServiceException):
    code: str = "InvalidIdentityToken"
    sender_fault: bool = True
    status_code: int = 400


class JWTPayloadSizeExceededException(ServiceException):
    code: str = "JWTPayloadSizeExceededException"
    sender_fault: bool = True
    status_code: int = 400


class MalformedPolicyDocumentException(ServiceException):
    code: str = "MalformedPolicyDocument"
    sender_fault: bool = True
    status_code: int = 400


class OutboundWebIdentityFederationDisabledException(ServiceException):
    code: str = "OutboundWebIdentityFederationDisabledException"
    sender_fault: bool = True
    status_code: int = 403


class PackedPolicyTooLargeException(ServiceException):
    code: str = "PackedPolicyTooLarge"
    sender_fault: bool = True
    status_code: int = 400


class RegionDisabledException(ServiceException):
    code: str = "RegionDisabledException"
    sender_fault: bool = True
    status_code: int = 403


class SessionDurationEscalationException(ServiceException):
    code: str = "SessionDurationEscalationException"
    sender_fault: bool = True
    status_code: int = 403


class ProvidedContext(TypedDict, total=False):
    ProviderArn: arnType | None
    ContextAssertion: contextAssertionType | None


ProvidedContextsListType = list[ProvidedContext]
tagKeyListType = list[tagKeyType]


class Tag(TypedDict, total=False):
    Key: tagKeyType
    Value: tagValueType


tagListType = list[Tag]


class PolicyDescriptorType(TypedDict, total=False):
    arn: arnType | None


policyDescriptorListType = list[PolicyDescriptorType]


class AssumeRoleRequest(ServiceRequest):
    RoleArn: arnType
    RoleSessionName: roleSessionNameType
    PolicyArns: policyDescriptorListType | None
    Policy: unrestrictedSessionPolicyDocumentType | None
    DurationSeconds: roleDurationSecondsType | None
    Tags: tagListType | None
    TransitiveTagKeys: tagKeyListType | None
    ExternalId: externalIdType | None
    SerialNumber: serialNumberType | None
    TokenCode: tokenCodeType | None
    SourceIdentity: sourceIdentityType | None
    ProvidedContexts: ProvidedContextsListType | None


class AssumedRoleUser(TypedDict, total=False):
    AssumedRoleId: assumedRoleIdType
    Arn: arnType


dateType = datetime


class Credentials(TypedDict, total=False):
    AccessKeyId: accessKeyIdType
    SecretAccessKey: accessKeySecretType
    SessionToken: tokenType
    Expiration: dateType


class AssumeRoleResponse(TypedDict, total=False):
    Credentials: Credentials | None
    AssumedRoleUser: AssumedRoleUser | None
    PackedPolicySize: nonNegativeIntegerType | None
    SourceIdentity: sourceIdentityType | None


class AssumeRoleWithSAMLRequest(ServiceRequest):
    RoleArn: arnType
    PrincipalArn: arnType
    SAMLAssertion: SAMLAssertionType
    PolicyArns: policyDescriptorListType | None
    Policy: sessionPolicyDocumentType | None
    DurationSeconds: roleDurationSecondsType | None


class AssumeRoleWithSAMLResponse(TypedDict, total=False):
    Credentials: Credentials | None
    AssumedRoleUser: AssumedRoleUser | None
    PackedPolicySize: nonNegativeIntegerType | None
    Subject: Subject | None
    SubjectType: SubjectType | None
    Issuer: Issuer | None
    Audience: Audience | None
    NameQualifier: NameQualifier | None
    SourceIdentity: sourceIdentityType | None


class AssumeRoleWithWebIdentityRequest(ServiceRequest):
    RoleArn: arnType
    RoleSessionName: roleSessionNameType
    WebIdentityToken: clientTokenType
    ProviderId: urlType | None
    PolicyArns: policyDescriptorListType | None
    Policy: sessionPolicyDocumentType | None
    DurationSeconds: roleDurationSecondsType | None


class AssumeRoleWithWebIdentityResponse(TypedDict, total=False):
    Credentials: Credentials | None
    SubjectFromWebIdentityToken: webIdentitySubjectType | None
    AssumedRoleUser: AssumedRoleUser | None
    PackedPolicySize: nonNegativeIntegerType | None
    Provider: Issuer | None
    Audience: Audience | None
    SourceIdentity: sourceIdentityType | None


class AssumeRootRequest(ServiceRequest):
    TargetPrincipal: TargetPrincipalType
    TaskPolicyArn: PolicyDescriptorType
    DurationSeconds: RootDurationSecondsType | None


class AssumeRootResponse(TypedDict, total=False):
    Credentials: Credentials | None
    SourceIdentity: sourceIdentityType | None


class DecodeAuthorizationMessageRequest(ServiceRequest):
    EncodedMessage: encodedMessageType


class DecodeAuthorizationMessageResponse(TypedDict, total=False):
    DecodedMessage: decodedMessageType | None


class FederatedUser(TypedDict, total=False):
    FederatedUserId: federatedIdType
    Arn: arnType


class GetAccessKeyInfoRequest(ServiceRequest):
    AccessKeyId: accessKeyIdType


class GetAccessKeyInfoResponse(TypedDict, total=False):
    Account: accountType | None


class GetCallerIdentityRequest(ServiceRequest):
    pass


class GetCallerIdentityResponse(TypedDict, total=False):
    UserId: userIdType | None
    Account: accountType | None
    Arn: arnType | None


class GetDelegatedAccessTokenRequest(ServiceRequest):
    TradeInToken: tradeInTokenType


class GetDelegatedAccessTokenResponse(TypedDict, total=False):
    Credentials: Credentials | None
    PackedPolicySize: nonNegativeIntegerType | None
    AssumedPrincipal: arnType | None


class GetFederationTokenRequest(ServiceRequest):
    Name: userNameType
    Policy: sessionPolicyDocumentType | None
    PolicyArns: policyDescriptorListType | None
    DurationSeconds: durationSecondsType | None
    Tags: tagListType | None


class GetFederationTokenResponse(TypedDict, total=False):
    Credentials: Credentials | None
    FederatedUser: FederatedUser | None
    PackedPolicySize: nonNegativeIntegerType | None


class GetSessionTokenRequest(ServiceRequest):
    DurationSeconds: durationSecondsType | None
    SerialNumber: serialNumberType | None
    TokenCode: tokenCodeType | None


class GetSessionTokenResponse(TypedDict, total=False):
    Credentials: Credentials | None


webIdentityTokenAudienceListType = list[webIdentityTokenAudienceStringType]


class GetWebIdentityTokenRequest(ServiceRequest):
    Audience: webIdentityTokenAudienceListType
    DurationSeconds: webIdentityTokenDurationSecondsType | None
    SigningAlgorithm: jwtAlgorithmType
    Tags: tagListType | None


class GetWebIdentityTokenResponse(TypedDict, total=False):
    WebIdentityToken: webIdentityTokenType | None
    Expiration: dateType | None


class StsApi:
    service: str = "sts"
    version: str = "2011-06-15"

    @handler("AssumeRole")
    def assume_role(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        policy_arns: policyDescriptorListType | None = None,
        policy: unrestrictedSessionPolicyDocumentType | None = None,
        duration_seconds: roleDurationSecondsType | None = None,
        tags: tagListType | None = None,
        transitive_tag_keys: tagKeyListType | None = None,
        external_id: externalIdType | None = None,
        serial_number: serialNumberType | None = None,
        token_code: tokenCodeType | None = None,
        source_identity: sourceIdentityType | None = None,
        provided_contexts: ProvidedContextsListType | None = None,
        **kwargs,
    ) -> AssumeRoleResponse:
        raise NotImplementedError

    @handler("AssumeRoleWithSAML")
    def assume_role_with_saml(
        self,
        context: RequestContext,
        role_arn: arnType,
        principal_arn: arnType,
        saml_assertion: SAMLAssertionType,
        policy_arns: policyDescriptorListType | None = None,
        policy: sessionPolicyDocumentType | None = None,
        duration_seconds: roleDurationSecondsType | None = None,
        **kwargs,
    ) -> AssumeRoleWithSAMLResponse:
        raise NotImplementedError

    @handler("AssumeRoleWithWebIdentity")
    def assume_role_with_web_identity(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        web_identity_token: clientTokenType,
        provider_id: urlType | None = None,
        policy_arns: policyDescriptorListType | None = None,
        policy: sessionPolicyDocumentType | None = None,
        duration_seconds: roleDurationSecondsType | None = None,
        **kwargs,
    ) -> AssumeRoleWithWebIdentityResponse:
        raise NotImplementedError

    @handler("AssumeRoot")
    def assume_root(
        self,
        context: RequestContext,
        target_principal: TargetPrincipalType,
        task_policy_arn: PolicyDescriptorType,
        duration_seconds: RootDurationSecondsType | None = None,
        **kwargs,
    ) -> AssumeRootResponse:
        raise NotImplementedError

    @handler("DecodeAuthorizationMessage")
    def decode_authorization_message(
        self, context: RequestContext, encoded_message: encodedMessageType, **kwargs
    ) -> DecodeAuthorizationMessageResponse:
        raise NotImplementedError

    @handler("GetAccessKeyInfo")
    def get_access_key_info(
        self, context: RequestContext, access_key_id: accessKeyIdType, **kwargs
    ) -> GetAccessKeyInfoResponse:
        raise NotImplementedError

    @handler("GetCallerIdentity")
    def get_caller_identity(self, context: RequestContext, **kwargs) -> GetCallerIdentityResponse:
        raise NotImplementedError

    @handler("GetDelegatedAccessToken")
    def get_delegated_access_token(
        self, context: RequestContext, trade_in_token: tradeInTokenType, **kwargs
    ) -> GetDelegatedAccessTokenResponse:
        raise NotImplementedError

    @handler("GetFederationToken")
    def get_federation_token(
        self,
        context: RequestContext,
        name: userNameType,
        policy: sessionPolicyDocumentType | None = None,
        policy_arns: policyDescriptorListType | None = None,
        duration_seconds: durationSecondsType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> GetFederationTokenResponse:
        raise NotImplementedError

    @handler("GetSessionToken")
    def get_session_token(
        self,
        context: RequestContext,
        duration_seconds: durationSecondsType | None = None,
        serial_number: serialNumberType | None = None,
        token_code: tokenCodeType | None = None,
        **kwargs,
    ) -> GetSessionTokenResponse:
        raise NotImplementedError

    @handler("GetWebIdentityToken")
    def get_web_identity_token(
        self,
        context: RequestContext,
        audience: webIdentityTokenAudienceListType,
        signing_algorithm: jwtAlgorithmType,
        duration_seconds: webIdentityTokenDurationSecondsType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> GetWebIdentityTokenResponse:
        raise NotImplementedError
