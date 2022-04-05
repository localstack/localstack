import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Audience = str
Issuer = str
NameQualifier = str
SAMLAssertionType = str
Subject = str
SubjectType = str
accessKeyIdType = str
accessKeySecretType = str
accountType = str
arnType = str
assumedRoleIdType = str
clientTokenType = str
decodedMessageType = str
durationSecondsType = int
encodedMessageType = str
expiredIdentityTokenMessage = str
externalIdType = str
federatedIdType = str
idpCommunicationErrorMessage = str
idpRejectedClaimMessage = str
invalidAuthorizationMessage = str
invalidIdentityTokenMessage = str
malformedPolicyDocumentMessage = str
nonNegativeIntegerType = int
packedPolicyTooLargeMessage = str
regionDisabledMessage = str
roleDurationSecondsType = int
roleSessionNameType = str
serialNumberType = str
sessionPolicyDocumentType = str
sourceIdentityType = str
tagKeyType = str
tagValueType = str
tokenCodeType = str
tokenType = str
urlType = str
userIdType = str
userNameType = str
webIdentitySubjectType = str


class ExpiredTokenException(ServiceException):
    message: Optional[expiredIdentityTokenMessage]


class IDPCommunicationErrorException(ServiceException):
    message: Optional[idpCommunicationErrorMessage]


class IDPRejectedClaimException(ServiceException):
    message: Optional[idpRejectedClaimMessage]


class InvalidAuthorizationMessageException(ServiceException):
    message: Optional[invalidAuthorizationMessage]


class InvalidIdentityTokenException(ServiceException):
    message: Optional[invalidIdentityTokenMessage]


class MalformedPolicyDocumentException(ServiceException):
    message: Optional[malformedPolicyDocumentMessage]


class PackedPolicyTooLargeException(ServiceException):
    message: Optional[packedPolicyTooLargeMessage]


class RegionDisabledException(ServiceException):
    message: Optional[regionDisabledMessage]


tagKeyListType = List[tagKeyType]


class Tag(TypedDict, total=False):
    Key: tagKeyType
    Value: tagValueType


tagListType = List[Tag]


class PolicyDescriptorType(TypedDict, total=False):
    arn: Optional[arnType]


policyDescriptorListType = List[PolicyDescriptorType]


class AssumeRoleRequest(ServiceRequest):
    RoleArn: arnType
    RoleSessionName: roleSessionNameType
    PolicyArns: Optional[policyDescriptorListType]
    Policy: Optional[sessionPolicyDocumentType]
    DurationSeconds: Optional[roleDurationSecondsType]
    Tags: Optional[tagListType]
    TransitiveTagKeys: Optional[tagKeyListType]
    ExternalId: Optional[externalIdType]
    SerialNumber: Optional[serialNumberType]
    TokenCode: Optional[tokenCodeType]
    SourceIdentity: Optional[sourceIdentityType]


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
    Credentials: Optional[Credentials]
    AssumedRoleUser: Optional[AssumedRoleUser]
    PackedPolicySize: Optional[nonNegativeIntegerType]
    SourceIdentity: Optional[sourceIdentityType]


class AssumeRoleWithSAMLRequest(ServiceRequest):
    RoleArn: arnType
    PrincipalArn: arnType
    SAMLAssertion: SAMLAssertionType
    PolicyArns: Optional[policyDescriptorListType]
    Policy: Optional[sessionPolicyDocumentType]
    DurationSeconds: Optional[roleDurationSecondsType]


class AssumeRoleWithSAMLResponse(TypedDict, total=False):
    Credentials: Optional[Credentials]
    AssumedRoleUser: Optional[AssumedRoleUser]
    PackedPolicySize: Optional[nonNegativeIntegerType]
    Subject: Optional[Subject]
    SubjectType: Optional[SubjectType]
    Issuer: Optional[Issuer]
    Audience: Optional[Audience]
    NameQualifier: Optional[NameQualifier]
    SourceIdentity: Optional[sourceIdentityType]


class AssumeRoleWithWebIdentityRequest(ServiceRequest):
    RoleArn: arnType
    RoleSessionName: roleSessionNameType
    WebIdentityToken: clientTokenType
    ProviderId: Optional[urlType]
    PolicyArns: Optional[policyDescriptorListType]
    Policy: Optional[sessionPolicyDocumentType]
    DurationSeconds: Optional[roleDurationSecondsType]


class AssumeRoleWithWebIdentityResponse(TypedDict, total=False):
    Credentials: Optional[Credentials]
    SubjectFromWebIdentityToken: Optional[webIdentitySubjectType]
    AssumedRoleUser: Optional[AssumedRoleUser]
    PackedPolicySize: Optional[nonNegativeIntegerType]
    Provider: Optional[Issuer]
    Audience: Optional[Audience]
    SourceIdentity: Optional[sourceIdentityType]


class DecodeAuthorizationMessageRequest(ServiceRequest):
    EncodedMessage: encodedMessageType


class DecodeAuthorizationMessageResponse(TypedDict, total=False):
    DecodedMessage: Optional[decodedMessageType]


class FederatedUser(TypedDict, total=False):
    FederatedUserId: federatedIdType
    Arn: arnType


class GetAccessKeyInfoRequest(ServiceRequest):
    AccessKeyId: accessKeyIdType


class GetAccessKeyInfoResponse(TypedDict, total=False):
    Account: Optional[accountType]


class GetCallerIdentityRequest(ServiceRequest):
    pass


class GetCallerIdentityResponse(TypedDict, total=False):
    UserId: Optional[userIdType]
    Account: Optional[accountType]
    Arn: Optional[arnType]


class GetFederationTokenRequest(ServiceRequest):
    Name: userNameType
    Policy: Optional[sessionPolicyDocumentType]
    PolicyArns: Optional[policyDescriptorListType]
    DurationSeconds: Optional[durationSecondsType]
    Tags: Optional[tagListType]


class GetFederationTokenResponse(TypedDict, total=False):
    Credentials: Optional[Credentials]
    FederatedUser: Optional[FederatedUser]
    PackedPolicySize: Optional[nonNegativeIntegerType]


class GetSessionTokenRequest(ServiceRequest):
    DurationSeconds: Optional[durationSecondsType]
    SerialNumber: Optional[serialNumberType]
    TokenCode: Optional[tokenCodeType]


class GetSessionTokenResponse(TypedDict, total=False):
    Credentials: Optional[Credentials]


class StsApi:

    service = "sts"
    version = "2011-06-15"

    @handler("AssumeRole")
    def assume_role(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        policy_arns: policyDescriptorListType = None,
        policy: sessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        tags: tagListType = None,
        transitive_tag_keys: tagKeyListType = None,
        external_id: externalIdType = None,
        serial_number: serialNumberType = None,
        token_code: tokenCodeType = None,
        source_identity: sourceIdentityType = None,
    ) -> AssumeRoleResponse:
        raise NotImplementedError

    @handler("AssumeRoleWithSAML")
    def assume_role_with_saml(
        self,
        context: RequestContext,
        role_arn: arnType,
        principal_arn: arnType,
        saml_assertion: SAMLAssertionType,
        policy_arns: policyDescriptorListType = None,
        policy: sessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
    ) -> AssumeRoleWithSAMLResponse:
        raise NotImplementedError

    @handler("AssumeRoleWithWebIdentity")
    def assume_role_with_web_identity(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        web_identity_token: clientTokenType,
        provider_id: urlType = None,
        policy_arns: policyDescriptorListType = None,
        policy: sessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
    ) -> AssumeRoleWithWebIdentityResponse:
        raise NotImplementedError

    @handler("DecodeAuthorizationMessage")
    def decode_authorization_message(
        self, context: RequestContext, encoded_message: encodedMessageType
    ) -> DecodeAuthorizationMessageResponse:
        raise NotImplementedError

    @handler("GetAccessKeyInfo")
    def get_access_key_info(
        self, context: RequestContext, access_key_id: accessKeyIdType
    ) -> GetAccessKeyInfoResponse:
        raise NotImplementedError

    @handler("GetCallerIdentity")
    def get_caller_identity(
        self,
        context: RequestContext,
    ) -> GetCallerIdentityResponse:
        raise NotImplementedError

    @handler("GetFederationToken")
    def get_federation_token(
        self,
        context: RequestContext,
        name: userNameType,
        policy: sessionPolicyDocumentType = None,
        policy_arns: policyDescriptorListType = None,
        duration_seconds: durationSecondsType = None,
        tags: tagListType = None,
    ) -> GetFederationTokenResponse:
        raise NotImplementedError

    @handler("GetSessionToken")
    def get_session_token(
        self,
        context: RequestContext,
        duration_seconds: durationSecondsType = None,
        serial_number: serialNumberType = None,
        token_code: tokenCodeType = None,
    ) -> GetSessionTokenResponse:
        raise NotImplementedError
