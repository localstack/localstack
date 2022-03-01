import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arn = str
AvailabilityErrorMessage = str
CertificateBody = str
CertificateChain = str
DomainNameString = str
IdempotencyToken = str
MaxItems = int
NextToken = str
PositiveInteger = int
PrivateKey = str
ServiceErrorMessage = str
String = str
TagKey = str
TagValue = str
ValidationExceptionMessage = str


class CertificateStatus(str):
    PENDING_VALIDATION = "PENDING_VALIDATION"
    ISSUED = "ISSUED"
    INACTIVE = "INACTIVE"
    EXPIRED = "EXPIRED"
    VALIDATION_TIMED_OUT = "VALIDATION_TIMED_OUT"
    REVOKED = "REVOKED"
    FAILED = "FAILED"


class CertificateTransparencyLoggingPreference(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class CertificateType(str):
    IMPORTED = "IMPORTED"
    AMAZON_ISSUED = "AMAZON_ISSUED"
    PRIVATE = "PRIVATE"


class DomainStatus(str):
    PENDING_VALIDATION = "PENDING_VALIDATION"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class ExtendedKeyUsageName(str):
    TLS_WEB_SERVER_AUTHENTICATION = "TLS_WEB_SERVER_AUTHENTICATION"
    TLS_WEB_CLIENT_AUTHENTICATION = "TLS_WEB_CLIENT_AUTHENTICATION"
    CODE_SIGNING = "CODE_SIGNING"
    EMAIL_PROTECTION = "EMAIL_PROTECTION"
    TIME_STAMPING = "TIME_STAMPING"
    OCSP_SIGNING = "OCSP_SIGNING"
    IPSEC_END_SYSTEM = "IPSEC_END_SYSTEM"
    IPSEC_TUNNEL = "IPSEC_TUNNEL"
    IPSEC_USER = "IPSEC_USER"
    ANY = "ANY"
    NONE = "NONE"
    CUSTOM = "CUSTOM"


class FailureReason(str):
    NO_AVAILABLE_CONTACTS = "NO_AVAILABLE_CONTACTS"
    ADDITIONAL_VERIFICATION_REQUIRED = "ADDITIONAL_VERIFICATION_REQUIRED"
    DOMAIN_NOT_ALLOWED = "DOMAIN_NOT_ALLOWED"
    INVALID_PUBLIC_DOMAIN = "INVALID_PUBLIC_DOMAIN"
    DOMAIN_VALIDATION_DENIED = "DOMAIN_VALIDATION_DENIED"
    CAA_ERROR = "CAA_ERROR"
    PCA_LIMIT_EXCEEDED = "PCA_LIMIT_EXCEEDED"
    PCA_INVALID_ARN = "PCA_INVALID_ARN"
    PCA_INVALID_STATE = "PCA_INVALID_STATE"
    PCA_REQUEST_FAILED = "PCA_REQUEST_FAILED"
    PCA_NAME_CONSTRAINTS_VALIDATION = "PCA_NAME_CONSTRAINTS_VALIDATION"
    PCA_RESOURCE_NOT_FOUND = "PCA_RESOURCE_NOT_FOUND"
    PCA_INVALID_ARGS = "PCA_INVALID_ARGS"
    PCA_INVALID_DURATION = "PCA_INVALID_DURATION"
    PCA_ACCESS_DENIED = "PCA_ACCESS_DENIED"
    SLR_NOT_FOUND = "SLR_NOT_FOUND"
    OTHER = "OTHER"


class KeyAlgorithm(str):
    RSA_1024 = "RSA_1024"
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    EC_prime256v1 = "EC_prime256v1"
    EC_secp384r1 = "EC_secp384r1"
    EC_secp521r1 = "EC_secp521r1"


class KeyUsageName(str):
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    NON_REPUDIATION = "NON_REPUDIATION"
    KEY_ENCIPHERMENT = "KEY_ENCIPHERMENT"
    DATA_ENCIPHERMENT = "DATA_ENCIPHERMENT"
    KEY_AGREEMENT = "KEY_AGREEMENT"
    CERTIFICATE_SIGNING = "CERTIFICATE_SIGNING"
    CRL_SIGNING = "CRL_SIGNING"
    ENCIPHER_ONLY = "ENCIPHER_ONLY"
    DECIPHER_ONLY = "DECIPHER_ONLY"
    ANY = "ANY"
    CUSTOM = "CUSTOM"


class RecordType(str):
    CNAME = "CNAME"


class RenewalEligibility(str):
    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"


class RenewalStatus(str):
    PENDING_AUTO_RENEWAL = "PENDING_AUTO_RENEWAL"
    PENDING_VALIDATION = "PENDING_VALIDATION"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class RevocationReason(str):
    UNSPECIFIED = "UNSPECIFIED"
    KEY_COMPROMISE = "KEY_COMPROMISE"
    CA_COMPROMISE = "CA_COMPROMISE"
    AFFILIATION_CHANGED = "AFFILIATION_CHANGED"
    SUPERCEDED = "SUPERCEDED"
    CESSATION_OF_OPERATION = "CESSATION_OF_OPERATION"
    CERTIFICATE_HOLD = "CERTIFICATE_HOLD"
    REMOVE_FROM_CRL = "REMOVE_FROM_CRL"
    PRIVILEGE_WITHDRAWN = "PRIVILEGE_WITHDRAWN"
    A_A_COMPROMISE = "A_A_COMPROMISE"


class ValidationMethod(str):
    EMAIL = "EMAIL"
    DNS = "DNS"


class AccessDeniedException(ServiceException):
    Message: Optional[ServiceErrorMessage]


class ConflictException(ServiceException):
    message: Optional[String]


class InvalidArgsException(ServiceException):
    message: Optional[String]


class InvalidArnException(ServiceException):
    message: Optional[String]


class InvalidDomainValidationOptionsException(ServiceException):
    message: Optional[String]


class InvalidParameterException(ServiceException):
    message: Optional[String]


class InvalidStateException(ServiceException):
    message: Optional[String]


class InvalidTagException(ServiceException):
    message: Optional[String]


class LimitExceededException(ServiceException):
    message: Optional[String]


class RequestInProgressException(ServiceException):
    message: Optional[String]


class ResourceInUseException(ServiceException):
    message: Optional[String]


class ResourceNotFoundException(ServiceException):
    message: Optional[String]


class TagPolicyException(ServiceException):
    message: Optional[String]


class ThrottlingException(ServiceException):
    message: Optional[AvailabilityErrorMessage]


class TooManyTagsException(ServiceException):
    message: Optional[String]


class ValidationException(ServiceException):
    message: Optional[ValidationExceptionMessage]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]


class AddTagsToCertificateRequest(ServiceRequest):
    CertificateArn: Arn
    Tags: TagList


CertificateBodyBlob = bytes
CertificateChainBlob = bytes


class CertificateOptions(TypedDict, total=False):
    CertificateTransparencyLoggingPreference: Optional[CertificateTransparencyLoggingPreference]


class ExtendedKeyUsage(TypedDict, total=False):
    Name: Optional[ExtendedKeyUsageName]
    OID: Optional[String]


ExtendedKeyUsageList = List[ExtendedKeyUsage]


class KeyUsage(TypedDict, total=False):
    Name: Optional[KeyUsageName]


KeyUsageList = List[KeyUsage]
TStamp = datetime


class ResourceRecord(TypedDict, total=False):
    Name: String
    Type: RecordType
    Value: String


ValidationEmailList = List[String]


class DomainValidation(TypedDict, total=False):
    DomainName: DomainNameString
    ValidationEmails: Optional[ValidationEmailList]
    ValidationDomain: Optional[DomainNameString]
    ValidationStatus: Optional[DomainStatus]
    ResourceRecord: Optional[ResourceRecord]
    ValidationMethod: Optional[ValidationMethod]


DomainValidationList = List[DomainValidation]


class RenewalSummary(TypedDict, total=False):
    RenewalStatus: RenewalStatus
    DomainValidationOptions: DomainValidationList
    RenewalStatusReason: Optional[FailureReason]
    UpdatedAt: TStamp


InUseList = List[String]
DomainList = List[DomainNameString]


class CertificateDetail(TypedDict, total=False):
    CertificateArn: Optional[Arn]
    DomainName: Optional[DomainNameString]
    SubjectAlternativeNames: Optional[DomainList]
    DomainValidationOptions: Optional[DomainValidationList]
    Serial: Optional[String]
    Subject: Optional[String]
    Issuer: Optional[String]
    CreatedAt: Optional[TStamp]
    IssuedAt: Optional[TStamp]
    ImportedAt: Optional[TStamp]
    Status: Optional[CertificateStatus]
    RevokedAt: Optional[TStamp]
    RevocationReason: Optional[RevocationReason]
    NotBefore: Optional[TStamp]
    NotAfter: Optional[TStamp]
    KeyAlgorithm: Optional[KeyAlgorithm]
    SignatureAlgorithm: Optional[String]
    InUseBy: Optional[InUseList]
    FailureReason: Optional[FailureReason]
    Type: Optional[CertificateType]
    RenewalSummary: Optional[RenewalSummary]
    KeyUsages: Optional[KeyUsageList]
    ExtendedKeyUsages: Optional[ExtendedKeyUsageList]
    CertificateAuthorityArn: Optional[Arn]
    RenewalEligibility: Optional[RenewalEligibility]
    Options: Optional[CertificateOptions]


CertificateStatuses = List[CertificateStatus]


class CertificateSummary(TypedDict, total=False):
    CertificateArn: Optional[Arn]
    DomainName: Optional[DomainNameString]


CertificateSummaryList = List[CertificateSummary]


class DeleteCertificateRequest(ServiceRequest):
    CertificateArn: Arn


class DescribeCertificateRequest(ServiceRequest):
    CertificateArn: Arn


class DescribeCertificateResponse(TypedDict, total=False):
    Certificate: Optional[CertificateDetail]


class DomainValidationOption(TypedDict, total=False):
    DomainName: DomainNameString
    ValidationDomain: DomainNameString


DomainValidationOptionList = List[DomainValidationOption]


class ExpiryEventsConfiguration(TypedDict, total=False):
    DaysBeforeExpiry: Optional[PositiveInteger]


PassphraseBlob = bytes


class ExportCertificateRequest(ServiceRequest):
    CertificateArn: Arn
    Passphrase: PassphraseBlob


class ExportCertificateResponse(TypedDict, total=False):
    Certificate: Optional[CertificateBody]
    CertificateChain: Optional[CertificateChain]
    PrivateKey: Optional[PrivateKey]


ExtendedKeyUsageFilterList = List[ExtendedKeyUsageName]
KeyAlgorithmList = List[KeyAlgorithm]
KeyUsageFilterList = List[KeyUsageName]


class Filters(TypedDict, total=False):
    extendedKeyUsage: Optional[ExtendedKeyUsageFilterList]
    keyUsage: Optional[KeyUsageFilterList]
    keyTypes: Optional[KeyAlgorithmList]


class GetAccountConfigurationResponse(TypedDict, total=False):
    ExpiryEvents: Optional[ExpiryEventsConfiguration]


class GetCertificateRequest(ServiceRequest):
    CertificateArn: Arn


class GetCertificateResponse(TypedDict, total=False):
    Certificate: Optional[CertificateBody]
    CertificateChain: Optional[CertificateChain]


PrivateKeyBlob = bytes


class ImportCertificateRequest(ServiceRequest):
    CertificateArn: Optional[Arn]
    Certificate: CertificateBodyBlob
    PrivateKey: PrivateKeyBlob
    CertificateChain: Optional[CertificateChainBlob]
    Tags: Optional[TagList]


class ImportCertificateResponse(TypedDict, total=False):
    CertificateArn: Optional[Arn]


class ListCertificatesRequest(ServiceRequest):
    CertificateStatuses: Optional[CertificateStatuses]
    Includes: Optional[Filters]
    NextToken: Optional[NextToken]
    MaxItems: Optional[MaxItems]


class ListCertificatesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    CertificateSummaryList: Optional[CertificateSummaryList]


class ListTagsForCertificateRequest(ServiceRequest):
    CertificateArn: Arn


class ListTagsForCertificateResponse(TypedDict, total=False):
    Tags: Optional[TagList]


class PutAccountConfigurationRequest(ServiceRequest):
    ExpiryEvents: Optional[ExpiryEventsConfiguration]
    IdempotencyToken: IdempotencyToken


class RemoveTagsFromCertificateRequest(ServiceRequest):
    CertificateArn: Arn
    Tags: TagList


class RenewCertificateRequest(ServiceRequest):
    CertificateArn: Arn


class RequestCertificateRequest(ServiceRequest):
    DomainName: DomainNameString
    ValidationMethod: Optional[ValidationMethod]
    SubjectAlternativeNames: Optional[DomainList]
    IdempotencyToken: Optional[IdempotencyToken]
    DomainValidationOptions: Optional[DomainValidationOptionList]
    Options: Optional[CertificateOptions]
    CertificateAuthorityArn: Optional[Arn]
    Tags: Optional[TagList]


class RequestCertificateResponse(TypedDict, total=False):
    CertificateArn: Optional[Arn]


class ResendValidationEmailRequest(ServiceRequest):
    CertificateArn: Arn
    Domain: DomainNameString
    ValidationDomain: DomainNameString


class UpdateCertificateOptionsRequest(ServiceRequest):
    CertificateArn: Arn
    Options: CertificateOptions


class AcmApi:

    service = "acm"
    version = "2015-12-08"

    @handler("AddTagsToCertificate")
    def add_tags_to_certificate(
        self, context: RequestContext, certificate_arn: Arn, tags: TagList
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCertificate")
    def delete_certificate(self, context: RequestContext, certificate_arn: Arn) -> None:
        raise NotImplementedError

    @handler("DescribeCertificate")
    def describe_certificate(
        self, context: RequestContext, certificate_arn: Arn
    ) -> DescribeCertificateResponse:
        raise NotImplementedError

    @handler("ExportCertificate")
    def export_certificate(
        self, context: RequestContext, certificate_arn: Arn, passphrase: PassphraseBlob
    ) -> ExportCertificateResponse:
        raise NotImplementedError

    @handler("GetAccountConfiguration")
    def get_account_configuration(
        self,
        context: RequestContext,
    ) -> GetAccountConfigurationResponse:
        raise NotImplementedError

    @handler("GetCertificate")
    def get_certificate(
        self, context: RequestContext, certificate_arn: Arn
    ) -> GetCertificateResponse:
        raise NotImplementedError

    @handler("ImportCertificate")
    def import_certificate(
        self,
        context: RequestContext,
        certificate: CertificateBodyBlob,
        private_key: PrivateKeyBlob,
        certificate_arn: Arn = None,
        certificate_chain: CertificateChainBlob = None,
        tags: TagList = None,
    ) -> ImportCertificateResponse:
        raise NotImplementedError

    @handler("ListCertificates")
    def list_certificates(
        self,
        context: RequestContext,
        certificate_statuses: CertificateStatuses = None,
        includes: Filters = None,
        next_token: NextToken = None,
        max_items: MaxItems = None,
    ) -> ListCertificatesResponse:
        raise NotImplementedError

    @handler("ListTagsForCertificate")
    def list_tags_for_certificate(
        self, context: RequestContext, certificate_arn: Arn
    ) -> ListTagsForCertificateResponse:
        raise NotImplementedError

    @handler("PutAccountConfiguration")
    def put_account_configuration(
        self,
        context: RequestContext,
        idempotency_token: IdempotencyToken,
        expiry_events: ExpiryEventsConfiguration = None,
    ) -> None:
        raise NotImplementedError

    @handler("RemoveTagsFromCertificate")
    def remove_tags_from_certificate(
        self, context: RequestContext, certificate_arn: Arn, tags: TagList
    ) -> None:
        raise NotImplementedError

    @handler("RenewCertificate")
    def renew_certificate(self, context: RequestContext, certificate_arn: Arn) -> None:
        raise NotImplementedError

    @handler("RequestCertificate")
    def request_certificate(
        self,
        context: RequestContext,
        domain_name: DomainNameString,
        validation_method: ValidationMethod = None,
        subject_alternative_names: DomainList = None,
        idempotency_token: IdempotencyToken = None,
        domain_validation_options: DomainValidationOptionList = None,
        options: CertificateOptions = None,
        certificate_authority_arn: Arn = None,
        tags: TagList = None,
    ) -> RequestCertificateResponse:
        raise NotImplementedError

    @handler("ResendValidationEmail")
    def resend_validation_email(
        self,
        context: RequestContext,
        certificate_arn: Arn,
        domain: DomainNameString,
        validation_domain: DomainNameString,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateCertificateOptions")
    def update_certificate_options(
        self, context: RequestContext, certificate_arn: Arn, options: CertificateOptions
    ) -> None:
        raise NotImplementedError
