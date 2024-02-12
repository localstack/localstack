from datetime import datetime
from typing import List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arn = str
AvailabilityErrorMessage = str
CertificateBody = str
CertificateChain = str
DomainNameString = str
IdempotencyToken = str
MaxItems = int
NextToken = str
NullableBoolean = bool
PcaArn = str
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


class SortBy(str):
    CREATED_AT = "CREATED_AT"


class SortOrder(str):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


class ValidationMethod(str):
    EMAIL = "EMAIL"
    DNS = "DNS"


class AccessDeniedException(ServiceException):
    code: str = "AccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidArgsException(ServiceException):
    code: str = "InvalidArgsException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidArnException(ServiceException):
    code: str = "InvalidArnException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDomainValidationOptionsException(ServiceException):
    code: str = "InvalidDomainValidationOptionsException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterException(ServiceException):
    code: str = "InvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidStateException(ServiceException):
    code: str = "InvalidStateException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTagException(ServiceException):
    code: str = "InvalidTagException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class RequestInProgressException(ServiceException):
    code: str = "RequestInProgressException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class TagPolicyException(ServiceException):
    code: str = "TagPolicyException"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


class TooManyTagsException(ServiceException):
    code: str = "TooManyTagsException"
    sender_fault: bool = False
    status_code: int = 400


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


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
ExtendedKeyUsageNames = List[ExtendedKeyUsageName]
KeyUsageNames = List[KeyUsageName]


class CertificateSummary(TypedDict, total=False):
    CertificateArn: Optional[Arn]
    DomainName: Optional[DomainNameString]
    SubjectAlternativeNameSummaries: Optional[DomainList]
    HasAdditionalSubjectAlternativeNames: Optional[NullableBoolean]
    Status: Optional[CertificateStatus]
    Type: Optional[CertificateType]
    KeyAlgorithm: Optional[KeyAlgorithm]
    KeyUsages: Optional[KeyUsageNames]
    ExtendedKeyUsages: Optional[ExtendedKeyUsageNames]
    InUse: Optional[NullableBoolean]
    Exported: Optional[NullableBoolean]
    RenewalEligibility: Optional[RenewalEligibility]
    NotBefore: Optional[TStamp]
    NotAfter: Optional[TStamp]
    CreatedAt: Optional[TStamp]
    IssuedAt: Optional[TStamp]
    ImportedAt: Optional[TStamp]
    RevokedAt: Optional[TStamp]


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
    SortBy: Optional[SortBy]
    SortOrder: Optional[SortOrder]


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
    CertificateAuthorityArn: Optional[PcaArn]
    Tags: Optional[TagList]
    KeyAlgorithm: Optional[KeyAlgorithm]


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
        self, context: RequestContext, certificate_arn: Arn, tags: TagList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteCertificate")
    def delete_certificate(self, context: RequestContext, certificate_arn: Arn, **kwargs) -> None:
        raise NotImplementedError

    @handler("DescribeCertificate")
    def describe_certificate(
        self, context: RequestContext, certificate_arn: Arn, **kwargs
    ) -> DescribeCertificateResponse:
        raise NotImplementedError

    @handler("ExportCertificate")
    def export_certificate(
        self, context: RequestContext, certificate_arn: Arn, passphrase: PassphraseBlob, **kwargs
    ) -> ExportCertificateResponse:
        raise NotImplementedError

    @handler("GetAccountConfiguration")
    def get_account_configuration(
        self, context: RequestContext, **kwargs
    ) -> GetAccountConfigurationResponse:
        raise NotImplementedError

    @handler("GetCertificate")
    def get_certificate(
        self, context: RequestContext, certificate_arn: Arn, **kwargs
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
        **kwargs
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
        sort_by: SortBy = None,
        sort_order: SortOrder = None,
        **kwargs
    ) -> ListCertificatesResponse:
        raise NotImplementedError

    @handler("ListTagsForCertificate")
    def list_tags_for_certificate(
        self, context: RequestContext, certificate_arn: Arn, **kwargs
    ) -> ListTagsForCertificateResponse:
        raise NotImplementedError

    @handler("PutAccountConfiguration")
    def put_account_configuration(
        self,
        context: RequestContext,
        idempotency_token: IdempotencyToken,
        expiry_events: ExpiryEventsConfiguration = None,
        **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RemoveTagsFromCertificate")
    def remove_tags_from_certificate(
        self, context: RequestContext, certificate_arn: Arn, tags: TagList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("RenewCertificate")
    def renew_certificate(self, context: RequestContext, certificate_arn: Arn, **kwargs) -> None:
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
        certificate_authority_arn: PcaArn = None,
        tags: TagList = None,
        key_algorithm: KeyAlgorithm = None,
        **kwargs
    ) -> RequestCertificateResponse:
        raise NotImplementedError

    @handler("ResendValidationEmail")
    def resend_validation_email(
        self,
        context: RequestContext,
        certificate_arn: Arn,
        domain: DomainNameString,
        validation_domain: DomainNameString,
        **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdateCertificateOptions")
    def update_certificate_options(
        self, context: RequestContext, certificate_arn: Arn, options: CertificateOptions, **kwargs
    ) -> None:
        raise NotImplementedError
