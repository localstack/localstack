from datetime import datetime
from typing import List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ASN1PrintableString64 = str
AWSPolicy = str
AccountId = str
Arn = str
AuditReportId = str
Base64String1To4096 = str
Boolean = bool
CertificateBody = str
CertificateChain = str
CnameString = str
CountryCodeString = str
CsrBody = str
CustomObjectIdentifier = str
IdempotencyToken = str
Integer1To5000 = int
MaxResults = int
NextToken = str
PermanentDeletionTimeInDays = int
Principal = str
S3BucketName = str
S3BucketName3To255 = str
S3Key = str
String = str
String128 = str
String16 = str
String1To256 = str
String253 = str
String256 = str
String3 = str
String39 = str
String40 = str
String5 = str
String64 = str
TagKey = str
TagValue = str


class AccessMethodType(str):
    CA_REPOSITORY = "CA_REPOSITORY"
    RESOURCE_PKI_MANIFEST = "RESOURCE_PKI_MANIFEST"
    RESOURCE_PKI_NOTIFY = "RESOURCE_PKI_NOTIFY"


class ActionType(str):
    IssueCertificate = "IssueCertificate"
    GetCertificate = "GetCertificate"
    ListPermissions = "ListPermissions"


class AuditReportResponseFormat(str):
    JSON = "JSON"
    CSV = "CSV"


class AuditReportStatus(str):
    CREATING = "CREATING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class CertificateAuthorityStatus(str):
    CREATING = "CREATING"
    PENDING_CERTIFICATE = "PENDING_CERTIFICATE"
    ACTIVE = "ACTIVE"
    DELETED = "DELETED"
    DISABLED = "DISABLED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class CertificateAuthorityType(str):
    ROOT = "ROOT"
    SUBORDINATE = "SUBORDINATE"


class CertificateAuthorityUsageMode(str):
    GENERAL_PURPOSE = "GENERAL_PURPOSE"
    SHORT_LIVED_CERTIFICATE = "SHORT_LIVED_CERTIFICATE"


class ExtendedKeyUsageType(str):
    SERVER_AUTH = "SERVER_AUTH"
    CLIENT_AUTH = "CLIENT_AUTH"
    CODE_SIGNING = "CODE_SIGNING"
    EMAIL_PROTECTION = "EMAIL_PROTECTION"
    TIME_STAMPING = "TIME_STAMPING"
    OCSP_SIGNING = "OCSP_SIGNING"
    SMART_CARD_LOGIN = "SMART_CARD_LOGIN"
    DOCUMENT_SIGNING = "DOCUMENT_SIGNING"
    CERTIFICATE_TRANSPARENCY = "CERTIFICATE_TRANSPARENCY"


class FailureReason(str):
    REQUEST_TIMED_OUT = "REQUEST_TIMED_OUT"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    OTHER = "OTHER"


class KeyAlgorithm(str):
    RSA_2048 = "RSA_2048"
    RSA_4096 = "RSA_4096"
    EC_prime256v1 = "EC_prime256v1"
    EC_secp384r1 = "EC_secp384r1"


class KeyStorageSecurityStandard(str):
    FIPS_140_2_LEVEL_2_OR_HIGHER = "FIPS_140_2_LEVEL_2_OR_HIGHER"
    FIPS_140_2_LEVEL_3_OR_HIGHER = "FIPS_140_2_LEVEL_3_OR_HIGHER"


class PolicyQualifierId(str):
    CPS = "CPS"


class ResourceOwner(str):
    SELF = "SELF"
    OTHER_ACCOUNTS = "OTHER_ACCOUNTS"


class RevocationReason(str):
    UNSPECIFIED = "UNSPECIFIED"
    KEY_COMPROMISE = "KEY_COMPROMISE"
    CERTIFICATE_AUTHORITY_COMPROMISE = "CERTIFICATE_AUTHORITY_COMPROMISE"
    AFFILIATION_CHANGED = "AFFILIATION_CHANGED"
    SUPERSEDED = "SUPERSEDED"
    CESSATION_OF_OPERATION = "CESSATION_OF_OPERATION"
    PRIVILEGE_WITHDRAWN = "PRIVILEGE_WITHDRAWN"
    A_A_COMPROMISE = "A_A_COMPROMISE"


class S3ObjectAcl(str):
    PUBLIC_READ = "PUBLIC_READ"
    BUCKET_OWNER_FULL_CONTROL = "BUCKET_OWNER_FULL_CONTROL"


class SigningAlgorithm(str):
    SHA256WITHECDSA = "SHA256WITHECDSA"
    SHA384WITHECDSA = "SHA384WITHECDSA"
    SHA512WITHECDSA = "SHA512WITHECDSA"
    SHA256WITHRSA = "SHA256WITHRSA"
    SHA384WITHRSA = "SHA384WITHRSA"
    SHA512WITHRSA = "SHA512WITHRSA"


class ValidityPeriodType(str):
    END_DATE = "END_DATE"
    ABSOLUTE = "ABSOLUTE"
    DAYS = "DAYS"
    MONTHS = "MONTHS"
    YEARS = "YEARS"


class CertificateMismatchException(ServiceException):
    """The certificate authority certificate you are importing does not comply
    with conditions specified in the certificate that signed it.
    """

    code: str = "CertificateMismatchException"
    sender_fault: bool = False
    status_code: int = 400


class ConcurrentModificationException(ServiceException):
    """A previous update to your private CA is still ongoing."""

    code: str = "ConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidArgsException(ServiceException):
    """One or more of the specified arguments was not valid."""

    code: str = "InvalidArgsException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidArnException(ServiceException):
    """The requested Amazon Resource Name (ARN) does not refer to an existing
    resource.
    """

    code: str = "InvalidArnException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidNextTokenException(ServiceException):
    """The token specified in the ``NextToken`` argument is not valid. Use the
    token returned from your previous call to
    `ListCertificateAuthorities <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html>`__.
    """

    code: str = "InvalidNextTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidPolicyException(ServiceException):
    """The resource policy is invalid or is missing a required statement. For
    general information about IAM policy and statement structure, see
    `Overview of JSON
    Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json>`__.
    """

    code: str = "InvalidPolicyException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRequestException(ServiceException):
    """The request action cannot be performed or is prohibited."""

    code: str = "InvalidRequestException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidStateException(ServiceException):
    """The state of the private CA does not allow this action to occur."""

    code: str = "InvalidStateException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTagException(ServiceException):
    """The tag associated with the CA is not valid. The invalid argument is
    contained in the message field.
    """

    code: str = "InvalidTagException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    """An Amazon Web Services Private CA quota has been exceeded. See the
    exception message returned to determine the quota that was exceeded.
    """

    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class LockoutPreventedException(ServiceException):
    """The current action was prevented because it would lock the caller out
    from performing subsequent actions. Verify that the specified parameters
    would not result in the caller being denied access to the resource.
    """

    code: str = "LockoutPreventedException"
    sender_fault: bool = False
    status_code: int = 400


class MalformedCSRException(ServiceException):
    """The certificate signing request is invalid."""

    code: str = "MalformedCSRException"
    sender_fault: bool = False
    status_code: int = 400


class MalformedCertificateException(ServiceException):
    """One or more fields in the certificate are invalid."""

    code: str = "MalformedCertificateException"
    sender_fault: bool = False
    status_code: int = 400


class PermissionAlreadyExistsException(ServiceException):
    """The designated permission has already been given to the user."""

    code: str = "PermissionAlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class RequestAlreadyProcessedException(ServiceException):
    """Your request has already been completed."""

    code: str = "RequestAlreadyProcessedException"
    sender_fault: bool = False
    status_code: int = 400


class RequestFailedException(ServiceException):
    """The request has failed for an unspecified reason."""

    code: str = "RequestFailedException"
    sender_fault: bool = False
    status_code: int = 400


class RequestInProgressException(ServiceException):
    """Your request is already in progress."""

    code: str = "RequestInProgressException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    """A resource such as a private CA, S3 bucket, certificate, audit report,
    or policy cannot be found.
    """

    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class TooManyTagsException(ServiceException):
    """You can associate up to 50 tags with a private CA. Exception information
    is contained in the exception message field.
    """

    code: str = "TooManyTagsException"
    sender_fault: bool = False
    status_code: int = 400


class CustomAttribute(TypedDict, total=False):
    """Defines the X.500 relative distinguished name (RDN)."""

    ObjectIdentifier: CustomObjectIdentifier
    Value: String1To256


CustomAttributeList = List[CustomAttribute]


class ASN1Subject(TypedDict, total=False):
    """Contains information about the certificate subject. The ``Subject``
    field in the certificate identifies the entity that owns or controls the
    public key in the certificate. The entity can be a user, computer,
    device, or service. The ``Subject`` must contain an X.500 distinguished
    name (DN). A DN is a sequence of relative distinguished names (RDNs).
    The RDNs are separated by commas in the certificate.
    """

    Country: Optional[CountryCodeString]
    Organization: Optional[String64]
    OrganizationalUnit: Optional[String64]
    DistinguishedNameQualifier: Optional[ASN1PrintableString64]
    State: Optional[String128]
    CommonName: Optional[String64]
    SerialNumber: Optional[ASN1PrintableString64]
    Locality: Optional[String128]
    Title: Optional[String64]
    Surname: Optional[String40]
    GivenName: Optional[String16]
    Initials: Optional[String5]
    Pseudonym: Optional[String128]
    GenerationQualifier: Optional[String3]
    CustomAttributes: Optional[CustomAttributeList]


class EdiPartyName(TypedDict, total=False):
    """Describes an Electronic Data Interchange (EDI) entity as described in as
    defined in `Subject Alternative
    Name <https://datatracker.ietf.org/doc/html/rfc5280>`__ in RFC 5280.
    """

    PartyName: String256
    NameAssigner: Optional[String256]


class OtherName(TypedDict, total=False):
    """Defines a custom ASN.1 X.400 ``GeneralName`` using an object identifier
    (OID) and value. The OID must satisfy the regular expression shown
    below. For more information, see NIST's definition of `Object Identifier
    (OID) <https://csrc.nist.gov/glossary/term/Object_Identifier>`__.
    """

    TypeId: CustomObjectIdentifier
    Value: String256


class GeneralName(TypedDict, total=False):
    """Describes an ASN.1 X.400 ``GeneralName`` as defined in `RFC
    5280 <https://datatracker.ietf.org/doc/html/rfc5280>`__. Only one of the
    following naming options should be provided. Providing more than one
    option results in an ``InvalidArgsException`` error.
    """

    OtherName: Optional[OtherName]
    Rfc822Name: Optional[String256]
    DnsName: Optional[String253]
    DirectoryName: Optional[ASN1Subject]
    EdiPartyName: Optional[EdiPartyName]
    UniformResourceIdentifier: Optional[String253]
    IpAddress: Optional[String39]
    RegisteredId: Optional[CustomObjectIdentifier]


class AccessMethod(TypedDict, total=False):
    """Describes the type and format of extension access. Only one of
    ``CustomObjectIdentifier`` or ``AccessMethodType`` may be provided.
    Providing both results in ``InvalidArgsException``.
    """

    CustomObjectIdentifier: Optional[CustomObjectIdentifier]
    AccessMethodType: Optional[AccessMethodType]


class AccessDescription(TypedDict, total=False):
    """Provides access information used by the ``authorityInfoAccess`` and
    ``subjectInfoAccess`` extensions described in `RFC
    5280 <https://datatracker.ietf.org/doc/html/rfc5280>`__.
    """

    AccessMethod: AccessMethod
    AccessLocation: GeneralName


AccessDescriptionList = List[AccessDescription]
ActionList = List[ActionType]


class CustomExtension(TypedDict, total=False):
    """Specifies the X.509 extension information for a certificate.

    Extensions present in ``CustomExtensions`` follow the ``ApiPassthrough``
    `template
    rules <https://docs.aws.amazon.com/privateca/latest/userguide/UsingTemplates.html#template-order-of-operations>`__.
    """

    ObjectIdentifier: CustomObjectIdentifier
    Value: Base64String1To4096
    Critical: Optional[Boolean]


CustomExtensionList = List[CustomExtension]
GeneralNameList = List[GeneralName]


class KeyUsage(TypedDict, total=False):
    """Defines one or more purposes for which the key contained in the
    certificate can be used. Default value for each option is false.
    """

    DigitalSignature: Optional[Boolean]
    NonRepudiation: Optional[Boolean]
    KeyEncipherment: Optional[Boolean]
    DataEncipherment: Optional[Boolean]
    KeyAgreement: Optional[Boolean]
    KeyCertSign: Optional[Boolean]
    CRLSign: Optional[Boolean]
    EncipherOnly: Optional[Boolean]
    DecipherOnly: Optional[Boolean]


class ExtendedKeyUsage(TypedDict, total=False):
    """Specifies additional purposes for which the certified public key may be
    used other than basic purposes indicated in the ``KeyUsage`` extension.
    """

    ExtendedKeyUsageType: Optional[ExtendedKeyUsageType]
    ExtendedKeyUsageObjectIdentifier: Optional[CustomObjectIdentifier]


ExtendedKeyUsageList = List[ExtendedKeyUsage]


class Qualifier(TypedDict, total=False):
    """Defines a ``PolicyInformation`` qualifier. Amazon Web Services Private
    CA supports the `certification practice statement (CPS)
    qualifier <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4>`__
    defined in RFC 5280.
    """

    CpsUri: String256


class PolicyQualifierInfo(TypedDict, total=False):
    """Modifies the ``CertPolicyId`` of a ``PolicyInformation`` object with a
    qualifier. Amazon Web Services Private CA supports the certification
    practice statement (CPS) qualifier.
    """

    PolicyQualifierId: PolicyQualifierId
    Qualifier: Qualifier


PolicyQualifierInfoList = List[PolicyQualifierInfo]


class PolicyInformation(TypedDict, total=False):
    """Defines the X.509 ``CertificatePolicies`` extension."""

    CertPolicyId: CustomObjectIdentifier
    PolicyQualifiers: Optional[PolicyQualifierInfoList]


CertificatePolicyList = List[PolicyInformation]


class Extensions(TypedDict, total=False):
    """Contains X.509 extension information for a certificate."""

    CertificatePolicies: Optional[CertificatePolicyList]
    ExtendedKeyUsage: Optional[ExtendedKeyUsageList]
    KeyUsage: Optional[KeyUsage]
    SubjectAlternativeNames: Optional[GeneralNameList]
    CustomExtensions: Optional[CustomExtensionList]


class ApiPassthrough(TypedDict, total=False):
    """Contains X.509 certificate information to be placed in an issued
    certificate. An ``APIPassthrough`` or ``APICSRPassthrough`` template
    variant must be selected, or else this parameter is ignored.

    If conflicting or duplicate certificate information is supplied from
    other sources, Amazon Web Services Private CA applies `order of
    operation
    rules <https://docs.aws.amazon.com/privateca/latest/userguide/UsingTemplates.html#template-order-of-operations>`__
    to determine what information is used.
    """

    Extensions: Optional[Extensions]
    Subject: Optional[ASN1Subject]


TStamp = datetime


class OcspConfiguration(TypedDict, total=False):
    """Contains information to enable and configure Online Certificate Status
    Protocol (OCSP) for validating certificate revocation status.

    When you revoke a certificate, OCSP responses may take up to 60 minutes
    to reflect the new status.
    """

    Enabled: Boolean
    OcspCustomCname: Optional[CnameString]


class CrlConfiguration(TypedDict, total=False):
    """Contains configuration information for a certificate revocation list
    (CRL). Your private certificate authority (CA) creates base CRLs. Delta
    CRLs are not supported. You can enable CRLs for your new or an existing
    private CA by setting the **Enabled** parameter to ``true``. Your
    private CA writes CRLs to an S3 bucket that you specify in the
    **S3BucketName** parameter. You can hide the name of your bucket by
    specifying a value for the **CustomCname** parameter. Your private CA
    copies the CNAME or the S3 bucket name to the **CRL Distribution
    Points** extension of each certificate it issues. Your S3 bucket policy
    must give write permission to Amazon Web Services Private CA.

    Amazon Web Services Private CA assets that are stored in Amazon S3 can
    be protected with encryption. For more information, see `Encrypting Your
    CRLs <https://docs.aws.amazon.com/privateca/latest/userguide/PcaCreateCa.html#crl-encryption>`__.

    Your private CA uses the value in the **ExpirationInDays** parameter to
    calculate the **nextUpdate** field in the CRL. The CRL is refreshed
    prior to a certificate's expiration date or when a certificate is
    revoked. When a certificate is revoked, it appears in the CRL until the
    certificate expires, and then in one additional CRL after expiration,
    and it always appears in the audit report.

    A CRL is typically updated approximately 30 minutes after a certificate
    is revoked. If for any reason a CRL update fails, Amazon Web Services
    Private CA makes further attempts every 15 minutes.

    CRLs contain the following fields:

    -  **Version**: The current version number defined in RFC 5280 is V2.
       The integer value is 0x1.

    -  **Signature Algorithm**: The name of the algorithm used to sign the
       CRL.

    -  **Issuer**: The X.500 distinguished name of your private CA that
       issued the CRL.

    -  **Last Update**: The issue date and time of this CRL.

    -  **Next Update**: The day and time by which the next CRL will be
       issued.

    -  **Revoked Certificates**: List of revoked certificates. Each list
       item contains the following information.

       -  **Serial Number**: The serial number, in hexadecimal format, of
          the revoked certificate.

       -  **Revocation Date**: Date and time the certificate was revoked.

       -  **CRL Entry Extensions**: Optional extensions for the CRL entry.

          -  **X509v3 CRL Reason Code**: Reason the certificate was revoked.

    -  **CRL Extensions**: Optional extensions for the CRL.

       -  **X509v3 Authority Key Identifier**: Identifies the public key
          associated with the private key used to sign the certificate.

       -  **X509v3 CRL Number:**: Decimal sequence number for the CRL.

    -  **Signature Algorithm**: Algorithm used by your private CA to sign
       the CRL.

    -  **Signature Value**: Signature computed over the CRL.

    Certificate revocation lists created by Amazon Web Services Private CA
    are DER-encoded. You can use the following OpenSSL command to list a
    CRL.

    ``openssl crl -inform DER -text -in`` *``crl_path``* ``-noout``

    For more information, see `Planning a certificate revocation list
    (CRL) <https://docs.aws.amazon.com/privateca/latest/userguide/crl-planning.html>`__
    in the *Amazon Web Services Private Certificate Authority User Guide*
    """

    Enabled: Boolean
    ExpirationInDays: Optional[Integer1To5000]
    CustomCname: Optional[CnameString]
    S3BucketName: Optional[S3BucketName3To255]
    S3ObjectAcl: Optional[S3ObjectAcl]


class RevocationConfiguration(TypedDict, total=False):
    """Certificate revocation information used by the
    `CreateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html>`__
    and
    `UpdateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_UpdateCertificateAuthority.html>`__
    actions. Your private certificate authority (CA) can configure Online
    Certificate Status Protocol (OCSP) support and/or maintain a certificate
    revocation list (CRL). OCSP returns validation information about
    certificates as requested by clients, and a CRL contains an updated list
    of certificates revoked by your CA. For more information, see
    `RevokeCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_RevokeCertificate.html>`__
    and `Setting up a certificate revocation
    method <https://docs.aws.amazon.com/privateca/latest/userguide/revocation-setup.html>`__
    in the *Amazon Web Services Private Certificate Authority User Guide*.
    """

    CrlConfiguration: Optional[CrlConfiguration]
    OcspConfiguration: Optional[OcspConfiguration]


class CsrExtensions(TypedDict, total=False):
    """Describes the certificate extensions to be added to the certificate
    signing request (CSR).
    """

    KeyUsage: Optional[KeyUsage]
    SubjectInformationAccess: Optional[AccessDescriptionList]


class CertificateAuthorityConfiguration(TypedDict, total=False):
    """Contains configuration information for your private certificate
    authority (CA). This includes information about the class of public key
    algorithm and the key pair that your private CA creates when it issues a
    certificate. It also includes the signature algorithm that it uses when
    issuing certificates, and its X.500 distinguished name. You must specify
    this information when you call the
    `CreateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html>`__
    action.
    """

    KeyAlgorithm: KeyAlgorithm
    SigningAlgorithm: SigningAlgorithm
    Subject: ASN1Subject
    CsrExtensions: Optional[CsrExtensions]


class CertificateAuthority(TypedDict, total=False):
    """Contains information about your private certificate authority (CA). Your
    private CA can issue and revoke X.509 digital certificates. Digital
    certificates verify that the entity named in the certificate **Subject**
    field owns or controls the public key contained in the **Subject Public
    Key Info** field. Call the
    `CreateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html>`__
    action to create your private CA. You must then call the
    `GetCertificateAuthorityCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_GetCertificateAuthorityCertificate.html>`__
    action to retrieve a private CA certificate signing request (CSR). Sign
    the CSR with your Amazon Web Services Private CA-hosted or on-premises
    root or subordinate CA certificate. Call the
    `ImportCertificateAuthorityCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ImportCertificateAuthorityCertificate.html>`__
    action to import the signed certificate into Certificate Manager (ACM).
    """

    Arn: Optional[Arn]
    OwnerAccount: Optional[AccountId]
    CreatedAt: Optional[TStamp]
    LastStateChangeAt: Optional[TStamp]
    Type: Optional[CertificateAuthorityType]
    Serial: Optional[String]
    Status: Optional[CertificateAuthorityStatus]
    NotBefore: Optional[TStamp]
    NotAfter: Optional[TStamp]
    FailureReason: Optional[FailureReason]
    CertificateAuthorityConfiguration: Optional[CertificateAuthorityConfiguration]
    RevocationConfiguration: Optional[RevocationConfiguration]
    RestorableUntil: Optional[TStamp]
    KeyStorageSecurityStandard: Optional[KeyStorageSecurityStandard]
    UsageMode: Optional[CertificateAuthorityUsageMode]


CertificateAuthorities = List[CertificateAuthority]
CertificateBodyBlob = bytes
CertificateChainBlob = bytes


class CreateCertificateAuthorityAuditReportRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    S3BucketName: S3BucketName
    AuditReportResponseFormat: AuditReportResponseFormat


class CreateCertificateAuthorityAuditReportResponse(TypedDict, total=False):
    AuditReportId: Optional[AuditReportId]
    S3Key: Optional[S3Key]


class Tag(TypedDict, total=False):
    """Tags are labels that you can use to identify and organize your private
    CAs. Each tag consists of a key and an optional value. You can associate
    up to 50 tags with a private CA. To add one or more tags to a private
    CA, call the
    `TagCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_TagCertificateAuthority.html>`__
    action. To remove a tag, call the
    `UntagCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_UntagCertificateAuthority.html>`__
    action.
    """

    Key: TagKey
    Value: Optional[TagValue]


TagList = List[Tag]


class CreateCertificateAuthorityRequest(ServiceRequest):
    CertificateAuthorityConfiguration: CertificateAuthorityConfiguration
    RevocationConfiguration: Optional[RevocationConfiguration]
    CertificateAuthorityType: CertificateAuthorityType
    IdempotencyToken: Optional[IdempotencyToken]
    KeyStorageSecurityStandard: Optional[KeyStorageSecurityStandard]
    Tags: Optional[TagList]
    UsageMode: Optional[CertificateAuthorityUsageMode]


class CreateCertificateAuthorityResponse(TypedDict, total=False):
    CertificateAuthorityArn: Optional[Arn]


class CreatePermissionRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    Principal: Principal
    SourceAccount: Optional[AccountId]
    Actions: ActionList


CsrBlob = bytes


class DeleteCertificateAuthorityRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    PermanentDeletionTimeInDays: Optional[PermanentDeletionTimeInDays]


class DeletePermissionRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    Principal: Principal
    SourceAccount: Optional[AccountId]


class DeletePolicyRequest(ServiceRequest):
    ResourceArn: Arn


class DescribeCertificateAuthorityAuditReportRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    AuditReportId: AuditReportId


class DescribeCertificateAuthorityAuditReportResponse(TypedDict, total=False):
    AuditReportStatus: Optional[AuditReportStatus]
    S3BucketName: Optional[S3BucketName]
    S3Key: Optional[S3Key]
    CreatedAt: Optional[TStamp]


class DescribeCertificateAuthorityRequest(ServiceRequest):
    CertificateAuthorityArn: Arn


class DescribeCertificateAuthorityResponse(TypedDict, total=False):
    CertificateAuthority: Optional[CertificateAuthority]


class GetCertificateAuthorityCertificateRequest(ServiceRequest):
    CertificateAuthorityArn: Arn


class GetCertificateAuthorityCertificateResponse(TypedDict, total=False):
    Certificate: Optional[CertificateBody]
    CertificateChain: Optional[CertificateChain]


class GetCertificateAuthorityCsrRequest(ServiceRequest):
    CertificateAuthorityArn: Arn


class GetCertificateAuthorityCsrResponse(TypedDict, total=False):
    Csr: Optional[CsrBody]


class GetCertificateRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    CertificateArn: Arn


class GetCertificateResponse(TypedDict, total=False):
    Certificate: Optional[CertificateBody]
    CertificateChain: Optional[CertificateChain]


class GetPolicyRequest(ServiceRequest):
    ResourceArn: Arn


class GetPolicyResponse(TypedDict, total=False):
    Policy: Optional[AWSPolicy]


class ImportCertificateAuthorityCertificateRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    Certificate: CertificateBodyBlob
    CertificateChain: Optional[CertificateChainBlob]


PositiveLong = int


class Validity(TypedDict, total=False):
    """Validity specifies the period of time during which a certificate is
    valid. Validity can be expressed as an explicit date and time when the
    validity of a certificate starts or expires, or as a span of time after
    issuance, stated in days, months, or years. For more information, see
    `Validity <https://tools.ietf.org/html/rfc5280#section-4.1.2.5>`__ in
    RFC 5280.

    Amazon Web Services Private CA API consumes the ``Validity`` data type
    differently in two distinct parameters of the ``IssueCertificate``
    action. The required parameter ``IssueCertificate``:``Validity``
    specifies the end of a certificate's validity period. The optional
    parameter ``IssueCertificate``:``ValidityNotBefore`` specifies a
    customized starting time for the validity period.
    """

    Value: PositiveLong
    Type: ValidityPeriodType


class IssueCertificateRequest(ServiceRequest):
    ApiPassthrough: Optional[ApiPassthrough]
    CertificateAuthorityArn: Arn
    Csr: CsrBlob
    SigningAlgorithm: SigningAlgorithm
    TemplateArn: Optional[Arn]
    Validity: Validity
    ValidityNotBefore: Optional[Validity]
    IdempotencyToken: Optional[IdempotencyToken]


class IssueCertificateResponse(TypedDict, total=False):
    CertificateArn: Optional[Arn]


class ListCertificateAuthoritiesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    ResourceOwner: Optional[ResourceOwner]


class ListCertificateAuthoritiesResponse(TypedDict, total=False):
    CertificateAuthorities: Optional[CertificateAuthorities]
    NextToken: Optional[NextToken]


class ListPermissionsRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class Permission(TypedDict, total=False):
    """Permissions designate which private CA actions can be performed by an
    Amazon Web Services service or entity. In order for ACM to automatically
    renew private certificates, you must give the ACM service principal all
    available permissions (``IssueCertificate``, ``GetCertificate``, and
    ``ListPermissions``). Permissions can be assigned with the
    `CreatePermission <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreatePermission.html>`__
    action, removed with the
    `DeletePermission <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DeletePermission.html>`__
    action, and listed with the
    `ListPermissions <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListPermissions.html>`__
    action.
    """

    CertificateAuthorityArn: Optional[Arn]
    CreatedAt: Optional[TStamp]
    Principal: Optional[Principal]
    SourceAccount: Optional[AccountId]
    Actions: Optional[ActionList]
    Policy: Optional[AWSPolicy]


PermissionList = List[Permission]


class ListPermissionsResponse(TypedDict, total=False):
    Permissions: Optional[PermissionList]
    NextToken: Optional[NextToken]


class ListTagsRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListTagsResponse(TypedDict, total=False):
    Tags: Optional[TagList]
    NextToken: Optional[NextToken]


class PutPolicyRequest(ServiceRequest):
    ResourceArn: Arn
    Policy: AWSPolicy


class RestoreCertificateAuthorityRequest(ServiceRequest):
    CertificateAuthorityArn: Arn


class RevokeCertificateRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    CertificateSerial: String128
    RevocationReason: RevocationReason


class TagCertificateAuthorityRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    Tags: TagList


class UntagCertificateAuthorityRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    Tags: TagList


class UpdateCertificateAuthorityRequest(ServiceRequest):
    CertificateAuthorityArn: Arn
    RevocationConfiguration: Optional[RevocationConfiguration]
    Status: Optional[CertificateAuthorityStatus]


class AcmPcaApi:
    service = "acm-pca"
    version = "2017-08-22"

    @handler("CreateCertificateAuthority")
    def create_certificate_authority(
        self,
        context: RequestContext,
        certificate_authority_configuration: CertificateAuthorityConfiguration,
        certificate_authority_type: CertificateAuthorityType,
        revocation_configuration: RevocationConfiguration = None,
        idempotency_token: IdempotencyToken = None,
        key_storage_security_standard: KeyStorageSecurityStandard = None,
        tags: TagList = None,
        usage_mode: CertificateAuthorityUsageMode = None,
    ) -> CreateCertificateAuthorityResponse:
        """Creates a root or subordinate private certificate authority (CA). You
        must specify the CA configuration, an optional configuration for Online
        Certificate Status Protocol (OCSP) and/or a certificate revocation list
        (CRL), the CA type, and an optional idempotency token to avoid
        accidental creation of multiple CAs. The CA configuration specifies the
        name of the algorithm and key size to be used to create the CA private
        key, the type of signing algorithm that the CA uses, and X.500 subject
        information. The OCSP configuration can optionally specify a custom URL
        for the OCSP responder. The CRL configuration specifies the CRL
        expiration period in days (the validity period of the CRL), the Amazon
        S3 bucket that will contain the CRL, and a CNAME alias for the S3 bucket
        that is included in certificates issued by the CA. If successful, this
        action returns the Amazon Resource Name (ARN) of the CA.

        Both Amazon Web Services Private CA and the IAM principal must have
        permission to write to the S3 bucket that you specify. If the IAM
        principal making the call does not have permission to write to the
        bucket, then an exception is thrown. For more information, see `Access
        policies for CRLs in Amazon
        S3 <https://docs.aws.amazon.com/privateca/latest/userguide/crl-planning.html#s3-policies>`__.

        Amazon Web Services Private CA assets that are stored in Amazon S3 can
        be protected with encryption. For more information, see `Encrypting Your
        CRLs <https://docs.aws.amazon.com/privateca/latest/userguide/PcaCreateCa.html#crl-encryption>`__.

        :param certificate_authority_configuration: Name and bit size of the private key algorithm, the name of the signing
        algorithm, and X.
        :param certificate_authority_type: The type of the certificate authority.
        :param revocation_configuration: Contains information to enable Online Certificate Status Protocol (OCSP)
        support, to enable a certificate revocation list (CRL), to enable both,
        or to enable neither.
        :param idempotency_token: Custom string that can be used to distinguish between calls to the
        **CreateCertificateAuthority** action.
        :param key_storage_security_standard: Specifies a cryptographic key management compliance standard used for
        handling CA keys.
        :param tags: Key-value pairs that will be attached to the new private CA.
        :param usage_mode: Specifies whether the CA issues general-purpose certificates that
        typically require a revocation mechanism, or short-lived certificates
        that may optionally omit revocation because they expire quickly.
        :returns: CreateCertificateAuthorityResponse
        :raises InvalidArgsException:
        :raises InvalidPolicyException:
        :raises InvalidTagException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("CreateCertificateAuthorityAuditReport")
    def create_certificate_authority_audit_report(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        s3_bucket_name: S3BucketName,
        audit_report_response_format: AuditReportResponseFormat,
    ) -> CreateCertificateAuthorityAuditReportResponse:
        """Creates an audit report that lists every time that your CA private key
        is used. The report is saved in the Amazon S3 bucket that you specify on
        input. The
        `IssueCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_IssueCertificate.html>`__
        and
        `RevokeCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_RevokeCertificate.html>`__
        actions use the private key.

        Both Amazon Web Services Private CA and the IAM principal must have
        permission to write to the S3 bucket that you specify. If the IAM
        principal making the call does not have permission to write to the
        bucket, then an exception is thrown. For more information, see `Access
        policies for CRLs in Amazon
        S3 <https://docs.aws.amazon.com/privateca/latest/userguide/crl-planning.html#s3-policies>`__.

        Amazon Web Services Private CA assets that are stored in Amazon S3 can
        be protected with encryption. For more information, see `Encrypting Your
        Audit
        Reports <https://docs.aws.amazon.com/privateca/latest/userguide/PcaAuditReport.html#audit-report-encryption>`__.

        You can generate a maximum of one report every 30 minutes.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) of the CA to be audited.
        :param s3_bucket_name: The name of the S3 bucket that will contain the audit report.
        :param audit_report_response_format: The format in which to create the report.
        :returns: CreateCertificateAuthorityAuditReportResponse
        :raises RequestInProgressException:
        :raises RequestFailedException:
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidArgsException:
        :raises InvalidStateException:
        """
        raise NotImplementedError

    @handler("CreatePermission")
    def create_permission(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        principal: Principal,
        actions: ActionList,
        source_account: AccountId = None,
    ) -> None:
        """Grants one or more permissions on a private CA to the Certificate
        Manager (ACM) service principal (``acm.amazonaws.com``). These
        permissions allow ACM to issue and renew ACM certificates that reside in
        the same Amazon Web Services account as the CA.

        You can list current permissions with the
        `ListPermissions <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListPermissions.html>`__
        action and revoke them with the
        `DeletePermission <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DeletePermission.html>`__
        action.

        **About Permissions**

        -  If the private CA and the certificates it issues reside in the same
           account, you can use ``CreatePermission`` to grant permissions for
           ACM to carry out automatic certificate renewals.

        -  For automatic certificate renewal to succeed, the ACM service
           principal needs permissions to create, retrieve, and list
           certificates.

        -  If the private CA and the ACM certificates reside in different
           accounts, then permissions cannot be used to enable automatic
           renewals. Instead, the ACM certificate owner must set up a
           resource-based policy to enable cross-account issuance and renewals.
           For more information, see `Using a Resource Based Policy with Amazon
           Web Services Private
           CA <https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html>`__.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) of the CA that grants the permissions.
        :param principal: The Amazon Web Services service or identity that receives the
        permission.
        :param actions: The actions that the specified Amazon Web Services service principal can
        use.
        :param source_account: The ID of the calling account.
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises PermissionAlreadyExistsException:
        :raises LimitExceededException:
        :raises InvalidStateException:
        :raises RequestFailedException:
        """
        raise NotImplementedError

    @handler("DeleteCertificateAuthority")
    def delete_certificate_authority(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        permanent_deletion_time_in_days: PermanentDeletionTimeInDays = None,
    ) -> None:
        """Deletes a private certificate authority (CA). You must provide the
        Amazon Resource Name (ARN) of the private CA that you want to delete.
        You can find the ARN by calling the
        `ListCertificateAuthorities <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html>`__
        action.

        Deleting a CA will invalidate other CAs and certificates below it in
        your CA hierarchy.

        Before you can delete a CA that you have created and activated, you must
        disable it. To do this, call the
        `UpdateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_UpdateCertificateAuthority.html>`__
        action and set the **CertificateAuthorityStatus** parameter to
        ``DISABLED``.

        Additionally, you can delete a CA if you are waiting for it to be
        created (that is, the status of the CA is ``CREATING``). You can also
        delete it if the CA has been created but you haven't yet imported the
        signed certificate into Amazon Web Services Private CA (that is, the
        status of the CA is ``PENDING_CERTIFICATE``).

        When you successfully call
        `DeleteCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DeleteCertificateAuthority.html>`__,
        the CA's status changes to ``DELETED``. However, the CA won't be
        permanently deleted until the restoration period has passed. By default,
        if you do not set the ``PermanentDeletionTimeInDays`` parameter, the CA
        remains restorable for 30 days. You can set the parameter from 7 to 30
        days. The
        `DescribeCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DescribeCertificateAuthority.html>`__
        action returns the time remaining in the restoration window of a private
        CA in the ``DELETED`` state. To restore an eligible CA, call the
        `RestoreCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_RestoreCertificateAuthority.html>`__
        action.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called
        `CreateCertificateAuthority <https://docs.
        :param permanent_deletion_time_in_days: The number of days to make a CA restorable after it has been deleted.
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        """
        raise NotImplementedError

    @handler("DeletePermission")
    def delete_permission(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        principal: Principal,
        source_account: AccountId = None,
    ) -> None:
        """Revokes permissions on a private CA granted to the Certificate Manager
        (ACM) service principal (acm.amazonaws.com).

        These permissions allow ACM to issue and renew ACM certificates that
        reside in the same Amazon Web Services account as the CA. If you revoke
        these permissions, ACM will no longer renew the affected certificates
        automatically.

        Permissions can be granted with the
        `CreatePermission <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreatePermission.html>`__
        action and listed with the
        `ListPermissions <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListPermissions.html>`__
        action.

        **About Permissions**

        -  If the private CA and the certificates it issues reside in the same
           account, you can use ``CreatePermission`` to grant permissions for
           ACM to carry out automatic certificate renewals.

        -  For automatic certificate renewal to succeed, the ACM service
           principal needs permissions to create, retrieve, and list
           certificates.

        -  If the private CA and the ACM certificates reside in different
           accounts, then permissions cannot be used to enable automatic
           renewals. Instead, the ACM certificate owner must set up a
           resource-based policy to enable cross-account issuance and renewals.
           For more information, see `Using a Resource Based Policy with Amazon
           Web Services Private
           CA <https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html>`__.

        :param certificate_authority_arn: The Amazon Resource Number (ARN) of the private CA that issued the
        permissions.
        :param principal: The Amazon Web Services service or identity that will have its CA
        permissions revoked.
        :param source_account: The Amazon Web Services account that calls this action.
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        :raises RequestFailedException:
        """
        raise NotImplementedError

    @handler("DeletePolicy")
    def delete_policy(self, context: RequestContext, resource_arn: Arn) -> None:
        """Deletes the resource-based policy attached to a private CA. Deletion
        will remove any access that the policy has granted. If there is no
        policy attached to the private CA, this action will return successful.

        If you delete a policy that was applied through Amazon Web Services
        Resource Access Manager (RAM), the CA will be removed from all shares in
        which it was included.

        The Certificate Manager Service Linked Role that the policy supports is
        not affected when you delete the policy.

        The current policy can be shown with
        `GetPolicy <https://docs.aws.amazon.com/privateca/latest/APIReference/API_GetPolicy.html>`__
        and updated with
        `PutPolicy <https://docs.aws.amazon.com/privateca/latest/APIReference/API_PutPolicy.html>`__.

        **About Policies**

        -  A policy grants access on a private CA to an Amazon Web Services
           customer account, to Amazon Web Services Organizations, or to an
           Amazon Web Services Organizations unit. Policies are under the
           control of a CA administrator. For more information, see `Using a
           Resource Based Policy with Amazon Web Services Private
           CA <https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html>`__.

        -  A policy permits a user of Certificate Manager (ACM) to issue ACM
           certificates signed by a CA in another account.

        -  For ACM to manage automatic renewal of these certificates, the ACM
           user must configure a Service Linked Role (SLR). The SLR allows the
           ACM service to assume the identity of the user, subject to
           confirmation against the Amazon Web Services Private CA policy. For
           more information, see `Using a Service Linked Role with
           ACM <https://docs.aws.amazon.com/acm/latest/userguide/acm-slr.html>`__.

        -  Updates made in Amazon Web Services Resource Manager (RAM) are
           reflected in policies. For more information, see `Attach a Policy for
           Cross-Account
           Access <https://docs.aws.amazon.com/privateca/latest/userguide/pca-ram.html>`__.

        :param resource_arn: The Amazon Resource Number (ARN) of the private CA that will have its
        policy deleted.
        :raises ConcurrentModificationException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        :raises LockoutPreventedException:
        :raises RequestFailedException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("DescribeCertificateAuthority")
    def describe_certificate_authority(
        self, context: RequestContext, certificate_authority_arn: Arn
    ) -> DescribeCertificateAuthorityResponse:
        """Lists information about your private certificate authority (CA) or one
        that has been shared with you. You specify the private CA on input by
        its ARN (Amazon Resource Name). The output contains the status of your
        CA. This can be any of the following:

        -  ``CREATING`` - Amazon Web Services Private CA is creating your
           private certificate authority.

        -  ``PENDING_CERTIFICATE`` - The certificate is pending. You must use
           your Amazon Web Services Private CA-hosted or on-premises root or
           subordinate CA to sign your private CA CSR and then import it into
           Amazon Web Services Private CA.

        -  ``ACTIVE`` - Your private CA is active.

        -  ``DISABLED`` - Your private CA has been disabled.

        -  ``EXPIRED`` - Your private CA certificate has expired.

        -  ``FAILED`` - Your private CA has failed. Your CA can fail because of
           problems such a network outage or back-end Amazon Web Services
           failure or other errors. A failed CA can never return to the pending
           state. You must create a new CA.

        -  ``DELETED`` - Your private CA is within the restoration period, after
           which it is permanently deleted. The length of time remaining in the
           CA's restoration period is also included in this action's output.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called
        `CreateCertificateAuthority <https://docs.
        :returns: DescribeCertificateAuthorityResponse
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        """
        raise NotImplementedError

    @handler("DescribeCertificateAuthorityAuditReport")
    def describe_certificate_authority_audit_report(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        audit_report_id: AuditReportId,
    ) -> DescribeCertificateAuthorityAuditReportResponse:
        """Lists information about a specific audit report created by calling the
        `CreateCertificateAuthorityAuditReport <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthorityAuditReport.html>`__
        action. Audit information is created every time the certificate
        authority (CA) private key is used. The private key is used when you
        call the
        `IssueCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_IssueCertificate.html>`__
        action or the
        `RevokeCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_RevokeCertificate.html>`__
        action.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) of the private CA.
        :param audit_report_id: The report ID returned by calling the
        `CreateCertificateAuthorityAuditReport <https://docs.
        :returns: DescribeCertificateAuthorityAuditReportResponse
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidArgsException:
        """
        raise NotImplementedError

    @handler("GetCertificate")
    def get_certificate(
        self, context: RequestContext, certificate_authority_arn: Arn, certificate_arn: Arn
    ) -> GetCertificateResponse:
        """Retrieves a certificate from your private CA or one that has been shared
        with you. The ARN of the certificate is returned when you call the
        `IssueCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_IssueCertificate.html>`__
        action. You must specify both the ARN of your private CA and the ARN of
        the issued certificate when calling the **GetCertificate** action. You
        can retrieve the certificate if it is in the **ISSUED** state. You can
        call the
        `CreateCertificateAuthorityAuditReport <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthorityAuditReport.html>`__
        action to create a report that contains information about all of the
        certificates issued and revoked by your private CA.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called
        `CreateCertificateAuthority <https://docs.
        :param certificate_arn: The ARN of the issued certificate.
        :returns: GetCertificateResponse
        :raises RequestInProgressException:
        :raises RequestFailedException:
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        """
        raise NotImplementedError

    @handler("GetCertificateAuthorityCertificate")
    def get_certificate_authority_certificate(
        self, context: RequestContext, certificate_authority_arn: Arn
    ) -> GetCertificateAuthorityCertificateResponse:
        """Retrieves the certificate and certificate chain for your private
        certificate authority (CA) or one that has been shared with you. Both
        the certificate and the chain are base64 PEM-encoded. The chain does not
        include the CA certificate. Each certificate in the chain signs the one
        before it.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) of your private CA.
        :returns: GetCertificateAuthorityCertificateResponse
        :raises ResourceNotFoundException:
        :raises InvalidStateException:
        :raises InvalidArnException:
        """
        raise NotImplementedError

    @handler("GetCertificateAuthorityCsr")
    def get_certificate_authority_csr(
        self, context: RequestContext, certificate_authority_arn: Arn
    ) -> GetCertificateAuthorityCsrResponse:
        """Retrieves the certificate signing request (CSR) for your private
        certificate authority (CA). The CSR is created when you call the
        `CreateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html>`__
        action. Sign the CSR with your Amazon Web Services Private CA-hosted or
        on-premises root or subordinate CA. Then import the signed certificate
        back into Amazon Web Services Private CA by calling the
        `ImportCertificateAuthorityCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ImportCertificateAuthorityCertificate.html>`__
        action. The CSR is returned as a base64 PEM-encoded string.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called the
        `CreateCertificateAuthority <https://docs.
        :returns: GetCertificateAuthorityCsrResponse
        :raises RequestInProgressException:
        :raises RequestFailedException:
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        """
        raise NotImplementedError

    @handler("GetPolicy")
    def get_policy(self, context: RequestContext, resource_arn: Arn) -> GetPolicyResponse:
        """Retrieves the resource-based policy attached to a private CA. If either
        the private CA resource or the policy cannot be found, this action
        returns a ``ResourceNotFoundException``.

        The policy can be attached or updated with
        `PutPolicy <https://docs.aws.amazon.com/privateca/latest/APIReference/API_PutPolicy.html>`__
        and removed with
        `DeletePolicy <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DeletePolicy.html>`__.

        **About Policies**

        -  A policy grants access on a private CA to an Amazon Web Services
           customer account, to Amazon Web Services Organizations, or to an
           Amazon Web Services Organizations unit. Policies are under the
           control of a CA administrator. For more information, see `Using a
           Resource Based Policy with Amazon Web Services Private
           CA <https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html>`__.

        -  A policy permits a user of Certificate Manager (ACM) to issue ACM
           certificates signed by a CA in another account.

        -  For ACM to manage automatic renewal of these certificates, the ACM
           user must configure a Service Linked Role (SLR). The SLR allows the
           ACM service to assume the identity of the user, subject to
           confirmation against the Amazon Web Services Private CA policy. For
           more information, see `Using a Service Linked Role with
           ACM <https://docs.aws.amazon.com/acm/latest/userguide/acm-slr.html>`__.

        -  Updates made in Amazon Web Services Resource Manager (RAM) are
           reflected in policies. For more information, see `Attach a Policy for
           Cross-Account
           Access <https://docs.aws.amazon.com/privateca/latest/userguide/pca-ram.html>`__.

        :param resource_arn: The Amazon Resource Number (ARN) of the private CA that will have its
        policy retrieved.
        :returns: GetPolicyResponse
        :raises InvalidArnException:
        :raises InvalidStateException:
        :raises RequestFailedException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("ImportCertificateAuthorityCertificate")
    def import_certificate_authority_certificate(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        certificate: CertificateBodyBlob,
        certificate_chain: CertificateChainBlob = None,
    ) -> None:
        """Imports a signed private CA certificate into Amazon Web Services Private
        CA. This action is used when you are using a chain of trust whose root
        is located outside Amazon Web Services Private CA. Before you can call
        this action, the following preparations must in place:

        #. In Amazon Web Services Private CA, call the
           `CreateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html>`__
           action to create the private CA that you plan to back with the
           imported certificate.

        #. Call the
           `GetCertificateAuthorityCsr <https://docs.aws.amazon.com/privateca/latest/APIReference/API_GetCertificateAuthorityCsr.html>`__
           action to generate a certificate signing request (CSR).

        #. Sign the CSR using a root or intermediate CA hosted by either an
           on-premises PKI hierarchy or by a commercial CA.

        #. Create a certificate chain and copy the signed certificate and the
           certificate chain to your working directory.

        Amazon Web Services Private CA supports three scenarios for installing a
        CA certificate:

        -  Installing a certificate for a root CA hosted by Amazon Web Services
           Private CA.

        -  Installing a subordinate CA certificate whose parent authority is
           hosted by Amazon Web Services Private CA.

        -  Installing a subordinate CA certificate whose parent authority is
           externally hosted.

        The following additional requirements apply when you import a CA
        certificate.

        -  Only a self-signed certificate can be imported as a root CA.

        -  A self-signed certificate cannot be imported as a subordinate CA.

        -  Your certificate chain must not include the private CA certificate
           that you are importing.

        -  Your root CA must be the last certificate in your chain. The
           subordinate certificate, if any, that your root CA signed must be
           next to last. The subordinate certificate signed by the preceding
           subordinate CA must come next, and so on until your chain is built.

        -  The chain must be PEM-encoded.

        -  The maximum allowed size of a certificate is 32 KB.

        -  The maximum allowed size of a certificate chain is 2 MB.

        *Enforcement of Critical Constraints*

        Amazon Web Services Private CA allows the following extensions to be
        marked critical in the imported CA certificate or chain.

        -  Basic constraints (*must* be marked critical)

        -  Subject alternative names

        -  Key usage

        -  Extended key usage

        -  Authority key identifier

        -  Subject key identifier

        -  Issuer alternative name

        -  Subject directory attributes

        -  Subject information access

        -  Certificate policies

        -  Policy mappings

        -  Inhibit anyPolicy

        Amazon Web Services Private CA rejects the following extensions when
        they are marked critical in an imported CA certificate or chain.

        -  Name constraints

        -  Policy constraints

        -  CRL distribution points

        -  Authority information access

        -  Freshest CRL

        -  Any other extension

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called
        `CreateCertificateAuthority <https://docs.
        :param certificate: The PEM-encoded certificate for a private CA.
        :param certificate_chain: A PEM-encoded file that contains all of your certificates, other than
        the certificate you're importing, chaining up to your root CA.
        :raises ConcurrentModificationException:
        :raises RequestInProgressException:
        :raises RequestFailedException:
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidRequestException:
        :raises InvalidStateException:
        :raises MalformedCertificateException:
        :raises CertificateMismatchException:
        """
        raise NotImplementedError

    @handler("IssueCertificate")
    def issue_certificate(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        csr: CsrBlob,
        signing_algorithm: SigningAlgorithm,
        validity: Validity,
        api_passthrough: ApiPassthrough = None,
        template_arn: Arn = None,
        validity_not_before: Validity = None,
        idempotency_token: IdempotencyToken = None,
    ) -> IssueCertificateResponse:
        """Uses your private certificate authority (CA), or one that has been
        shared with you, to issue a client certificate. This action returns the
        Amazon Resource Name (ARN) of the certificate. You can retrieve the
        certificate by calling the
        `GetCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_GetCertificate.html>`__
        action and specifying the ARN.

        You cannot use the ACM **ListCertificateAuthorities** action to retrieve
        the ARNs of the certificates that you issue by using Amazon Web Services
        Private CA.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called
        `CreateCertificateAuthority <https://docs.
        :param csr: The certificate signing request (CSR) for the certificate you want to
        issue.
        :param signing_algorithm: The name of the algorithm that will be used to sign the certificate to
        be issued.
        :param validity: Information describing the end of the validity period of the
        certificate.
        :param api_passthrough: Specifies X.
        :param template_arn: Specifies a custom configuration template to use when issuing a
        certificate.
        :param validity_not_before: Information describing the start of the validity period of the
        certificate.
        :param idempotency_token: Alphanumeric string that can be used to distinguish between calls to the
        **IssueCertificate** action.
        :returns: IssueCertificateResponse
        :raises LimitExceededException:
        :raises ResourceNotFoundException:
        :raises InvalidStateException:
        :raises InvalidArnException:
        :raises InvalidArgsException:
        :raises MalformedCSRException:
        """
        raise NotImplementedError

    @handler("ListCertificateAuthorities")
    def list_certificate_authorities(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        resource_owner: ResourceOwner = None,
    ) -> ListCertificateAuthoritiesResponse:
        """Lists the private certificate authorities that you created by using the
        `CreateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html>`__
        action.

        :param next_token: Use this parameter when paginating results in a subsequent request after
        you receive a response with truncated results.
        :param max_results: Use this parameter when paginating results to specify the maximum number
        of items to return in the response on each page.
        :param resource_owner: Use this parameter to filter the returned set of certificate authorities
        based on their owner.
        :returns: ListCertificateAuthoritiesResponse
        :raises InvalidNextTokenException:
        """
        raise NotImplementedError

    @handler("ListPermissions")
    def list_permissions(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListPermissionsResponse:
        """List all permissions on a private CA, if any, granted to the Certificate
        Manager (ACM) service principal (acm.amazonaws.com).

        These permissions allow ACM to issue and renew ACM certificates that
        reside in the same Amazon Web Services account as the CA.

        Permissions can be granted with the
        `CreatePermission <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreatePermission.html>`__
        action and revoked with the
        `DeletePermission <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DeletePermission.html>`__
        action.

        **About Permissions**

        -  If the private CA and the certificates it issues reside in the same
           account, you can use ``CreatePermission`` to grant permissions for
           ACM to carry out automatic certificate renewals.

        -  For automatic certificate renewal to succeed, the ACM service
           principal needs permissions to create, retrieve, and list
           certificates.

        -  If the private CA and the ACM certificates reside in different
           accounts, then permissions cannot be used to enable automatic
           renewals. Instead, the ACM certificate owner must set up a
           resource-based policy to enable cross-account issuance and renewals.
           For more information, see `Using a Resource Based Policy with Amazon
           Web Services Private
           CA <https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html>`__.

        :param certificate_authority_arn: The Amazon Resource Number (ARN) of the private CA to inspect.
        :param next_token: When paginating results, use this parameter in a subsequent request
        after you receive a response with truncated results.
        :param max_results: When paginating results, use this parameter to specify the maximum
        number of items to return in the response.
        :returns: ListPermissionsResponse
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidNextTokenException:
        :raises InvalidStateException:
        :raises RequestFailedException:
        """
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListTagsResponse:
        """Lists the tags, if any, that are associated with your private CA or one
        that has been shared with you. Tags are labels that you can use to
        identify and organize your CAs. Each tag consists of a key and an
        optional value. Call the
        `TagCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_TagCertificateAuthority.html>`__
        action to add one or more tags to your CA. Call the
        `UntagCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_UntagCertificateAuthority.html>`__
        action to remove tags.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called the
        `CreateCertificateAuthority <https://docs.
        :param next_token: Use this parameter when paginating results in a subsequent request after
        you receive a response with truncated results.
        :param max_results: Use this parameter when paginating results to specify the maximum number
        of items to return in the response.
        :returns: ListTagsResponse
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        """
        raise NotImplementedError

    @handler("PutPolicy")
    def put_policy(self, context: RequestContext, resource_arn: Arn, policy: AWSPolicy) -> None:
        """Attaches a resource-based policy to a private CA.

        A policy can also be applied by sharing a private CA through Amazon Web
        Services Resource Access Manager (RAM). For more information, see
        `Attach a Policy for Cross-Account
        Access <https://docs.aws.amazon.com/privateca/latest/userguide/pca-ram.html>`__.

        The policy can be displayed with
        `GetPolicy <https://docs.aws.amazon.com/privateca/latest/APIReference/API_GetPolicy.html>`__
        and removed with
        `DeletePolicy <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DeletePolicy.html>`__.

        **About Policies**

        -  A policy grants access on a private CA to an Amazon Web Services
           customer account, to Amazon Web Services Organizations, or to an
           Amazon Web Services Organizations unit. Policies are under the
           control of a CA administrator. For more information, see `Using a
           Resource Based Policy with Amazon Web Services Private
           CA <https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html>`__.

        -  A policy permits a user of Certificate Manager (ACM) to issue ACM
           certificates signed by a CA in another account.

        -  For ACM to manage automatic renewal of these certificates, the ACM
           user must configure a Service Linked Role (SLR). The SLR allows the
           ACM service to assume the identity of the user, subject to
           confirmation against the Amazon Web Services Private CA policy. For
           more information, see `Using a Service Linked Role with
           ACM <https://docs.aws.amazon.com/acm/latest/userguide/acm-slr.html>`__.

        -  Updates made in Amazon Web Services Resource Manager (RAM) are
           reflected in policies. For more information, see `Attach a Policy for
           Cross-Account
           Access <https://docs.aws.amazon.com/privateca/latest/userguide/pca-ram.html>`__.

        :param resource_arn: The Amazon Resource Number (ARN) of the private CA to associate with the
        policy.
        :param policy: The path and file name of a JSON-formatted IAM policy to attach to the
        specified private CA resource.
        :raises ConcurrentModificationException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        :raises InvalidPolicyException:
        :raises LockoutPreventedException:
        :raises RequestFailedException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("RestoreCertificateAuthority")
    def restore_certificate_authority(
        self, context: RequestContext, certificate_authority_arn: Arn
    ) -> None:
        """Restores a certificate authority (CA) that is in the ``DELETED`` state.
        You can restore a CA during the period that you defined in the
        **PermanentDeletionTimeInDays** parameter of the
        `DeleteCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DeleteCertificateAuthority.html>`__
        action. Currently, you can specify 7 to 30 days. If you did not specify
        a **PermanentDeletionTimeInDays** value, by default you can restore the
        CA at any time in a 30 day period. You can check the time remaining in
        the restoration period of a private CA in the ``DELETED`` state by
        calling the
        `DescribeCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_DescribeCertificateAuthority.html>`__
        or
        `ListCertificateAuthorities <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html>`__
        actions. The status of a restored CA is set to its pre-deletion status
        when the **RestoreCertificateAuthority** action returns. To change its
        status to ``ACTIVE``, call the
        `UpdateCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_UpdateCertificateAuthority.html>`__
        action. If the private CA was in the ``PENDING_CERTIFICATE`` state at
        deletion, you must use the
        `ImportCertificateAuthorityCertificate <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ImportCertificateAuthorityCertificate.html>`__
        action to import a certificate authority into the private CA before it
        can be activated. You cannot restore a CA after the restoration period
        has ended.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called the
        `CreateCertificateAuthority <https://docs.
        :raises ResourceNotFoundException:
        :raises InvalidStateException:
        :raises InvalidArnException:
        """
        raise NotImplementedError

    @handler("RevokeCertificate")
    def revoke_certificate(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        certificate_serial: String128,
        revocation_reason: RevocationReason,
    ) -> None:
        """Revokes a certificate that was issued inside Amazon Web Services Private
        CA. If you enable a certificate revocation list (CRL) when you create or
        update your private CA, information about the revoked certificates will
        be included in the CRL. Amazon Web Services Private CA writes the CRL to
        an S3 bucket that you specify. A CRL is typically updated approximately
        30 minutes after a certificate is revoked. If for any reason the CRL
        update fails, Amazon Web Services Private CA attempts makes further
        attempts every 15 minutes. With Amazon CloudWatch, you can create alarms
        for the metrics ``CRLGenerated`` and ``MisconfiguredCRLBucket``. For
        more information, see `Supported CloudWatch
        Metrics <https://docs.aws.amazon.com/privateca/latest/userguide/PcaCloudWatch.html>`__.

        Both Amazon Web Services Private CA and the IAM principal must have
        permission to write to the S3 bucket that you specify. If the IAM
        principal making the call does not have permission to write to the
        bucket, then an exception is thrown. For more information, see `Access
        policies for CRLs in Amazon
        S3 <https://docs.aws.amazon.com/privateca/latest/userguide/crl-planning.html#s3-policies>`__.

        Amazon Web Services Private CA also writes revocation information to the
        audit report. For more information, see
        `CreateCertificateAuthorityAuditReport <https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthorityAuditReport.html>`__.

        You cannot revoke a root CA self-signed certificate.

        :param certificate_authority_arn: Amazon Resource Name (ARN) of the private CA that issued the certificate
        to be revoked.
        :param certificate_serial: Serial number of the certificate to be revoked.
        :param revocation_reason: Specifies why you revoked the certificate.
        :raises ConcurrentModificationException:
        :raises InvalidArnException:
        :raises InvalidRequestException:
        :raises InvalidStateException:
        :raises LimitExceededException:
        :raises ResourceNotFoundException:
        :raises RequestAlreadyProcessedException:
        :raises RequestInProgressException:
        :raises RequestFailedException:
        """
        raise NotImplementedError

    @handler("TagCertificateAuthority")
    def tag_certificate_authority(
        self, context: RequestContext, certificate_authority_arn: Arn, tags: TagList
    ) -> None:
        """Adds one or more tags to your private CA. Tags are labels that you can
        use to identify and organize your Amazon Web Services resources. Each
        tag consists of a key and an optional value. You specify the private CA
        on input by its Amazon Resource Name (ARN). You specify the tag by using
        a key-value pair. You can apply a tag to just one private CA if you want
        to identify a specific characteristic of that CA, or you can apply the
        same tag to multiple private CAs if you want to filter for a common
        relationship among those CAs. To remove one or more tags, use the
        `UntagCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_UntagCertificateAuthority.html>`__
        action. Call the
        `ListTags <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListTags.html>`__
        action to see what tags are associated with your CA.

        To attach tags to a private CA during the creation procedure, a CA
        administrator must first associate an inline IAM policy with the
        ``CreateCertificateAuthority`` action and explicitly allow tagging. For
        more information, see `Attaching tags to a CA at the time of
        creation <https://docs.aws.amazon.com/privateca/latest/userguide/auth-InlinePolicies.html#policy-tag-ca>`__.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called
        `CreateCertificateAuthority <https://docs.
        :param tags: List of tags to be associated with the CA.
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        :raises InvalidTagException:
        :raises TooManyTagsException:
        """
        raise NotImplementedError

    @handler("UntagCertificateAuthority")
    def untag_certificate_authority(
        self, context: RequestContext, certificate_authority_arn: Arn, tags: TagList
    ) -> None:
        """Remove one or more tags from your private CA. A tag consists of a
        key-value pair. If you do not specify the value portion of the tag when
        calling this action, the tag will be removed regardless of value. If you
        specify a value, the tag is removed only if it is associated with the
        specified value. To add tags to a private CA, use the
        `TagCertificateAuthority <https://docs.aws.amazon.com/privateca/latest/APIReference/API_TagCertificateAuthority.html>`__.
        Call the
        `ListTags <https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListTags.html>`__
        action to see what tags are associated with your CA.

        :param certificate_authority_arn: The Amazon Resource Name (ARN) that was returned when you called
        `CreateCertificateAuthority <https://docs.
        :param tags: List of tags to be removed from the CA.
        :raises ResourceNotFoundException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        :raises InvalidTagException:
        """
        raise NotImplementedError

    @handler("UpdateCertificateAuthority")
    def update_certificate_authority(
        self,
        context: RequestContext,
        certificate_authority_arn: Arn,
        revocation_configuration: RevocationConfiguration = None,
        status: CertificateAuthorityStatus = None,
    ) -> None:
        """Updates the status or configuration of a private certificate authority
        (CA). Your private CA must be in the ``ACTIVE`` or ``DISABLED`` state
        before you can update it. You can disable a private CA that is in the
        ``ACTIVE`` state or make a CA that is in the ``DISABLED`` state active
        again.

        Both Amazon Web Services Private CA and the IAM principal must have
        permission to write to the S3 bucket that you specify. If the IAM
        principal making the call does not have permission to write to the
        bucket, then an exception is thrown. For more information, see `Access
        policies for CRLs in Amazon
        S3 <https://docs.aws.amazon.com/privateca/latest/userguide/crl-planning.html#s3-policies>`__.

        :param certificate_authority_arn: Amazon Resource Name (ARN) of the private CA that issued the certificate
        to be revoked.
        :param revocation_configuration: Contains information to enable Online Certificate Status Protocol (OCSP)
        support, to enable a certificate revocation list (CRL), to enable both,
        or to enable neither.
        :param status: Status of your private CA.
        :raises ConcurrentModificationException:
        :raises ResourceNotFoundException:
        :raises InvalidArgsException:
        :raises InvalidArnException:
        :raises InvalidStateException:
        :raises InvalidPolicyException:
        """
        raise NotImplementedError
