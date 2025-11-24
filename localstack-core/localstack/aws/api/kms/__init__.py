from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AWSAccountIdType = str
AccountIdType = str
AliasNameType = str
ArnType = str
BackingKeyIdResponseType = str
BackingKeyIdType = str
BooleanType = bool
CloudHsmClusterIdType = str
CustomKeyStoreIdType = str
CustomKeyStoreNameType = str
DescriptionType = str
EncryptionContextKey = str
EncryptionContextValue = str
ErrorMessageType = str
GrantIdType = str
GrantNameType = str
GrantTokenType = str
KeyIdType = str
KeyMaterialDescriptionType = str
KeyStorePasswordType = str
LimitType = int
MarkerType = str
NullableBooleanType = bool
NumberOfBytesType = int
PendingWindowInDaysType = int
PolicyNameType = str
PolicyType = str
PrincipalIdType = str
RegionType = str
RotationPeriodInDaysType = int
TagKeyType = str
TagValueType = str
TrustAnchorCertificateType = str
XksKeyIdType = str
XksProxyAuthenticationAccessKeyIdType = str
XksProxyAuthenticationRawSecretAccessKeyType = str
XksProxyUriEndpointType = str
XksProxyUriPathType = str
XksProxyVpcEndpointServiceNameType = str


class AlgorithmSpec(StrEnum):
    RSAES_PKCS1_V1_5 = "RSAES_PKCS1_V1_5"
    RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1"
    RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"
    RSA_AES_KEY_WRAP_SHA_1 = "RSA_AES_KEY_WRAP_SHA_1"
    RSA_AES_KEY_WRAP_SHA_256 = "RSA_AES_KEY_WRAP_SHA_256"
    SM2PKE = "SM2PKE"


class ConnectionErrorCodeType(StrEnum):
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    CLUSTER_NOT_FOUND = "CLUSTER_NOT_FOUND"
    NETWORK_ERRORS = "NETWORK_ERRORS"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INSUFFICIENT_CLOUDHSM_HSMS = "INSUFFICIENT_CLOUDHSM_HSMS"
    USER_LOCKED_OUT = "USER_LOCKED_OUT"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    USER_LOGGED_IN = "USER_LOGGED_IN"
    SUBNET_NOT_FOUND = "SUBNET_NOT_FOUND"
    INSUFFICIENT_FREE_ADDRESSES_IN_SUBNET = "INSUFFICIENT_FREE_ADDRESSES_IN_SUBNET"
    XKS_PROXY_ACCESS_DENIED = "XKS_PROXY_ACCESS_DENIED"
    XKS_PROXY_NOT_REACHABLE = "XKS_PROXY_NOT_REACHABLE"
    XKS_VPC_ENDPOINT_SERVICE_NOT_FOUND = "XKS_VPC_ENDPOINT_SERVICE_NOT_FOUND"
    XKS_PROXY_INVALID_RESPONSE = "XKS_PROXY_INVALID_RESPONSE"
    XKS_PROXY_INVALID_CONFIGURATION = "XKS_PROXY_INVALID_CONFIGURATION"
    XKS_VPC_ENDPOINT_SERVICE_INVALID_CONFIGURATION = (
        "XKS_VPC_ENDPOINT_SERVICE_INVALID_CONFIGURATION"
    )
    XKS_PROXY_TIMED_OUT = "XKS_PROXY_TIMED_OUT"
    XKS_PROXY_INVALID_TLS_CONFIGURATION = "XKS_PROXY_INVALID_TLS_CONFIGURATION"


class ConnectionStateType(StrEnum):
    CONNECTED = "CONNECTED"
    CONNECTING = "CONNECTING"
    FAILED = "FAILED"
    DISCONNECTED = "DISCONNECTED"
    DISCONNECTING = "DISCONNECTING"


class CustomKeyStoreType(StrEnum):
    AWS_CLOUDHSM = "AWS_CLOUDHSM"
    EXTERNAL_KEY_STORE = "EXTERNAL_KEY_STORE"


class CustomerMasterKeySpec(StrEnum):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    ECC_NIST_P256 = "ECC_NIST_P256"
    ECC_NIST_P384 = "ECC_NIST_P384"
    ECC_NIST_P521 = "ECC_NIST_P521"
    ECC_SECG_P256K1 = "ECC_SECG_P256K1"
    SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT"
    HMAC_224 = "HMAC_224"
    HMAC_256 = "HMAC_256"
    HMAC_384 = "HMAC_384"
    HMAC_512 = "HMAC_512"
    SM2 = "SM2"


class DataKeyPairSpec(StrEnum):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    ECC_NIST_P256 = "ECC_NIST_P256"
    ECC_NIST_P384 = "ECC_NIST_P384"
    ECC_NIST_P521 = "ECC_NIST_P521"
    ECC_SECG_P256K1 = "ECC_SECG_P256K1"
    SM2 = "SM2"
    ECC_NIST_EDWARDS25519 = "ECC_NIST_EDWARDS25519"


class DataKeySpec(StrEnum):
    AES_256 = "AES_256"
    AES_128 = "AES_128"


class EncryptionAlgorithmSpec(StrEnum):
    SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT"
    RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1"
    RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"
    SM2PKE = "SM2PKE"


class ExpirationModelType(StrEnum):
    KEY_MATERIAL_EXPIRES = "KEY_MATERIAL_EXPIRES"
    KEY_MATERIAL_DOES_NOT_EXPIRE = "KEY_MATERIAL_DOES_NOT_EXPIRE"


class GrantOperation(StrEnum):
    Decrypt = "Decrypt"
    Encrypt = "Encrypt"
    GenerateDataKey = "GenerateDataKey"
    GenerateDataKeyWithoutPlaintext = "GenerateDataKeyWithoutPlaintext"
    ReEncryptFrom = "ReEncryptFrom"
    ReEncryptTo = "ReEncryptTo"
    Sign = "Sign"
    Verify = "Verify"
    GetPublicKey = "GetPublicKey"
    CreateGrant = "CreateGrant"
    RetireGrant = "RetireGrant"
    DescribeKey = "DescribeKey"
    GenerateDataKeyPair = "GenerateDataKeyPair"
    GenerateDataKeyPairWithoutPlaintext = "GenerateDataKeyPairWithoutPlaintext"
    GenerateMac = "GenerateMac"
    VerifyMac = "VerifyMac"
    DeriveSharedSecret = "DeriveSharedSecret"


class ImportState(StrEnum):
    IMPORTED = "IMPORTED"
    PENDING_IMPORT = "PENDING_IMPORT"


class ImportType(StrEnum):
    NEW_KEY_MATERIAL = "NEW_KEY_MATERIAL"
    EXISTING_KEY_MATERIAL = "EXISTING_KEY_MATERIAL"


class IncludeKeyMaterial(StrEnum):
    ALL_KEY_MATERIAL = "ALL_KEY_MATERIAL"
    ROTATIONS_ONLY = "ROTATIONS_ONLY"


class KeyAgreementAlgorithmSpec(StrEnum):
    ECDH = "ECDH"


class KeyEncryptionMechanism(StrEnum):
    RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"


class KeyManagerType(StrEnum):
    AWS = "AWS"
    CUSTOMER = "CUSTOMER"


class KeyMaterialState(StrEnum):
    NON_CURRENT = "NON_CURRENT"
    CURRENT = "CURRENT"
    PENDING_ROTATION = "PENDING_ROTATION"
    PENDING_MULTI_REGION_IMPORT_AND_ROTATION = "PENDING_MULTI_REGION_IMPORT_AND_ROTATION"


class KeySpec(StrEnum):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    ECC_NIST_P256 = "ECC_NIST_P256"
    ECC_NIST_P384 = "ECC_NIST_P384"
    ECC_NIST_P521 = "ECC_NIST_P521"
    ECC_SECG_P256K1 = "ECC_SECG_P256K1"
    SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT"
    HMAC_224 = "HMAC_224"
    HMAC_256 = "HMAC_256"
    HMAC_384 = "HMAC_384"
    HMAC_512 = "HMAC_512"
    SM2 = "SM2"
    ML_DSA_44 = "ML_DSA_44"
    ML_DSA_65 = "ML_DSA_65"
    ML_DSA_87 = "ML_DSA_87"
    ECC_NIST_EDWARDS25519 = "ECC_NIST_EDWARDS25519"


class KeyState(StrEnum):
    Creating = "Creating"
    Enabled = "Enabled"
    Disabled = "Disabled"
    PendingDeletion = "PendingDeletion"
    PendingImport = "PendingImport"
    PendingReplicaDeletion = "PendingReplicaDeletion"
    Unavailable = "Unavailable"
    Updating = "Updating"


class KeyUsageType(StrEnum):
    SIGN_VERIFY = "SIGN_VERIFY"
    ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
    GENERATE_VERIFY_MAC = "GENERATE_VERIFY_MAC"
    KEY_AGREEMENT = "KEY_AGREEMENT"


class MacAlgorithmSpec(StrEnum):
    HMAC_SHA_224 = "HMAC_SHA_224"
    HMAC_SHA_256 = "HMAC_SHA_256"
    HMAC_SHA_384 = "HMAC_SHA_384"
    HMAC_SHA_512 = "HMAC_SHA_512"


class MessageType(StrEnum):
    RAW = "RAW"
    DIGEST = "DIGEST"
    EXTERNAL_MU = "EXTERNAL_MU"


class MultiRegionKeyType(StrEnum):
    PRIMARY = "PRIMARY"
    REPLICA = "REPLICA"


class OriginType(StrEnum):
    AWS_KMS = "AWS_KMS"
    EXTERNAL = "EXTERNAL"
    AWS_CLOUDHSM = "AWS_CLOUDHSM"
    EXTERNAL_KEY_STORE = "EXTERNAL_KEY_STORE"


class RotationType(StrEnum):
    AUTOMATIC = "AUTOMATIC"
    ON_DEMAND = "ON_DEMAND"


class SigningAlgorithmSpec(StrEnum):
    RSASSA_PSS_SHA_256 = "RSASSA_PSS_SHA_256"
    RSASSA_PSS_SHA_384 = "RSASSA_PSS_SHA_384"
    RSASSA_PSS_SHA_512 = "RSASSA_PSS_SHA_512"
    RSASSA_PKCS1_V1_5_SHA_256 = "RSASSA_PKCS1_V1_5_SHA_256"
    RSASSA_PKCS1_V1_5_SHA_384 = "RSASSA_PKCS1_V1_5_SHA_384"
    RSASSA_PKCS1_V1_5_SHA_512 = "RSASSA_PKCS1_V1_5_SHA_512"
    ECDSA_SHA_256 = "ECDSA_SHA_256"
    ECDSA_SHA_384 = "ECDSA_SHA_384"
    ECDSA_SHA_512 = "ECDSA_SHA_512"
    SM2DSA = "SM2DSA"
    ML_DSA_SHAKE_256 = "ML_DSA_SHAKE_256"
    ED25519_SHA_512 = "ED25519_SHA_512"
    ED25519_PH_SHA_512 = "ED25519_PH_SHA_512"


class WrappingKeySpec(StrEnum):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    SM2 = "SM2"


class XksProxyConnectivityType(StrEnum):
    PUBLIC_ENDPOINT = "PUBLIC_ENDPOINT"
    VPC_ENDPOINT_SERVICE = "VPC_ENDPOINT_SERVICE"


class AlreadyExistsException(ServiceException):
    code: str = "AlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400


class CloudHsmClusterInUseException(ServiceException):
    code: str = "CloudHsmClusterInUseException"
    sender_fault: bool = False
    status_code: int = 400


class CloudHsmClusterInvalidConfigurationException(ServiceException):
    code: str = "CloudHsmClusterInvalidConfigurationException"
    sender_fault: bool = False
    status_code: int = 400


class CloudHsmClusterNotActiveException(ServiceException):
    code: str = "CloudHsmClusterNotActiveException"
    sender_fault: bool = False
    status_code: int = 400


class CloudHsmClusterNotFoundException(ServiceException):
    code: str = "CloudHsmClusterNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class CloudHsmClusterNotRelatedException(ServiceException):
    code: str = "CloudHsmClusterNotRelatedException"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 400


class CustomKeyStoreHasCMKsException(ServiceException):
    code: str = "CustomKeyStoreHasCMKsException"
    sender_fault: bool = False
    status_code: int = 400


class CustomKeyStoreInvalidStateException(ServiceException):
    code: str = "CustomKeyStoreInvalidStateException"
    sender_fault: bool = False
    status_code: int = 400


class CustomKeyStoreNameInUseException(ServiceException):
    code: str = "CustomKeyStoreNameInUseException"
    sender_fault: bool = False
    status_code: int = 400


class CustomKeyStoreNotFoundException(ServiceException):
    code: str = "CustomKeyStoreNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class DependencyTimeoutException(ServiceException):
    code: str = "DependencyTimeoutException"
    sender_fault: bool = False
    status_code: int = 400


class DisabledException(ServiceException):
    code: str = "DisabledException"
    sender_fault: bool = False
    status_code: int = 400


class DryRunOperationException(ServiceException):
    code: str = "DryRunOperationException"
    sender_fault: bool = False
    status_code: int = 400


class ExpiredImportTokenException(ServiceException):
    code: str = "ExpiredImportTokenException"
    sender_fault: bool = False
    status_code: int = 400


class IncorrectKeyException(ServiceException):
    code: str = "IncorrectKeyException"
    sender_fault: bool = False
    status_code: int = 400


class IncorrectKeyMaterialException(ServiceException):
    code: str = "IncorrectKeyMaterialException"
    sender_fault: bool = False
    status_code: int = 400


class IncorrectTrustAnchorException(ServiceException):
    code: str = "IncorrectTrustAnchorException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAliasNameException(ServiceException):
    code: str = "InvalidAliasNameException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidArnException(ServiceException):
    code: str = "InvalidArnException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidCiphertextException(ServiceException):
    code: str = "InvalidCiphertextException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidGrantIdException(ServiceException):
    code: str = "InvalidGrantIdException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidGrantTokenException(ServiceException):
    code: str = "InvalidGrantTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidImportTokenException(ServiceException):
    code: str = "InvalidImportTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidKeyUsageException(ServiceException):
    code: str = "InvalidKeyUsageException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidMarkerException(ServiceException):
    code: str = "InvalidMarkerException"
    sender_fault: bool = False
    status_code: int = 400


class KMSInternalException(ServiceException):
    code: str = "KMSInternalException"
    sender_fault: bool = False
    status_code: int = 400


class KMSInvalidMacException(ServiceException):
    code: str = "KMSInvalidMacException"
    sender_fault: bool = False
    status_code: int = 400


class KMSInvalidSignatureException(ServiceException):
    code: str = "KMSInvalidSignatureException"
    sender_fault: bool = False
    status_code: int = 400


class KMSInvalidStateException(ServiceException):
    code: str = "KMSInvalidStateException"
    sender_fault: bool = False
    status_code: int = 400


class KeyUnavailableException(ServiceException):
    code: str = "KeyUnavailableException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MalformedPolicyDocumentException(ServiceException):
    code: str = "MalformedPolicyDocumentException"
    sender_fault: bool = False
    status_code: int = 400


class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class TagException(ServiceException):
    code: str = "TagException"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedOperationException(ServiceException):
    code: str = "UnsupportedOperationException"
    sender_fault: bool = False
    status_code: int = 400


class XksKeyAlreadyInUseException(ServiceException):
    code: str = "XksKeyAlreadyInUseException"
    sender_fault: bool = False
    status_code: int = 400


class XksKeyInvalidConfigurationException(ServiceException):
    code: str = "XksKeyInvalidConfigurationException"
    sender_fault: bool = False
    status_code: int = 400


class XksKeyNotFoundException(ServiceException):
    code: str = "XksKeyNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyIncorrectAuthenticationCredentialException(ServiceException):
    code: str = "XksProxyIncorrectAuthenticationCredentialException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyInvalidConfigurationException(ServiceException):
    code: str = "XksProxyInvalidConfigurationException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyInvalidResponseException(ServiceException):
    code: str = "XksProxyInvalidResponseException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyUriEndpointInUseException(ServiceException):
    code: str = "XksProxyUriEndpointInUseException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyUriInUseException(ServiceException):
    code: str = "XksProxyUriInUseException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyUriUnreachableException(ServiceException):
    code: str = "XksProxyUriUnreachableException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyVpcEndpointServiceInUseException(ServiceException):
    code: str = "XksProxyVpcEndpointServiceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyVpcEndpointServiceInvalidConfigurationException(ServiceException):
    code: str = "XksProxyVpcEndpointServiceInvalidConfigurationException"
    sender_fault: bool = False
    status_code: int = 400


class XksProxyVpcEndpointServiceNotFoundException(ServiceException):
    code: str = "XksProxyVpcEndpointServiceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


DateType = datetime


class AliasListEntry(TypedDict, total=False):
    AliasName: AliasNameType | None
    AliasArn: ArnType | None
    TargetKeyId: KeyIdType | None
    CreationDate: DateType | None
    LastUpdatedDate: DateType | None


AliasList = list[AliasListEntry]
AttestationDocumentType = bytes


class CancelKeyDeletionRequest(ServiceRequest):
    KeyId: KeyIdType


class CancelKeyDeletionResponse(TypedDict, total=False):
    KeyId: KeyIdType | None


CiphertextType = bytes


class ConnectCustomKeyStoreRequest(ServiceRequest):
    CustomKeyStoreId: CustomKeyStoreIdType


class ConnectCustomKeyStoreResponse(TypedDict, total=False):
    pass


class CreateAliasRequest(ServiceRequest):
    AliasName: AliasNameType
    TargetKeyId: KeyIdType


class XksProxyAuthenticationCredentialType(TypedDict, total=False):
    AccessKeyId: XksProxyAuthenticationAccessKeyIdType
    RawSecretAccessKey: XksProxyAuthenticationRawSecretAccessKeyType


class CreateCustomKeyStoreRequest(ServiceRequest):
    CustomKeyStoreName: CustomKeyStoreNameType
    CloudHsmClusterId: CloudHsmClusterIdType | None
    TrustAnchorCertificate: TrustAnchorCertificateType | None
    KeyStorePassword: KeyStorePasswordType | None
    CustomKeyStoreType: CustomKeyStoreType | None
    XksProxyUriEndpoint: XksProxyUriEndpointType | None
    XksProxyUriPath: XksProxyUriPathType | None
    XksProxyVpcEndpointServiceName: XksProxyVpcEndpointServiceNameType | None
    XksProxyVpcEndpointServiceOwner: AccountIdType | None
    XksProxyAuthenticationCredential: XksProxyAuthenticationCredentialType | None
    XksProxyConnectivity: XksProxyConnectivityType | None


class CreateCustomKeyStoreResponse(TypedDict, total=False):
    CustomKeyStoreId: CustomKeyStoreIdType | None


GrantTokenList = list[GrantTokenType]
EncryptionContextType = dict[EncryptionContextKey, EncryptionContextValue]


class GrantConstraints(TypedDict, total=False):
    EncryptionContextSubset: EncryptionContextType | None
    EncryptionContextEquals: EncryptionContextType | None


GrantOperationList = list[GrantOperation]


class CreateGrantRequest(ServiceRequest):
    KeyId: KeyIdType
    GranteePrincipal: PrincipalIdType
    RetiringPrincipal: PrincipalIdType | None
    Operations: GrantOperationList
    Constraints: GrantConstraints | None
    GrantTokens: GrantTokenList | None
    Name: GrantNameType | None
    DryRun: NullableBooleanType | None


class CreateGrantResponse(TypedDict, total=False):
    GrantToken: GrantTokenType | None
    GrantId: GrantIdType | None


class Tag(TypedDict, total=False):
    TagKey: TagKeyType
    TagValue: TagValueType


TagList = list[Tag]


class CreateKeyRequest(ServiceRequest):
    Policy: PolicyType | None
    Description: DescriptionType | None
    KeyUsage: KeyUsageType | None
    CustomerMasterKeySpec: CustomerMasterKeySpec | None
    KeySpec: KeySpec | None
    Origin: OriginType | None
    CustomKeyStoreId: CustomKeyStoreIdType | None
    BypassPolicyLockoutSafetyCheck: BooleanType | None
    Tags: TagList | None
    MultiRegion: NullableBooleanType | None
    XksKeyId: XksKeyIdType | None


class XksKeyConfigurationType(TypedDict, total=False):
    Id: XksKeyIdType | None


MacAlgorithmSpecList = list[MacAlgorithmSpec]


class MultiRegionKey(TypedDict, total=False):
    Arn: ArnType | None
    Region: RegionType | None


MultiRegionKeyList = list[MultiRegionKey]


class MultiRegionConfiguration(TypedDict, total=False):
    MultiRegionKeyType: MultiRegionKeyType | None
    PrimaryKey: MultiRegionKey | None
    ReplicaKeys: MultiRegionKeyList | None


KeyAgreementAlgorithmSpecList = list[KeyAgreementAlgorithmSpec]
SigningAlgorithmSpecList = list[SigningAlgorithmSpec]
EncryptionAlgorithmSpecList = list[EncryptionAlgorithmSpec]


class KeyMetadata(TypedDict, total=False):
    AWSAccountId: AWSAccountIdType | None
    KeyId: KeyIdType
    Arn: ArnType | None
    CreationDate: DateType | None
    Enabled: BooleanType | None
    Description: DescriptionType | None
    KeyUsage: KeyUsageType | None
    KeyState: KeyState | None
    DeletionDate: DateType | None
    ValidTo: DateType | None
    Origin: OriginType | None
    CustomKeyStoreId: CustomKeyStoreIdType | None
    CloudHsmClusterId: CloudHsmClusterIdType | None
    ExpirationModel: ExpirationModelType | None
    KeyManager: KeyManagerType | None
    CustomerMasterKeySpec: CustomerMasterKeySpec | None
    KeySpec: KeySpec | None
    EncryptionAlgorithms: EncryptionAlgorithmSpecList | None
    SigningAlgorithms: SigningAlgorithmSpecList | None
    KeyAgreementAlgorithms: KeyAgreementAlgorithmSpecList | None
    MultiRegion: NullableBooleanType | None
    MultiRegionConfiguration: MultiRegionConfiguration | None
    PendingDeletionWindowInDays: PendingWindowInDaysType | None
    MacAlgorithms: MacAlgorithmSpecList | None
    XksKeyConfiguration: XksKeyConfigurationType | None
    CurrentKeyMaterialId: BackingKeyIdType | None


class CreateKeyResponse(TypedDict, total=False):
    KeyMetadata: KeyMetadata | None


class XksProxyConfigurationType(TypedDict, total=False):
    Connectivity: XksProxyConnectivityType | None
    AccessKeyId: XksProxyAuthenticationAccessKeyIdType | None
    UriEndpoint: XksProxyUriEndpointType | None
    UriPath: XksProxyUriPathType | None
    VpcEndpointServiceName: XksProxyVpcEndpointServiceNameType | None
    VpcEndpointServiceOwner: AccountIdType | None


class CustomKeyStoresListEntry(TypedDict, total=False):
    CustomKeyStoreId: CustomKeyStoreIdType | None
    CustomKeyStoreName: CustomKeyStoreNameType | None
    CloudHsmClusterId: CloudHsmClusterIdType | None
    TrustAnchorCertificate: TrustAnchorCertificateType | None
    ConnectionState: ConnectionStateType | None
    ConnectionErrorCode: ConnectionErrorCodeType | None
    CreationDate: DateType | None
    CustomKeyStoreType: CustomKeyStoreType | None
    XksProxyConfiguration: XksProxyConfigurationType | None


CustomKeyStoresList = list[CustomKeyStoresListEntry]


class RecipientInfo(TypedDict, total=False):
    KeyEncryptionAlgorithm: KeyEncryptionMechanism | None
    AttestationDocument: AttestationDocumentType | None


class DecryptRequest(ServiceRequest):
    CiphertextBlob: CiphertextType
    EncryptionContext: EncryptionContextType | None
    GrantTokens: GrantTokenList | None
    KeyId: KeyIdType | None
    EncryptionAlgorithm: EncryptionAlgorithmSpec | None
    Recipient: RecipientInfo | None
    DryRun: NullableBooleanType | None


PlaintextType = bytes


class DecryptResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    Plaintext: PlaintextType | None
    EncryptionAlgorithm: EncryptionAlgorithmSpec | None
    CiphertextForRecipient: CiphertextType | None
    KeyMaterialId: BackingKeyIdType | None


class DeleteAliasRequest(ServiceRequest):
    AliasName: AliasNameType


class DeleteCustomKeyStoreRequest(ServiceRequest):
    CustomKeyStoreId: CustomKeyStoreIdType


class DeleteCustomKeyStoreResponse(TypedDict, total=False):
    pass


class DeleteImportedKeyMaterialRequest(ServiceRequest):
    KeyId: KeyIdType
    KeyMaterialId: BackingKeyIdType | None


class DeleteImportedKeyMaterialResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    KeyMaterialId: BackingKeyIdResponseType | None


PublicKeyType = bytes


class DeriveSharedSecretRequest(ServiceRequest):
    KeyId: KeyIdType
    KeyAgreementAlgorithm: KeyAgreementAlgorithmSpec
    PublicKey: PublicKeyType
    GrantTokens: GrantTokenList | None
    DryRun: NullableBooleanType | None
    Recipient: RecipientInfo | None


class DeriveSharedSecretResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    SharedSecret: PlaintextType | None
    CiphertextForRecipient: CiphertextType | None
    KeyAgreementAlgorithm: KeyAgreementAlgorithmSpec | None
    KeyOrigin: OriginType | None


class DescribeCustomKeyStoresRequest(ServiceRequest):
    CustomKeyStoreId: CustomKeyStoreIdType | None
    CustomKeyStoreName: CustomKeyStoreNameType | None
    Limit: LimitType | None
    Marker: MarkerType | None


class DescribeCustomKeyStoresResponse(TypedDict, total=False):
    CustomKeyStores: CustomKeyStoresList | None
    NextMarker: MarkerType | None
    Truncated: BooleanType | None


class DescribeKeyRequest(ServiceRequest):
    KeyId: KeyIdType
    GrantTokens: GrantTokenList | None


class DescribeKeyResponse(TypedDict, total=False):
    KeyMetadata: KeyMetadata | None


class DisableKeyRequest(ServiceRequest):
    KeyId: KeyIdType


class DisableKeyRotationRequest(ServiceRequest):
    KeyId: KeyIdType


class DisconnectCustomKeyStoreRequest(ServiceRequest):
    CustomKeyStoreId: CustomKeyStoreIdType


class DisconnectCustomKeyStoreResponse(TypedDict, total=False):
    pass


class EnableKeyRequest(ServiceRequest):
    KeyId: KeyIdType


class EnableKeyRotationRequest(ServiceRequest):
    KeyId: KeyIdType
    RotationPeriodInDays: RotationPeriodInDaysType | None


class EncryptRequest(ServiceRequest):
    KeyId: KeyIdType
    Plaintext: PlaintextType
    EncryptionContext: EncryptionContextType | None
    GrantTokens: GrantTokenList | None
    EncryptionAlgorithm: EncryptionAlgorithmSpec | None
    DryRun: NullableBooleanType | None


class EncryptResponse(TypedDict, total=False):
    CiphertextBlob: CiphertextType | None
    KeyId: KeyIdType | None
    EncryptionAlgorithm: EncryptionAlgorithmSpec | None


class GenerateDataKeyPairRequest(ServiceRequest):
    EncryptionContext: EncryptionContextType | None
    KeyId: KeyIdType
    KeyPairSpec: DataKeyPairSpec
    GrantTokens: GrantTokenList | None
    Recipient: RecipientInfo | None
    DryRun: NullableBooleanType | None


class GenerateDataKeyPairResponse(TypedDict, total=False):
    PrivateKeyCiphertextBlob: CiphertextType | None
    PrivateKeyPlaintext: PlaintextType | None
    PublicKey: PublicKeyType | None
    KeyId: KeyIdType | None
    KeyPairSpec: DataKeyPairSpec | None
    CiphertextForRecipient: CiphertextType | None
    KeyMaterialId: BackingKeyIdType | None


class GenerateDataKeyPairWithoutPlaintextRequest(ServiceRequest):
    EncryptionContext: EncryptionContextType | None
    KeyId: KeyIdType
    KeyPairSpec: DataKeyPairSpec
    GrantTokens: GrantTokenList | None
    DryRun: NullableBooleanType | None


class GenerateDataKeyPairWithoutPlaintextResponse(TypedDict, total=False):
    PrivateKeyCiphertextBlob: CiphertextType | None
    PublicKey: PublicKeyType | None
    KeyId: KeyIdType | None
    KeyPairSpec: DataKeyPairSpec | None
    KeyMaterialId: BackingKeyIdType | None


class GenerateDataKeyRequest(ServiceRequest):
    KeyId: KeyIdType
    EncryptionContext: EncryptionContextType | None
    NumberOfBytes: NumberOfBytesType | None
    KeySpec: DataKeySpec | None
    GrantTokens: GrantTokenList | None
    Recipient: RecipientInfo | None
    DryRun: NullableBooleanType | None


class GenerateDataKeyResponse(TypedDict, total=False):
    CiphertextBlob: CiphertextType | None
    Plaintext: PlaintextType | None
    KeyId: KeyIdType | None
    CiphertextForRecipient: CiphertextType | None
    KeyMaterialId: BackingKeyIdType | None


class GenerateDataKeyWithoutPlaintextRequest(ServiceRequest):
    KeyId: KeyIdType
    EncryptionContext: EncryptionContextType | None
    KeySpec: DataKeySpec | None
    NumberOfBytes: NumberOfBytesType | None
    GrantTokens: GrantTokenList | None
    DryRun: NullableBooleanType | None


class GenerateDataKeyWithoutPlaintextResponse(TypedDict, total=False):
    CiphertextBlob: CiphertextType | None
    KeyId: KeyIdType | None
    KeyMaterialId: BackingKeyIdType | None


class GenerateMacRequest(ServiceRequest):
    Message: PlaintextType
    KeyId: KeyIdType
    MacAlgorithm: MacAlgorithmSpec
    GrantTokens: GrantTokenList | None
    DryRun: NullableBooleanType | None


class GenerateMacResponse(TypedDict, total=False):
    Mac: CiphertextType | None
    MacAlgorithm: MacAlgorithmSpec | None
    KeyId: KeyIdType | None


class GenerateRandomRequest(ServiceRequest):
    NumberOfBytes: NumberOfBytesType | None
    CustomKeyStoreId: CustomKeyStoreIdType | None
    Recipient: RecipientInfo | None


class GenerateRandomResponse(TypedDict, total=False):
    Plaintext: PlaintextType | None
    CiphertextForRecipient: CiphertextType | None


class GetKeyPolicyRequest(ServiceRequest):
    KeyId: KeyIdType
    PolicyName: PolicyNameType | None


class GetKeyPolicyResponse(TypedDict, total=False):
    Policy: PolicyType | None
    PolicyName: PolicyNameType | None


class GetKeyRotationStatusRequest(ServiceRequest):
    KeyId: KeyIdType


class GetKeyRotationStatusResponse(TypedDict, total=False):
    KeyRotationEnabled: BooleanType | None
    KeyId: KeyIdType | None
    RotationPeriodInDays: RotationPeriodInDaysType | None
    NextRotationDate: DateType | None
    OnDemandRotationStartDate: DateType | None


class GetParametersForImportRequest(ServiceRequest):
    KeyId: KeyIdType
    WrappingAlgorithm: AlgorithmSpec
    WrappingKeySpec: WrappingKeySpec


class GetParametersForImportResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    ImportToken: CiphertextType | None
    PublicKey: PlaintextType | None
    ParametersValidTo: DateType | None


class GetPublicKeyRequest(ServiceRequest):
    KeyId: KeyIdType
    GrantTokens: GrantTokenList | None


class GetPublicKeyResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    PublicKey: PublicKeyType | None
    CustomerMasterKeySpec: CustomerMasterKeySpec | None
    KeySpec: KeySpec | None
    KeyUsage: KeyUsageType | None
    EncryptionAlgorithms: EncryptionAlgorithmSpecList | None
    SigningAlgorithms: SigningAlgorithmSpecList | None
    KeyAgreementAlgorithms: KeyAgreementAlgorithmSpecList | None


class GrantListEntry(TypedDict, total=False):
    KeyId: KeyIdType | None
    GrantId: GrantIdType | None
    Name: GrantNameType | None
    CreationDate: DateType | None
    GranteePrincipal: PrincipalIdType | None
    RetiringPrincipal: PrincipalIdType | None
    IssuingAccount: PrincipalIdType | None
    Operations: GrantOperationList | None
    Constraints: GrantConstraints | None


GrantList = list[GrantListEntry]


class ImportKeyMaterialRequest(ServiceRequest):
    KeyId: KeyIdType
    ImportToken: CiphertextType
    EncryptedKeyMaterial: CiphertextType
    ValidTo: DateType | None
    ExpirationModel: ExpirationModelType | None
    ImportType: ImportType | None
    KeyMaterialDescription: KeyMaterialDescriptionType | None
    KeyMaterialId: BackingKeyIdType | None


class ImportKeyMaterialResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    KeyMaterialId: BackingKeyIdType | None


class KeyListEntry(TypedDict, total=False):
    KeyId: KeyIdType | None
    KeyArn: ArnType | None


KeyList = list[KeyListEntry]


class ListAliasesRequest(ServiceRequest):
    KeyId: KeyIdType | None
    Limit: LimitType | None
    Marker: MarkerType | None


class ListAliasesResponse(TypedDict, total=False):
    Aliases: AliasList | None
    NextMarker: MarkerType | None
    Truncated: BooleanType | None


class ListGrantsRequest(ServiceRequest):
    Limit: LimitType | None
    Marker: MarkerType | None
    KeyId: KeyIdType
    GrantId: GrantIdType | None
    GranteePrincipal: PrincipalIdType | None


class ListGrantsResponse(TypedDict, total=False):
    Grants: GrantList | None
    NextMarker: MarkerType | None
    Truncated: BooleanType | None


class ListKeyPoliciesRequest(ServiceRequest):
    KeyId: KeyIdType
    Limit: LimitType | None
    Marker: MarkerType | None


PolicyNameList = list[PolicyNameType]


class ListKeyPoliciesResponse(TypedDict, total=False):
    PolicyNames: PolicyNameList | None
    NextMarker: MarkerType | None
    Truncated: BooleanType | None


class ListKeyRotationsRequest(ServiceRequest):
    KeyId: KeyIdType
    IncludeKeyMaterial: IncludeKeyMaterial | None
    Limit: LimitType | None
    Marker: MarkerType | None


class RotationsListEntry(TypedDict, total=False):
    KeyId: KeyIdType | None
    KeyMaterialId: BackingKeyIdType | None
    KeyMaterialDescription: KeyMaterialDescriptionType | None
    ImportState: ImportState | None
    KeyMaterialState: KeyMaterialState | None
    ExpirationModel: ExpirationModelType | None
    ValidTo: DateType | None
    RotationDate: DateType | None
    RotationType: RotationType | None


RotationsList = list[RotationsListEntry]


class ListKeyRotationsResponse(TypedDict, total=False):
    Rotations: RotationsList | None
    NextMarker: MarkerType | None
    Truncated: BooleanType | None


class ListKeysRequest(ServiceRequest):
    Limit: LimitType | None
    Marker: MarkerType | None


class ListKeysResponse(TypedDict, total=False):
    Keys: KeyList | None
    NextMarker: MarkerType | None
    Truncated: BooleanType | None


class ListResourceTagsRequest(ServiceRequest):
    KeyId: KeyIdType
    Limit: LimitType | None
    Marker: MarkerType | None


class ListResourceTagsResponse(TypedDict, total=False):
    Tags: TagList | None
    NextMarker: MarkerType | None
    Truncated: BooleanType | None


class ListRetirableGrantsRequest(ServiceRequest):
    Limit: LimitType | None
    Marker: MarkerType | None
    RetiringPrincipal: PrincipalIdType


class PutKeyPolicyRequest(ServiceRequest):
    KeyId: KeyIdType
    PolicyName: PolicyNameType | None
    Policy: PolicyType
    BypassPolicyLockoutSafetyCheck: BooleanType | None


class ReEncryptRequest(ServiceRequest):
    CiphertextBlob: CiphertextType
    SourceEncryptionContext: EncryptionContextType | None
    SourceKeyId: KeyIdType | None
    DestinationKeyId: KeyIdType
    DestinationEncryptionContext: EncryptionContextType | None
    SourceEncryptionAlgorithm: EncryptionAlgorithmSpec | None
    DestinationEncryptionAlgorithm: EncryptionAlgorithmSpec | None
    GrantTokens: GrantTokenList | None
    DryRun: NullableBooleanType | None


class ReEncryptResponse(TypedDict, total=False):
    CiphertextBlob: CiphertextType | None
    SourceKeyId: KeyIdType | None
    KeyId: KeyIdType | None
    SourceEncryptionAlgorithm: EncryptionAlgorithmSpec | None
    DestinationEncryptionAlgorithm: EncryptionAlgorithmSpec | None
    SourceKeyMaterialId: BackingKeyIdType | None
    DestinationKeyMaterialId: BackingKeyIdType | None


class ReplicateKeyRequest(ServiceRequest):
    KeyId: KeyIdType
    ReplicaRegion: RegionType
    Policy: PolicyType | None
    BypassPolicyLockoutSafetyCheck: BooleanType | None
    Description: DescriptionType | None
    Tags: TagList | None


class ReplicateKeyResponse(TypedDict, total=False):
    ReplicaKeyMetadata: KeyMetadata | None
    ReplicaPolicy: PolicyType | None
    ReplicaTags: TagList | None


class RetireGrantRequest(ServiceRequest):
    GrantToken: GrantTokenType | None
    KeyId: KeyIdType | None
    GrantId: GrantIdType | None
    DryRun: NullableBooleanType | None


class RevokeGrantRequest(ServiceRequest):
    KeyId: KeyIdType
    GrantId: GrantIdType
    DryRun: NullableBooleanType | None


class RotateKeyOnDemandRequest(ServiceRequest):
    KeyId: KeyIdType


class RotateKeyOnDemandResponse(TypedDict, total=False):
    KeyId: KeyIdType | None


class ScheduleKeyDeletionRequest(ServiceRequest):
    KeyId: KeyIdType
    PendingWindowInDays: PendingWindowInDaysType | None


class ScheduleKeyDeletionResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    DeletionDate: DateType | None
    KeyState: KeyState | None
    PendingWindowInDays: PendingWindowInDaysType | None


class SignRequest(ServiceRequest):
    KeyId: KeyIdType
    Message: PlaintextType
    MessageType: MessageType | None
    GrantTokens: GrantTokenList | None
    SigningAlgorithm: SigningAlgorithmSpec
    DryRun: NullableBooleanType | None


class SignResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    Signature: CiphertextType | None
    SigningAlgorithm: SigningAlgorithmSpec | None


TagKeyList = list[TagKeyType]


class TagResourceRequest(ServiceRequest):
    KeyId: KeyIdType
    Tags: TagList


class UntagResourceRequest(ServiceRequest):
    KeyId: KeyIdType
    TagKeys: TagKeyList


class UpdateAliasRequest(ServiceRequest):
    AliasName: AliasNameType
    TargetKeyId: KeyIdType


class UpdateCustomKeyStoreRequest(ServiceRequest):
    CustomKeyStoreId: CustomKeyStoreIdType
    NewCustomKeyStoreName: CustomKeyStoreNameType | None
    KeyStorePassword: KeyStorePasswordType | None
    CloudHsmClusterId: CloudHsmClusterIdType | None
    XksProxyUriEndpoint: XksProxyUriEndpointType | None
    XksProxyUriPath: XksProxyUriPathType | None
    XksProxyVpcEndpointServiceName: XksProxyVpcEndpointServiceNameType | None
    XksProxyVpcEndpointServiceOwner: AccountIdType | None
    XksProxyAuthenticationCredential: XksProxyAuthenticationCredentialType | None
    XksProxyConnectivity: XksProxyConnectivityType | None


class UpdateCustomKeyStoreResponse(TypedDict, total=False):
    pass


class UpdateKeyDescriptionRequest(ServiceRequest):
    KeyId: KeyIdType
    Description: DescriptionType


class UpdatePrimaryRegionRequest(ServiceRequest):
    KeyId: KeyIdType
    PrimaryRegion: RegionType


class VerifyMacRequest(ServiceRequest):
    Message: PlaintextType
    KeyId: KeyIdType
    MacAlgorithm: MacAlgorithmSpec
    Mac: CiphertextType
    GrantTokens: GrantTokenList | None
    DryRun: NullableBooleanType | None


class VerifyMacResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    MacValid: BooleanType | None
    MacAlgorithm: MacAlgorithmSpec | None


class VerifyRequest(ServiceRequest):
    KeyId: KeyIdType
    Message: PlaintextType
    MessageType: MessageType | None
    Signature: CiphertextType
    SigningAlgorithm: SigningAlgorithmSpec
    GrantTokens: GrantTokenList | None
    DryRun: NullableBooleanType | None


class VerifyResponse(TypedDict, total=False):
    KeyId: KeyIdType | None
    SignatureValid: BooleanType | None
    SigningAlgorithm: SigningAlgorithmSpec | None


class KmsApi:
    service: str = "kms"
    version: str = "2014-11-01"

    @handler("CancelKeyDeletion")
    def cancel_key_deletion(
        self, context: RequestContext, key_id: KeyIdType, **kwargs
    ) -> CancelKeyDeletionResponse:
        raise NotImplementedError

    @handler("ConnectCustomKeyStore")
    def connect_custom_key_store(
        self, context: RequestContext, custom_key_store_id: CustomKeyStoreIdType, **kwargs
    ) -> ConnectCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("CreateAlias")
    def create_alias(
        self, context: RequestContext, alias_name: AliasNameType, target_key_id: KeyIdType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("CreateCustomKeyStore")
    def create_custom_key_store(
        self,
        context: RequestContext,
        custom_key_store_name: CustomKeyStoreNameType,
        cloud_hsm_cluster_id: CloudHsmClusterIdType | None = None,
        trust_anchor_certificate: TrustAnchorCertificateType | None = None,
        key_store_password: KeyStorePasswordType | None = None,
        custom_key_store_type: CustomKeyStoreType | None = None,
        xks_proxy_uri_endpoint: XksProxyUriEndpointType | None = None,
        xks_proxy_uri_path: XksProxyUriPathType | None = None,
        xks_proxy_vpc_endpoint_service_name: XksProxyVpcEndpointServiceNameType | None = None,
        xks_proxy_vpc_endpoint_service_owner: AccountIdType | None = None,
        xks_proxy_authentication_credential: XksProxyAuthenticationCredentialType | None = None,
        xks_proxy_connectivity: XksProxyConnectivityType | None = None,
        **kwargs,
    ) -> CreateCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("CreateGrant")
    def create_grant(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        grantee_principal: PrincipalIdType,
        operations: GrantOperationList,
        retiring_principal: PrincipalIdType | None = None,
        constraints: GrantConstraints | None = None,
        grant_tokens: GrantTokenList | None = None,
        name: GrantNameType | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> CreateGrantResponse:
        raise NotImplementedError

    @handler("CreateKey")
    def create_key(
        self,
        context: RequestContext,
        policy: PolicyType | None = None,
        description: DescriptionType | None = None,
        key_usage: KeyUsageType | None = None,
        customer_master_key_spec: CustomerMasterKeySpec | None = None,
        key_spec: KeySpec | None = None,
        origin: OriginType | None = None,
        custom_key_store_id: CustomKeyStoreIdType | None = None,
        bypass_policy_lockout_safety_check: BooleanType | None = None,
        tags: TagList | None = None,
        multi_region: NullableBooleanType | None = None,
        xks_key_id: XksKeyIdType | None = None,
        **kwargs,
    ) -> CreateKeyResponse:
        raise NotImplementedError

    @handler("Decrypt")
    def decrypt(
        self,
        context: RequestContext,
        ciphertext_blob: CiphertextType,
        encryption_context: EncryptionContextType | None = None,
        grant_tokens: GrantTokenList | None = None,
        key_id: KeyIdType | None = None,
        encryption_algorithm: EncryptionAlgorithmSpec | None = None,
        recipient: RecipientInfo | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> DecryptResponse:
        raise NotImplementedError

    @handler("DeleteAlias")
    def delete_alias(self, context: RequestContext, alias_name: AliasNameType, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteCustomKeyStore")
    def delete_custom_key_store(
        self, context: RequestContext, custom_key_store_id: CustomKeyStoreIdType, **kwargs
    ) -> DeleteCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("DeleteImportedKeyMaterial")
    def delete_imported_key_material(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        key_material_id: BackingKeyIdType | None = None,
        **kwargs,
    ) -> DeleteImportedKeyMaterialResponse:
        raise NotImplementedError

    @handler("DeriveSharedSecret")
    def derive_shared_secret(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        key_agreement_algorithm: KeyAgreementAlgorithmSpec,
        public_key: PublicKeyType,
        grant_tokens: GrantTokenList | None = None,
        dry_run: NullableBooleanType | None = None,
        recipient: RecipientInfo | None = None,
        **kwargs,
    ) -> DeriveSharedSecretResponse:
        raise NotImplementedError

    @handler("DescribeCustomKeyStores")
    def describe_custom_key_stores(
        self,
        context: RequestContext,
        custom_key_store_id: CustomKeyStoreIdType | None = None,
        custom_key_store_name: CustomKeyStoreNameType | None = None,
        limit: LimitType | None = None,
        marker: MarkerType | None = None,
        **kwargs,
    ) -> DescribeCustomKeyStoresResponse:
        raise NotImplementedError

    @handler("DescribeKey")
    def describe_key(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        grant_tokens: GrantTokenList | None = None,
        **kwargs,
    ) -> DescribeKeyResponse:
        raise NotImplementedError

    @handler("DisableKey")
    def disable_key(self, context: RequestContext, key_id: KeyIdType, **kwargs) -> None:
        raise NotImplementedError

    @handler("DisableKeyRotation")
    def disable_key_rotation(self, context: RequestContext, key_id: KeyIdType, **kwargs) -> None:
        raise NotImplementedError

    @handler("DisconnectCustomKeyStore")
    def disconnect_custom_key_store(
        self, context: RequestContext, custom_key_store_id: CustomKeyStoreIdType, **kwargs
    ) -> DisconnectCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("EnableKey")
    def enable_key(self, context: RequestContext, key_id: KeyIdType, **kwargs) -> None:
        raise NotImplementedError

    @handler("EnableKeyRotation")
    def enable_key_rotation(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        rotation_period_in_days: RotationPeriodInDaysType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("Encrypt")
    def encrypt(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        plaintext: PlaintextType,
        encryption_context: EncryptionContextType | None = None,
        grant_tokens: GrantTokenList | None = None,
        encryption_algorithm: EncryptionAlgorithmSpec | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> EncryptResponse:
        raise NotImplementedError

    @handler("GenerateDataKey")
    def generate_data_key(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        encryption_context: EncryptionContextType | None = None,
        number_of_bytes: NumberOfBytesType | None = None,
        key_spec: DataKeySpec | None = None,
        grant_tokens: GrantTokenList | None = None,
        recipient: RecipientInfo | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> GenerateDataKeyResponse:
        raise NotImplementedError

    @handler("GenerateDataKeyPair")
    def generate_data_key_pair(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        key_pair_spec: DataKeyPairSpec,
        encryption_context: EncryptionContextType | None = None,
        grant_tokens: GrantTokenList | None = None,
        recipient: RecipientInfo | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> GenerateDataKeyPairResponse:
        raise NotImplementedError

    @handler("GenerateDataKeyPairWithoutPlaintext")
    def generate_data_key_pair_without_plaintext(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        key_pair_spec: DataKeyPairSpec,
        encryption_context: EncryptionContextType | None = None,
        grant_tokens: GrantTokenList | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> GenerateDataKeyPairWithoutPlaintextResponse:
        raise NotImplementedError

    @handler("GenerateDataKeyWithoutPlaintext")
    def generate_data_key_without_plaintext(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        encryption_context: EncryptionContextType | None = None,
        key_spec: DataKeySpec | None = None,
        number_of_bytes: NumberOfBytesType | None = None,
        grant_tokens: GrantTokenList | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> GenerateDataKeyWithoutPlaintextResponse:
        raise NotImplementedError

    @handler("GenerateMac")
    def generate_mac(
        self,
        context: RequestContext,
        message: PlaintextType,
        key_id: KeyIdType,
        mac_algorithm: MacAlgorithmSpec,
        grant_tokens: GrantTokenList | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> GenerateMacResponse:
        raise NotImplementedError

    @handler("GenerateRandom")
    def generate_random(
        self,
        context: RequestContext,
        number_of_bytes: NumberOfBytesType | None = None,
        custom_key_store_id: CustomKeyStoreIdType | None = None,
        recipient: RecipientInfo | None = None,
        **kwargs,
    ) -> GenerateRandomResponse:
        raise NotImplementedError

    @handler("GetKeyPolicy")
    def get_key_policy(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        policy_name: PolicyNameType | None = None,
        **kwargs,
    ) -> GetKeyPolicyResponse:
        raise NotImplementedError

    @handler("GetKeyRotationStatus")
    def get_key_rotation_status(
        self, context: RequestContext, key_id: KeyIdType, **kwargs
    ) -> GetKeyRotationStatusResponse:
        raise NotImplementedError

    @handler("GetParametersForImport")
    def get_parameters_for_import(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        wrapping_algorithm: AlgorithmSpec,
        wrapping_key_spec: WrappingKeySpec,
        **kwargs,
    ) -> GetParametersForImportResponse:
        raise NotImplementedError

    @handler("GetPublicKey")
    def get_public_key(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        grant_tokens: GrantTokenList | None = None,
        **kwargs,
    ) -> GetPublicKeyResponse:
        raise NotImplementedError

    @handler("ImportKeyMaterial")
    def import_key_material(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        import_token: CiphertextType,
        encrypted_key_material: CiphertextType,
        valid_to: DateType | None = None,
        expiration_model: ExpirationModelType | None = None,
        import_type: ImportType | None = None,
        key_material_description: KeyMaterialDescriptionType | None = None,
        key_material_id: BackingKeyIdType | None = None,
        **kwargs,
    ) -> ImportKeyMaterialResponse:
        raise NotImplementedError

    @handler("ListAliases")
    def list_aliases(
        self,
        context: RequestContext,
        key_id: KeyIdType | None = None,
        limit: LimitType | None = None,
        marker: MarkerType | None = None,
        **kwargs,
    ) -> ListAliasesResponse:
        raise NotImplementedError

    @handler("ListGrants")
    def list_grants(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        limit: LimitType | None = None,
        marker: MarkerType | None = None,
        grant_id: GrantIdType | None = None,
        grantee_principal: PrincipalIdType | None = None,
        **kwargs,
    ) -> ListGrantsResponse:
        raise NotImplementedError

    @handler("ListKeyPolicies")
    def list_key_policies(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        limit: LimitType | None = None,
        marker: MarkerType | None = None,
        **kwargs,
    ) -> ListKeyPoliciesResponse:
        raise NotImplementedError

    @handler("ListKeyRotations")
    def list_key_rotations(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        include_key_material: IncludeKeyMaterial | None = None,
        limit: LimitType | None = None,
        marker: MarkerType | None = None,
        **kwargs,
    ) -> ListKeyRotationsResponse:
        raise NotImplementedError

    @handler("ListKeys")
    def list_keys(
        self,
        context: RequestContext,
        limit: LimitType | None = None,
        marker: MarkerType | None = None,
        **kwargs,
    ) -> ListKeysResponse:
        raise NotImplementedError

    @handler("ListResourceTags")
    def list_resource_tags(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        limit: LimitType | None = None,
        marker: MarkerType | None = None,
        **kwargs,
    ) -> ListResourceTagsResponse:
        raise NotImplementedError

    @handler("ListRetirableGrants")
    def list_retirable_grants(
        self,
        context: RequestContext,
        retiring_principal: PrincipalIdType,
        limit: LimitType | None = None,
        marker: MarkerType | None = None,
        **kwargs,
    ) -> ListGrantsResponse:
        raise NotImplementedError

    @handler("PutKeyPolicy")
    def put_key_policy(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        policy: PolicyType,
        policy_name: PolicyNameType | None = None,
        bypass_policy_lockout_safety_check: BooleanType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ReEncrypt")
    def re_encrypt(
        self,
        context: RequestContext,
        ciphertext_blob: CiphertextType,
        destination_key_id: KeyIdType,
        source_encryption_context: EncryptionContextType | None = None,
        source_key_id: KeyIdType | None = None,
        destination_encryption_context: EncryptionContextType | None = None,
        source_encryption_algorithm: EncryptionAlgorithmSpec | None = None,
        destination_encryption_algorithm: EncryptionAlgorithmSpec | None = None,
        grant_tokens: GrantTokenList | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> ReEncryptResponse:
        raise NotImplementedError

    @handler("ReplicateKey")
    def replicate_key(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        replica_region: RegionType,
        policy: PolicyType | None = None,
        bypass_policy_lockout_safety_check: BooleanType | None = None,
        description: DescriptionType | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> ReplicateKeyResponse:
        raise NotImplementedError

    @handler("RetireGrant")
    def retire_grant(
        self,
        context: RequestContext,
        grant_token: GrantTokenType | None = None,
        key_id: KeyIdType | None = None,
        grant_id: GrantIdType | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RevokeGrant")
    def revoke_grant(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        grant_id: GrantIdType,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RotateKeyOnDemand")
    def rotate_key_on_demand(
        self, context: RequestContext, key_id: KeyIdType, **kwargs
    ) -> RotateKeyOnDemandResponse:
        raise NotImplementedError

    @handler("ScheduleKeyDeletion")
    def schedule_key_deletion(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        pending_window_in_days: PendingWindowInDaysType | None = None,
        **kwargs,
    ) -> ScheduleKeyDeletionResponse:
        raise NotImplementedError

    @handler("Sign")
    def sign(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        message: PlaintextType,
        signing_algorithm: SigningAlgorithmSpec,
        message_type: MessageType | None = None,
        grant_tokens: GrantTokenList | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> SignResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, key_id: KeyIdType, tags: TagList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, key_id: KeyIdType, tag_keys: TagKeyList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAlias")
    def update_alias(
        self, context: RequestContext, alias_name: AliasNameType, target_key_id: KeyIdType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdateCustomKeyStore")
    def update_custom_key_store(
        self,
        context: RequestContext,
        custom_key_store_id: CustomKeyStoreIdType,
        new_custom_key_store_name: CustomKeyStoreNameType | None = None,
        key_store_password: KeyStorePasswordType | None = None,
        cloud_hsm_cluster_id: CloudHsmClusterIdType | None = None,
        xks_proxy_uri_endpoint: XksProxyUriEndpointType | None = None,
        xks_proxy_uri_path: XksProxyUriPathType | None = None,
        xks_proxy_vpc_endpoint_service_name: XksProxyVpcEndpointServiceNameType | None = None,
        xks_proxy_vpc_endpoint_service_owner: AccountIdType | None = None,
        xks_proxy_authentication_credential: XksProxyAuthenticationCredentialType | None = None,
        xks_proxy_connectivity: XksProxyConnectivityType | None = None,
        **kwargs,
    ) -> UpdateCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("UpdateKeyDescription")
    def update_key_description(
        self, context: RequestContext, key_id: KeyIdType, description: DescriptionType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdatePrimaryRegion")
    def update_primary_region(
        self, context: RequestContext, key_id: KeyIdType, primary_region: RegionType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("Verify")
    def verify(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        message: PlaintextType,
        signature: CiphertextType,
        signing_algorithm: SigningAlgorithmSpec,
        message_type: MessageType | None = None,
        grant_tokens: GrantTokenList | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> VerifyResponse:
        raise NotImplementedError

    @handler("VerifyMac")
    def verify_mac(
        self,
        context: RequestContext,
        message: PlaintextType,
        key_id: KeyIdType,
        mac_algorithm: MacAlgorithmSpec,
        mac: CiphertextType,
        grant_tokens: GrantTokenList | None = None,
        dry_run: NullableBooleanType | None = None,
        **kwargs,
    ) -> VerifyMacResponse:
        raise NotImplementedError
