from datetime import datetime
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AWSAccountIdType = str
AliasNameType = str
ArnType = str
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
TagKeyType = str
TagValueType = str
TrustAnchorCertificateType = str
XksKeyIdType = str
XksProxyAuthenticationAccessKeyIdType = str
XksProxyAuthenticationRawSecretAccessKeyType = str
XksProxyUriEndpointType = str
XksProxyUriPathType = str
XksProxyVpcEndpointServiceNameType = str


class AlgorithmSpec(str):
    RSAES_PKCS1_V1_5 = "RSAES_PKCS1_V1_5"
    RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1"
    RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"
    RSA_AES_KEY_WRAP_SHA_1 = "RSA_AES_KEY_WRAP_SHA_1"
    RSA_AES_KEY_WRAP_SHA_256 = "RSA_AES_KEY_WRAP_SHA_256"


class ConnectionErrorCodeType(str):
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


class ConnectionStateType(str):
    CONNECTED = "CONNECTED"
    CONNECTING = "CONNECTING"
    FAILED = "FAILED"
    DISCONNECTED = "DISCONNECTED"
    DISCONNECTING = "DISCONNECTING"


class CustomKeyStoreType(str):
    AWS_CLOUDHSM = "AWS_CLOUDHSM"
    EXTERNAL_KEY_STORE = "EXTERNAL_KEY_STORE"


class CustomerMasterKeySpec(str):
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


class DataKeyPairSpec(str):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    ECC_NIST_P256 = "ECC_NIST_P256"
    ECC_NIST_P384 = "ECC_NIST_P384"
    ECC_NIST_P521 = "ECC_NIST_P521"
    ECC_SECG_P256K1 = "ECC_SECG_P256K1"
    SM2 = "SM2"


class DataKeySpec(str):
    AES_256 = "AES_256"
    AES_128 = "AES_128"


class EncryptionAlgorithmSpec(str):
    SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT"
    RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1"
    RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"
    SM2PKE = "SM2PKE"


class ExpirationModelType(str):
    KEY_MATERIAL_EXPIRES = "KEY_MATERIAL_EXPIRES"
    KEY_MATERIAL_DOES_NOT_EXPIRE = "KEY_MATERIAL_DOES_NOT_EXPIRE"


class GrantOperation(str):
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


class KeyEncryptionMechanism(str):
    RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"


class KeyManagerType(str):
    AWS = "AWS"
    CUSTOMER = "CUSTOMER"


class KeySpec(str):
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


class KeyState(str):
    Creating = "Creating"
    Enabled = "Enabled"
    Disabled = "Disabled"
    PendingDeletion = "PendingDeletion"
    PendingImport = "PendingImport"
    PendingReplicaDeletion = "PendingReplicaDeletion"
    Unavailable = "Unavailable"
    Updating = "Updating"


class KeyUsageType(str):
    SIGN_VERIFY = "SIGN_VERIFY"
    ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
    GENERATE_VERIFY_MAC = "GENERATE_VERIFY_MAC"


class MacAlgorithmSpec(str):
    HMAC_SHA_224 = "HMAC_SHA_224"
    HMAC_SHA_256 = "HMAC_SHA_256"
    HMAC_SHA_384 = "HMAC_SHA_384"
    HMAC_SHA_512 = "HMAC_SHA_512"


class MessageType(str):
    RAW = "RAW"
    DIGEST = "DIGEST"


class MultiRegionKeyType(str):
    PRIMARY = "PRIMARY"
    REPLICA = "REPLICA"


class OriginType(str):
    AWS_KMS = "AWS_KMS"
    EXTERNAL = "EXTERNAL"
    AWS_CLOUDHSM = "AWS_CLOUDHSM"
    EXTERNAL_KEY_STORE = "EXTERNAL_KEY_STORE"


class SigningAlgorithmSpec(str):
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


class WrappingKeySpec(str):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"


class XksProxyConnectivityType(str):
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
    AliasName: Optional[AliasNameType]
    AliasArn: Optional[ArnType]
    TargetKeyId: Optional[KeyIdType]
    CreationDate: Optional[DateType]
    LastUpdatedDate: Optional[DateType]


AliasList = List[AliasListEntry]
AttestationDocumentType = bytes


class CancelKeyDeletionRequest(ServiceRequest):
    KeyId: KeyIdType


class CancelKeyDeletionResponse(TypedDict, total=False):
    KeyId: Optional[KeyIdType]


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
    CloudHsmClusterId: Optional[CloudHsmClusterIdType]
    TrustAnchorCertificate: Optional[TrustAnchorCertificateType]
    KeyStorePassword: Optional[KeyStorePasswordType]
    CustomKeyStoreType: Optional[CustomKeyStoreType]
    XksProxyUriEndpoint: Optional[XksProxyUriEndpointType]
    XksProxyUriPath: Optional[XksProxyUriPathType]
    XksProxyVpcEndpointServiceName: Optional[XksProxyVpcEndpointServiceNameType]
    XksProxyAuthenticationCredential: Optional[XksProxyAuthenticationCredentialType]
    XksProxyConnectivity: Optional[XksProxyConnectivityType]


class CreateCustomKeyStoreResponse(TypedDict, total=False):
    CustomKeyStoreId: Optional[CustomKeyStoreIdType]


GrantTokenList = List[GrantTokenType]
EncryptionContextType = Dict[EncryptionContextKey, EncryptionContextValue]


class GrantConstraints(TypedDict, total=False):
    EncryptionContextSubset: Optional[EncryptionContextType]
    EncryptionContextEquals: Optional[EncryptionContextType]


GrantOperationList = List[GrantOperation]


class CreateGrantRequest(ServiceRequest):
    KeyId: KeyIdType
    GranteePrincipal: PrincipalIdType
    RetiringPrincipal: Optional[PrincipalIdType]
    Operations: GrantOperationList
    Constraints: Optional[GrantConstraints]
    GrantTokens: Optional[GrantTokenList]
    Name: Optional[GrantNameType]
    DryRun: Optional[NullableBooleanType]


class CreateGrantResponse(TypedDict, total=False):
    GrantToken: Optional[GrantTokenType]
    GrantId: Optional[GrantIdType]


class Tag(TypedDict, total=False):
    TagKey: TagKeyType
    TagValue: TagValueType


TagList = List[Tag]


class CreateKeyRequest(ServiceRequest):
    Policy: Optional[PolicyType]
    Description: Optional[DescriptionType]
    KeyUsage: Optional[KeyUsageType]
    CustomerMasterKeySpec: Optional[CustomerMasterKeySpec]
    KeySpec: Optional[KeySpec]
    Origin: Optional[OriginType]
    CustomKeyStoreId: Optional[CustomKeyStoreIdType]
    BypassPolicyLockoutSafetyCheck: Optional[BooleanType]
    Tags: Optional[TagList]
    MultiRegion: Optional[NullableBooleanType]
    XksKeyId: Optional[XksKeyIdType]


class XksKeyConfigurationType(TypedDict, total=False):
    Id: Optional[XksKeyIdType]


MacAlgorithmSpecList = List[MacAlgorithmSpec]


class MultiRegionKey(TypedDict, total=False):
    Arn: Optional[ArnType]
    Region: Optional[RegionType]


MultiRegionKeyList = List[MultiRegionKey]


class MultiRegionConfiguration(TypedDict, total=False):
    MultiRegionKeyType: Optional[MultiRegionKeyType]
    PrimaryKey: Optional[MultiRegionKey]
    ReplicaKeys: Optional[MultiRegionKeyList]


SigningAlgorithmSpecList = List[SigningAlgorithmSpec]
EncryptionAlgorithmSpecList = List[EncryptionAlgorithmSpec]


class KeyMetadata(TypedDict, total=False):
    AWSAccountId: Optional[AWSAccountIdType]
    KeyId: KeyIdType
    Arn: Optional[ArnType]
    CreationDate: Optional[DateType]
    Enabled: Optional[BooleanType]
    Description: Optional[DescriptionType]
    KeyUsage: Optional[KeyUsageType]
    KeyState: Optional[KeyState]
    DeletionDate: Optional[DateType]
    ValidTo: Optional[DateType]
    Origin: Optional[OriginType]
    CustomKeyStoreId: Optional[CustomKeyStoreIdType]
    CloudHsmClusterId: Optional[CloudHsmClusterIdType]
    ExpirationModel: Optional[ExpirationModelType]
    KeyManager: Optional[KeyManagerType]
    CustomerMasterKeySpec: Optional[CustomerMasterKeySpec]
    KeySpec: Optional[KeySpec]
    EncryptionAlgorithms: Optional[EncryptionAlgorithmSpecList]
    SigningAlgorithms: Optional[SigningAlgorithmSpecList]
    MultiRegion: Optional[NullableBooleanType]
    MultiRegionConfiguration: Optional[MultiRegionConfiguration]
    PendingDeletionWindowInDays: Optional[PendingWindowInDaysType]
    MacAlgorithms: Optional[MacAlgorithmSpecList]
    XksKeyConfiguration: Optional[XksKeyConfigurationType]


class CreateKeyResponse(TypedDict, total=False):
    KeyMetadata: Optional[KeyMetadata]


class XksProxyConfigurationType(TypedDict, total=False):
    Connectivity: Optional[XksProxyConnectivityType]
    AccessKeyId: Optional[XksProxyAuthenticationAccessKeyIdType]
    UriEndpoint: Optional[XksProxyUriEndpointType]
    UriPath: Optional[XksProxyUriPathType]
    VpcEndpointServiceName: Optional[XksProxyVpcEndpointServiceNameType]


class CustomKeyStoresListEntry(TypedDict, total=False):
    CustomKeyStoreId: Optional[CustomKeyStoreIdType]
    CustomKeyStoreName: Optional[CustomKeyStoreNameType]
    CloudHsmClusterId: Optional[CloudHsmClusterIdType]
    TrustAnchorCertificate: Optional[TrustAnchorCertificateType]
    ConnectionState: Optional[ConnectionStateType]
    ConnectionErrorCode: Optional[ConnectionErrorCodeType]
    CreationDate: Optional[DateType]
    CustomKeyStoreType: Optional[CustomKeyStoreType]
    XksProxyConfiguration: Optional[XksProxyConfigurationType]


CustomKeyStoresList = List[CustomKeyStoresListEntry]


class RecipientInfo(TypedDict, total=False):
    KeyEncryptionAlgorithm: Optional[KeyEncryptionMechanism]
    AttestationDocument: Optional[AttestationDocumentType]


class DecryptRequest(ServiceRequest):
    CiphertextBlob: CiphertextType
    EncryptionContext: Optional[EncryptionContextType]
    GrantTokens: Optional[GrantTokenList]
    KeyId: Optional[KeyIdType]
    EncryptionAlgorithm: Optional[EncryptionAlgorithmSpec]
    Recipient: Optional[RecipientInfo]
    DryRun: Optional[NullableBooleanType]


PlaintextType = bytes


class DecryptResponse(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    Plaintext: Optional[PlaintextType]
    EncryptionAlgorithm: Optional[EncryptionAlgorithmSpec]
    CiphertextForRecipient: Optional[CiphertextType]


class DeleteAliasRequest(ServiceRequest):
    AliasName: AliasNameType


class DeleteCustomKeyStoreRequest(ServiceRequest):
    CustomKeyStoreId: CustomKeyStoreIdType


class DeleteCustomKeyStoreResponse(TypedDict, total=False):
    pass


class DeleteImportedKeyMaterialRequest(ServiceRequest):
    KeyId: KeyIdType


class DescribeCustomKeyStoresRequest(ServiceRequest):
    CustomKeyStoreId: Optional[CustomKeyStoreIdType]
    CustomKeyStoreName: Optional[CustomKeyStoreNameType]
    Limit: Optional[LimitType]
    Marker: Optional[MarkerType]


class DescribeCustomKeyStoresResponse(TypedDict, total=False):
    CustomKeyStores: Optional[CustomKeyStoresList]
    NextMarker: Optional[MarkerType]
    Truncated: Optional[BooleanType]


class DescribeKeyRequest(ServiceRequest):
    KeyId: KeyIdType
    GrantTokens: Optional[GrantTokenList]


class DescribeKeyResponse(TypedDict, total=False):
    KeyMetadata: Optional[KeyMetadata]


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


class EncryptRequest(ServiceRequest):
    KeyId: KeyIdType
    Plaintext: PlaintextType
    EncryptionContext: Optional[EncryptionContextType]
    GrantTokens: Optional[GrantTokenList]
    EncryptionAlgorithm: Optional[EncryptionAlgorithmSpec]
    DryRun: Optional[NullableBooleanType]


class EncryptResponse(TypedDict, total=False):
    CiphertextBlob: Optional[CiphertextType]
    KeyId: Optional[KeyIdType]
    EncryptionAlgorithm: Optional[EncryptionAlgorithmSpec]


class GenerateDataKeyPairRequest(ServiceRequest):
    EncryptionContext: Optional[EncryptionContextType]
    KeyId: KeyIdType
    KeyPairSpec: DataKeyPairSpec
    GrantTokens: Optional[GrantTokenList]
    Recipient: Optional[RecipientInfo]
    DryRun: Optional[NullableBooleanType]


PublicKeyType = bytes


class GenerateDataKeyPairResponse(TypedDict, total=False):
    PrivateKeyCiphertextBlob: Optional[CiphertextType]
    PrivateKeyPlaintext: Optional[PlaintextType]
    PublicKey: Optional[PublicKeyType]
    KeyId: Optional[KeyIdType]
    KeyPairSpec: Optional[DataKeyPairSpec]
    CiphertextForRecipient: Optional[CiphertextType]


class GenerateDataKeyPairWithoutPlaintextRequest(ServiceRequest):
    EncryptionContext: Optional[EncryptionContextType]
    KeyId: KeyIdType
    KeyPairSpec: DataKeyPairSpec
    GrantTokens: Optional[GrantTokenList]
    DryRun: Optional[NullableBooleanType]


class GenerateDataKeyPairWithoutPlaintextResponse(TypedDict, total=False):
    PrivateKeyCiphertextBlob: Optional[CiphertextType]
    PublicKey: Optional[PublicKeyType]
    KeyId: Optional[KeyIdType]
    KeyPairSpec: Optional[DataKeyPairSpec]


class GenerateDataKeyRequest(ServiceRequest):
    KeyId: KeyIdType
    EncryptionContext: Optional[EncryptionContextType]
    NumberOfBytes: Optional[NumberOfBytesType]
    KeySpec: Optional[DataKeySpec]
    GrantTokens: Optional[GrantTokenList]
    Recipient: Optional[RecipientInfo]
    DryRun: Optional[NullableBooleanType]


class GenerateDataKeyResponse(TypedDict, total=False):
    CiphertextBlob: Optional[CiphertextType]
    Plaintext: Optional[PlaintextType]
    KeyId: Optional[KeyIdType]
    CiphertextForRecipient: Optional[CiphertextType]


class GenerateDataKeyWithoutPlaintextRequest(ServiceRequest):
    KeyId: KeyIdType
    EncryptionContext: Optional[EncryptionContextType]
    KeySpec: Optional[DataKeySpec]
    NumberOfBytes: Optional[NumberOfBytesType]
    GrantTokens: Optional[GrantTokenList]
    DryRun: Optional[NullableBooleanType]


class GenerateDataKeyWithoutPlaintextResponse(TypedDict, total=False):
    CiphertextBlob: Optional[CiphertextType]
    KeyId: Optional[KeyIdType]


class GenerateMacRequest(ServiceRequest):
    Message: PlaintextType
    KeyId: KeyIdType
    MacAlgorithm: MacAlgorithmSpec
    GrantTokens: Optional[GrantTokenList]
    DryRun: Optional[NullableBooleanType]


class GenerateMacResponse(TypedDict, total=False):
    Mac: Optional[CiphertextType]
    MacAlgorithm: Optional[MacAlgorithmSpec]
    KeyId: Optional[KeyIdType]


class GenerateRandomRequest(ServiceRequest):
    NumberOfBytes: Optional[NumberOfBytesType]
    CustomKeyStoreId: Optional[CustomKeyStoreIdType]
    Recipient: Optional[RecipientInfo]


class GenerateRandomResponse(TypedDict, total=False):
    Plaintext: Optional[PlaintextType]
    CiphertextForRecipient: Optional[CiphertextType]


class GetKeyPolicyRequest(ServiceRequest):
    KeyId: KeyIdType
    PolicyName: PolicyNameType


class GetKeyPolicyResponse(TypedDict, total=False):
    Policy: Optional[PolicyType]


class GetKeyRotationStatusRequest(ServiceRequest):
    KeyId: KeyIdType


class GetKeyRotationStatusResponse(TypedDict, total=False):
    KeyRotationEnabled: Optional[BooleanType]


class GetParametersForImportRequest(ServiceRequest):
    KeyId: KeyIdType
    WrappingAlgorithm: AlgorithmSpec
    WrappingKeySpec: WrappingKeySpec


class GetParametersForImportResponse(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    ImportToken: Optional[CiphertextType]
    PublicKey: Optional[PlaintextType]
    ParametersValidTo: Optional[DateType]


class GetPublicKeyRequest(ServiceRequest):
    KeyId: KeyIdType
    GrantTokens: Optional[GrantTokenList]


class GetPublicKeyResponse(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    PublicKey: Optional[PublicKeyType]
    CustomerMasterKeySpec: Optional[CustomerMasterKeySpec]
    KeySpec: Optional[KeySpec]
    KeyUsage: Optional[KeyUsageType]
    EncryptionAlgorithms: Optional[EncryptionAlgorithmSpecList]
    SigningAlgorithms: Optional[SigningAlgorithmSpecList]


class GrantListEntry(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    GrantId: Optional[GrantIdType]
    Name: Optional[GrantNameType]
    CreationDate: Optional[DateType]
    GranteePrincipal: Optional[PrincipalIdType]
    RetiringPrincipal: Optional[PrincipalIdType]
    IssuingAccount: Optional[PrincipalIdType]
    Operations: Optional[GrantOperationList]
    Constraints: Optional[GrantConstraints]


GrantList = List[GrantListEntry]


class ImportKeyMaterialRequest(ServiceRequest):
    KeyId: KeyIdType
    ImportToken: CiphertextType
    EncryptedKeyMaterial: CiphertextType
    ValidTo: Optional[DateType]
    ExpirationModel: Optional[ExpirationModelType]


class ImportKeyMaterialResponse(TypedDict, total=False):
    pass


class KeyListEntry(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    KeyArn: Optional[ArnType]


KeyList = List[KeyListEntry]


class ListAliasesRequest(ServiceRequest):
    KeyId: Optional[KeyIdType]
    Limit: Optional[LimitType]
    Marker: Optional[MarkerType]


class ListAliasesResponse(TypedDict, total=False):
    Aliases: Optional[AliasList]
    NextMarker: Optional[MarkerType]
    Truncated: Optional[BooleanType]


class ListGrantsRequest(ServiceRequest):
    Limit: Optional[LimitType]
    Marker: Optional[MarkerType]
    KeyId: KeyIdType
    GrantId: Optional[GrantIdType]
    GranteePrincipal: Optional[PrincipalIdType]


class ListGrantsResponse(TypedDict, total=False):
    Grants: Optional[GrantList]
    NextMarker: Optional[MarkerType]
    Truncated: Optional[BooleanType]


class ListKeyPoliciesRequest(ServiceRequest):
    KeyId: KeyIdType
    Limit: Optional[LimitType]
    Marker: Optional[MarkerType]


PolicyNameList = List[PolicyNameType]


class ListKeyPoliciesResponse(TypedDict, total=False):
    PolicyNames: Optional[PolicyNameList]
    NextMarker: Optional[MarkerType]
    Truncated: Optional[BooleanType]


class ListKeysRequest(ServiceRequest):
    Limit: Optional[LimitType]
    Marker: Optional[MarkerType]


class ListKeysResponse(TypedDict, total=False):
    Keys: Optional[KeyList]
    NextMarker: Optional[MarkerType]
    Truncated: Optional[BooleanType]


class ListResourceTagsRequest(ServiceRequest):
    KeyId: KeyIdType
    Limit: Optional[LimitType]
    Marker: Optional[MarkerType]


class ListResourceTagsResponse(TypedDict, total=False):
    Tags: Optional[TagList]
    NextMarker: Optional[MarkerType]
    Truncated: Optional[BooleanType]


class ListRetirableGrantsRequest(ServiceRequest):
    Limit: Optional[LimitType]
    Marker: Optional[MarkerType]
    RetiringPrincipal: PrincipalIdType


class PutKeyPolicyRequest(ServiceRequest):
    KeyId: KeyIdType
    PolicyName: PolicyNameType
    Policy: PolicyType
    BypassPolicyLockoutSafetyCheck: Optional[BooleanType]


class ReEncryptRequest(ServiceRequest):
    CiphertextBlob: CiphertextType
    SourceEncryptionContext: Optional[EncryptionContextType]
    SourceKeyId: Optional[KeyIdType]
    DestinationKeyId: KeyIdType
    DestinationEncryptionContext: Optional[EncryptionContextType]
    SourceEncryptionAlgorithm: Optional[EncryptionAlgorithmSpec]
    DestinationEncryptionAlgorithm: Optional[EncryptionAlgorithmSpec]
    GrantTokens: Optional[GrantTokenList]
    DryRun: Optional[NullableBooleanType]


class ReEncryptResponse(TypedDict, total=False):
    CiphertextBlob: Optional[CiphertextType]
    SourceKeyId: Optional[KeyIdType]
    KeyId: Optional[KeyIdType]
    SourceEncryptionAlgorithm: Optional[EncryptionAlgorithmSpec]
    DestinationEncryptionAlgorithm: Optional[EncryptionAlgorithmSpec]


class ReplicateKeyRequest(ServiceRequest):
    KeyId: KeyIdType
    ReplicaRegion: RegionType
    Policy: Optional[PolicyType]
    BypassPolicyLockoutSafetyCheck: Optional[BooleanType]
    Description: Optional[DescriptionType]
    Tags: Optional[TagList]


class ReplicateKeyResponse(TypedDict, total=False):
    ReplicaKeyMetadata: Optional[KeyMetadata]
    ReplicaPolicy: Optional[PolicyType]
    ReplicaTags: Optional[TagList]


class RetireGrantRequest(ServiceRequest):
    GrantToken: Optional[GrantTokenType]
    KeyId: Optional[KeyIdType]
    GrantId: Optional[GrantIdType]
    DryRun: Optional[NullableBooleanType]


class RevokeGrantRequest(ServiceRequest):
    KeyId: KeyIdType
    GrantId: GrantIdType
    DryRun: Optional[NullableBooleanType]


class ScheduleKeyDeletionRequest(ServiceRequest):
    KeyId: KeyIdType
    PendingWindowInDays: Optional[PendingWindowInDaysType]


class ScheduleKeyDeletionResponse(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    DeletionDate: Optional[DateType]
    KeyState: Optional[KeyState]
    PendingWindowInDays: Optional[PendingWindowInDaysType]


class SignRequest(ServiceRequest):
    KeyId: KeyIdType
    Message: PlaintextType
    MessageType: Optional[MessageType]
    GrantTokens: Optional[GrantTokenList]
    SigningAlgorithm: SigningAlgorithmSpec
    DryRun: Optional[NullableBooleanType]


class SignResponse(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    Signature: Optional[CiphertextType]
    SigningAlgorithm: Optional[SigningAlgorithmSpec]


TagKeyList = List[TagKeyType]


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
    NewCustomKeyStoreName: Optional[CustomKeyStoreNameType]
    KeyStorePassword: Optional[KeyStorePasswordType]
    CloudHsmClusterId: Optional[CloudHsmClusterIdType]
    XksProxyUriEndpoint: Optional[XksProxyUriEndpointType]
    XksProxyUriPath: Optional[XksProxyUriPathType]
    XksProxyVpcEndpointServiceName: Optional[XksProxyVpcEndpointServiceNameType]
    XksProxyAuthenticationCredential: Optional[XksProxyAuthenticationCredentialType]
    XksProxyConnectivity: Optional[XksProxyConnectivityType]


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
    GrantTokens: Optional[GrantTokenList]
    DryRun: Optional[NullableBooleanType]


class VerifyMacResponse(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    MacValid: Optional[BooleanType]
    MacAlgorithm: Optional[MacAlgorithmSpec]


class VerifyRequest(ServiceRequest):
    KeyId: KeyIdType
    Message: PlaintextType
    MessageType: Optional[MessageType]
    Signature: CiphertextType
    SigningAlgorithm: SigningAlgorithmSpec
    GrantTokens: Optional[GrantTokenList]
    DryRun: Optional[NullableBooleanType]


class VerifyResponse(TypedDict, total=False):
    KeyId: Optional[KeyIdType]
    SignatureValid: Optional[BooleanType]
    SigningAlgorithm: Optional[SigningAlgorithmSpec]


class KmsApi:

    service = "kms"
    version = "2014-11-01"

    @handler("CancelKeyDeletion")
    def cancel_key_deletion(
        self, context: RequestContext, key_id: KeyIdType
    ) -> CancelKeyDeletionResponse:
        raise NotImplementedError

    @handler("ConnectCustomKeyStore")
    def connect_custom_key_store(
        self, context: RequestContext, custom_key_store_id: CustomKeyStoreIdType
    ) -> ConnectCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("CreateAlias")
    def create_alias(
        self, context: RequestContext, alias_name: AliasNameType, target_key_id: KeyIdType
    ) -> None:
        raise NotImplementedError

    @handler("CreateCustomKeyStore")
    def create_custom_key_store(
        self,
        context: RequestContext,
        custom_key_store_name: CustomKeyStoreNameType,
        cloud_hsm_cluster_id: CloudHsmClusterIdType = None,
        trust_anchor_certificate: TrustAnchorCertificateType = None,
        key_store_password: KeyStorePasswordType = None,
        custom_key_store_type: CustomKeyStoreType = None,
        xks_proxy_uri_endpoint: XksProxyUriEndpointType = None,
        xks_proxy_uri_path: XksProxyUriPathType = None,
        xks_proxy_vpc_endpoint_service_name: XksProxyVpcEndpointServiceNameType = None,
        xks_proxy_authentication_credential: XksProxyAuthenticationCredentialType = None,
        xks_proxy_connectivity: XksProxyConnectivityType = None,
    ) -> CreateCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("CreateGrant")
    def create_grant(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        grantee_principal: PrincipalIdType,
        operations: GrantOperationList,
        retiring_principal: PrincipalIdType = None,
        constraints: GrantConstraints = None,
        grant_tokens: GrantTokenList = None,
        name: GrantNameType = None,
        dry_run: NullableBooleanType = None,
    ) -> CreateGrantResponse:
        raise NotImplementedError

    @handler("CreateKey")
    def create_key(
        self,
        context: RequestContext,
        policy: PolicyType = None,
        description: DescriptionType = None,
        key_usage: KeyUsageType = None,
        customer_master_key_spec: CustomerMasterKeySpec = None,
        key_spec: KeySpec = None,
        origin: OriginType = None,
        custom_key_store_id: CustomKeyStoreIdType = None,
        bypass_policy_lockout_safety_check: BooleanType = None,
        tags: TagList = None,
        multi_region: NullableBooleanType = None,
        xks_key_id: XksKeyIdType = None,
    ) -> CreateKeyResponse:
        raise NotImplementedError

    @handler("Decrypt")
    def decrypt(
        self,
        context: RequestContext,
        ciphertext_blob: CiphertextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        key_id: KeyIdType = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
        recipient: RecipientInfo = None,
        dry_run: NullableBooleanType = None,
    ) -> DecryptResponse:
        raise NotImplementedError

    @handler("DeleteAlias")
    def delete_alias(self, context: RequestContext, alias_name: AliasNameType) -> None:
        raise NotImplementedError

    @handler("DeleteCustomKeyStore")
    def delete_custom_key_store(
        self, context: RequestContext, custom_key_store_id: CustomKeyStoreIdType
    ) -> DeleteCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("DeleteImportedKeyMaterial")
    def delete_imported_key_material(self, context: RequestContext, key_id: KeyIdType) -> None:
        raise NotImplementedError

    @handler("DescribeCustomKeyStores")
    def describe_custom_key_stores(
        self,
        context: RequestContext,
        custom_key_store_id: CustomKeyStoreIdType = None,
        custom_key_store_name: CustomKeyStoreNameType = None,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> DescribeCustomKeyStoresResponse:
        raise NotImplementedError

    @handler("DescribeKey")
    def describe_key(
        self, context: RequestContext, key_id: KeyIdType, grant_tokens: GrantTokenList = None
    ) -> DescribeKeyResponse:
        raise NotImplementedError

    @handler("DisableKey")
    def disable_key(self, context: RequestContext, key_id: KeyIdType) -> None:
        raise NotImplementedError

    @handler("DisableKeyRotation")
    def disable_key_rotation(self, context: RequestContext, key_id: KeyIdType) -> None:
        raise NotImplementedError

    @handler("DisconnectCustomKeyStore")
    def disconnect_custom_key_store(
        self, context: RequestContext, custom_key_store_id: CustomKeyStoreIdType
    ) -> DisconnectCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("EnableKey")
    def enable_key(self, context: RequestContext, key_id: KeyIdType) -> None:
        raise NotImplementedError

    @handler("EnableKeyRotation")
    def enable_key_rotation(self, context: RequestContext, key_id: KeyIdType) -> None:
        raise NotImplementedError

    @handler("Encrypt")
    def encrypt(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        plaintext: PlaintextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
        dry_run: NullableBooleanType = None,
    ) -> EncryptResponse:
        raise NotImplementedError

    @handler("GenerateDataKey")
    def generate_data_key(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        encryption_context: EncryptionContextType = None,
        number_of_bytes: NumberOfBytesType = None,
        key_spec: DataKeySpec = None,
        grant_tokens: GrantTokenList = None,
        recipient: RecipientInfo = None,
        dry_run: NullableBooleanType = None,
    ) -> GenerateDataKeyResponse:
        raise NotImplementedError

    @handler("GenerateDataKeyPair")
    def generate_data_key_pair(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        key_pair_spec: DataKeyPairSpec,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        recipient: RecipientInfo = None,
        dry_run: NullableBooleanType = None,
    ) -> GenerateDataKeyPairResponse:
        raise NotImplementedError

    @handler("GenerateDataKeyPairWithoutPlaintext")
    def generate_data_key_pair_without_plaintext(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        key_pair_spec: DataKeyPairSpec,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
    ) -> GenerateDataKeyPairWithoutPlaintextResponse:
        raise NotImplementedError

    @handler("GenerateDataKeyWithoutPlaintext")
    def generate_data_key_without_plaintext(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        encryption_context: EncryptionContextType = None,
        key_spec: DataKeySpec = None,
        number_of_bytes: NumberOfBytesType = None,
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
    ) -> GenerateDataKeyWithoutPlaintextResponse:
        raise NotImplementedError

    @handler("GenerateMac")
    def generate_mac(
        self,
        context: RequestContext,
        message: PlaintextType,
        key_id: KeyIdType,
        mac_algorithm: MacAlgorithmSpec,
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
    ) -> GenerateMacResponse:
        raise NotImplementedError

    @handler("GenerateRandom")
    def generate_random(
        self,
        context: RequestContext,
        number_of_bytes: NumberOfBytesType = None,
        custom_key_store_id: CustomKeyStoreIdType = None,
        recipient: RecipientInfo = None,
    ) -> GenerateRandomResponse:
        raise NotImplementedError

    @handler("GetKeyPolicy")
    def get_key_policy(
        self, context: RequestContext, key_id: KeyIdType, policy_name: PolicyNameType
    ) -> GetKeyPolicyResponse:
        raise NotImplementedError

    @handler("GetKeyRotationStatus")
    def get_key_rotation_status(
        self, context: RequestContext, key_id: KeyIdType
    ) -> GetKeyRotationStatusResponse:
        raise NotImplementedError

    @handler("GetParametersForImport")
    def get_parameters_for_import(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        wrapping_algorithm: AlgorithmSpec,
        wrapping_key_spec: WrappingKeySpec,
    ) -> GetParametersForImportResponse:
        raise NotImplementedError

    @handler("GetPublicKey")
    def get_public_key(
        self, context: RequestContext, key_id: KeyIdType, grant_tokens: GrantTokenList = None
    ) -> GetPublicKeyResponse:
        raise NotImplementedError

    @handler("ImportKeyMaterial")
    def import_key_material(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        import_token: CiphertextType,
        encrypted_key_material: CiphertextType,
        valid_to: DateType = None,
        expiration_model: ExpirationModelType = None,
    ) -> ImportKeyMaterialResponse:
        raise NotImplementedError

    @handler("ListAliases")
    def list_aliases(
        self,
        context: RequestContext,
        key_id: KeyIdType = None,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListAliasesResponse:
        raise NotImplementedError

    @handler("ListGrants")
    def list_grants(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        limit: LimitType = None,
        marker: MarkerType = None,
        grant_id: GrantIdType = None,
        grantee_principal: PrincipalIdType = None,
    ) -> ListGrantsResponse:
        raise NotImplementedError

    @handler("ListKeyPolicies")
    def list_key_policies(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListKeyPoliciesResponse:
        raise NotImplementedError

    @handler("ListKeys")
    def list_keys(
        self, context: RequestContext, limit: LimitType = None, marker: MarkerType = None
    ) -> ListKeysResponse:
        raise NotImplementedError

    @handler("ListResourceTags")
    def list_resource_tags(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListResourceTagsResponse:
        raise NotImplementedError

    @handler("ListRetirableGrants")
    def list_retirable_grants(
        self,
        context: RequestContext,
        retiring_principal: PrincipalIdType,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListGrantsResponse:
        raise NotImplementedError

    @handler("PutKeyPolicy")
    def put_key_policy(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        policy_name: PolicyNameType,
        policy: PolicyType,
        bypass_policy_lockout_safety_check: BooleanType = None,
    ) -> None:
        raise NotImplementedError

    @handler("ReEncrypt")
    def re_encrypt(
        self,
        context: RequestContext,
        ciphertext_blob: CiphertextType,
        destination_key_id: KeyIdType,
        source_encryption_context: EncryptionContextType = None,
        source_key_id: KeyIdType = None,
        destination_encryption_context: EncryptionContextType = None,
        source_encryption_algorithm: EncryptionAlgorithmSpec = None,
        destination_encryption_algorithm: EncryptionAlgorithmSpec = None,
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
    ) -> ReEncryptResponse:
        raise NotImplementedError

    @handler("ReplicateKey")
    def replicate_key(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        replica_region: RegionType,
        policy: PolicyType = None,
        bypass_policy_lockout_safety_check: BooleanType = None,
        description: DescriptionType = None,
        tags: TagList = None,
    ) -> ReplicateKeyResponse:
        raise NotImplementedError

    @handler("RetireGrant")
    def retire_grant(
        self,
        context: RequestContext,
        grant_token: GrantTokenType = None,
        key_id: KeyIdType = None,
        grant_id: GrantIdType = None,
        dry_run: NullableBooleanType = None,
    ) -> None:
        raise NotImplementedError

    @handler("RevokeGrant")
    def revoke_grant(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        grant_id: GrantIdType,
        dry_run: NullableBooleanType = None,
    ) -> None:
        raise NotImplementedError

    @handler("ScheduleKeyDeletion")
    def schedule_key_deletion(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        pending_window_in_days: PendingWindowInDaysType = None,
    ) -> ScheduleKeyDeletionResponse:
        raise NotImplementedError

    @handler("Sign")
    def sign(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        message: PlaintextType,
        signing_algorithm: SigningAlgorithmSpec,
        message_type: MessageType = None,
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
    ) -> SignResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, key_id: KeyIdType, tags: TagList) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, key_id: KeyIdType, tag_keys: TagKeyList
    ) -> None:
        raise NotImplementedError

    @handler("UpdateAlias")
    def update_alias(
        self, context: RequestContext, alias_name: AliasNameType, target_key_id: KeyIdType
    ) -> None:
        raise NotImplementedError

    @handler("UpdateCustomKeyStore")
    def update_custom_key_store(
        self,
        context: RequestContext,
        custom_key_store_id: CustomKeyStoreIdType,
        new_custom_key_store_name: CustomKeyStoreNameType = None,
        key_store_password: KeyStorePasswordType = None,
        cloud_hsm_cluster_id: CloudHsmClusterIdType = None,
        xks_proxy_uri_endpoint: XksProxyUriEndpointType = None,
        xks_proxy_uri_path: XksProxyUriPathType = None,
        xks_proxy_vpc_endpoint_service_name: XksProxyVpcEndpointServiceNameType = None,
        xks_proxy_authentication_credential: XksProxyAuthenticationCredentialType = None,
        xks_proxy_connectivity: XksProxyConnectivityType = None,
    ) -> UpdateCustomKeyStoreResponse:
        raise NotImplementedError

    @handler("UpdateKeyDescription")
    def update_key_description(
        self, context: RequestContext, key_id: KeyIdType, description: DescriptionType
    ) -> None:
        raise NotImplementedError

    @handler("UpdatePrimaryRegion")
    def update_primary_region(
        self, context: RequestContext, key_id: KeyIdType, primary_region: RegionType
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
        message_type: MessageType = None,
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
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
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
    ) -> VerifyMacResponse:
        raise NotImplementedError
