from localstack.feature_catalog.service_feature import (
    ImplementationStatus,
    ServiceFeature,
    SupportStatus,
)


class KMSFeature(ServiceFeature):
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED


# Key Management


class KeyManagement(KMSFeature):
    general_docs: str = "Manages the creation and lifecycle of the cryptographic keys"
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/kms/latest/developerguide/getting-started.html"
    )


class Provisioning(KeyManagement):
    general_docs: str = "Manage the creation and modification of the keys."
    implementation_status: ImplementationStatus = ImplementationStatus.FULLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html"
    api_operations: list = ["CreateKey"]


class Alias(KeyManagement):
    general_docs: str = "Manage the aliases for referring to a KMS key."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html"


class StateControl(KeyManagement):
    general_docs: str = "Control the activation and deactivation of keys."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/enabling-keys.html"


class Deletion(KeyManagement):
    general_docs: str = "Manage the deletion of the keys."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html"


class Viewing(KeyManagement):
    general_docs: str = "View the details of the keys."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html"


class Tagging(KeyManagement):
    general_docs = "Manage the tags of the keys."
    implementation_status: ImplementationStatus = ImplementationStatus.FULLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/tagging-keys.html"


class Rotation(KeyManagement):
    general_docs: str = "Manage the rotation of the keys."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"


# CryptographicOperations


class CryptographicOperations(KMSFeature):
    general_docs: str = "Perform cryptographic operations using the keys for data protecttion."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    limitations: list = ["Limited support for offline encryption and decryption"]
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations"


class Symmetric(CryptographicOperations):
    general_docs: str = "Manage the symmetric keys for crytographic operations."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#symmetric-cmks"
    )


class Asymmetric(CryptographicOperations):
    general_docs: str = "Manage the asymmetric keys for crytographic operations."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    limitations: list = ["No support for SM2 key spec"]
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#asymmetric-keys-concept"


class HMAC(CryptographicOperations):
    general_docs: str = "Manage the HMAC keys for crytographic operations."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/hmac.html"


class Data(CryptographicOperations):
    general_docs: str = "Manage the data keys for crytographic operations."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#data-keys"
    )


class Random(CryptographicOperations):
    general_docs = "Generate random data for cryptographic operations."
    implementation_status = ImplementationStatus.FULLY_IMPLEMENTED
    support_type = SupportStatus.SUPPORTED
    aws_docs_link = "https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateRandom.html"


# PolicyAndPermissions


class AccessControl(KMSFeature):
    general_docs: str = "Define and manage permissions and access control for the keys."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/control-access.html"


class Policy(AccessControl):
    general_docs: str = "Manage the key policies for the keys."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html"


class Grant(AccessControl):
    general_docs: str = "Manage the grants for the keys."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/grants.html"


# Custom KeyStores


class CustomKeyStores(KMSFeature):
    general_docs: str = "Store the keys in custom key stores."
    support_type: SupportStatus = SupportStatus.NOT_SUPPORTED
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/kms/latest/developerguide/custom-key-store-overview.html"
    )


class StoreManagement(CustomKeyStores):
    general_docs: str = "Manage the custom key stores."
    support_type: SupportStatus = SupportStatus.NOT_SUPPORTED
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/kms/latest/developerguide/keystore-cloudhsm.html"
    )


# Multi-Region


class MultiRegion(KMSFeature):
    general_docs: str = "Manage the keys across multiple regions."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    limitations: list = [
        "Key replication is not automatically synchronized with the corresponding primary key"
    ]
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html"
    )


# Import


class Import(KMSFeature):
    general_docs: str = "Import your own cryptographic key material to AWS KMS."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    aws_docs_link: str = "https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html"


# TODO:
# "FULLY_IMPLEMENTED" -> definition? how to measure this? parity issues tracker usage?
# - feature support vs api support
