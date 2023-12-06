import base64
import datetime
import io
import json
import logging
import os
import random
import re
import struct
import uuid
from collections import namedtuple
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from localstack.aws.api.kms import (
    CreateAliasRequest,
    CreateGrantRequest,
    CreateKeyRequest,
    EncryptionContextType,
    KeyMetadata,
    KeyState,
    KMSInvalidMacException,
    KMSInvalidSignatureException,
    MacAlgorithmSpec,
    MessageType,
    OriginType,
    SigningAlgorithmSpec,
    UnsupportedOperationException,
)
from localstack.services.kms.exceptions import ValidationException
from localstack.services.kms.utils import is_valid_key_arn
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.aws.arns import kms_alias_arn, kms_key_arn
from localstack.utils.crypto import decrypt, encrypt
from localstack.utils.strings import long_uid, to_bytes, to_str

LOG = logging.getLogger(__name__)

PATTERN_UUID = re.compile(
    r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$"
)
MULTI_REGION_PATTERN = re.compile(r"^mrk-[a-fA-F0-9]{32}$")

SYMMETRIC_DEFAULT_MATERIAL_LENGTH = 32

RSA_CRYPTO_KEY_LENGTHS = {
    "RSA_2048": 2048,
    "RSA_3072": 3072,
    "RSA_4096": 4096,
}

ECC_CURVES = {
    "ECC_NIST_P256": ec.SECP256R1(),
    "ECC_NIST_P384": ec.SECP384R1(),
    "ECC_NIST_P521": ec.SECP521R1(),
    "ECC_SECG_P256K1": ec.SECP256K1(),
}

HMAC_RANGE_KEY_LENGTHS = {
    "HMAC_224": (28, 64),
    "HMAC_256": (32, 64),
    "HMAC_384": (48, 128),
    "HMAC_512": (64, 128),
}

KEY_ID_LEN = 36
# Moto uses IV_LEN of 12, as it is fine for GCM encryption mode, but we use CBC, so have to set it to 16.
IV_LEN = 16
TAG_LEN = 16
CIPHERTEXT_HEADER_FORMAT = ">{key_id_len}s{iv_len}s{tag_len}s".format(
    key_id_len=KEY_ID_LEN, iv_len=IV_LEN, tag_len=TAG_LEN
)
HEADER_LEN = KEY_ID_LEN + IV_LEN + TAG_LEN
Ciphertext = namedtuple("Ciphertext", ("key_id", "iv", "ciphertext", "tag"))

RESERVED_ALIASES = [
    "alias/aws/acm",
    "alias/aws/dynamodb",
    "alias/aws/ebs",
    "alias/aws/elasticfilesystem",
    "alias/aws/es",
    "alias/aws/glue",
    "alias/aws/kinesisvideo",
    "alias/aws/lambda",
    "alias/aws/rds",
    "alias/aws/redshift",
    "alias/aws/s3",
    "alias/aws/secretsmanager",
    "alias/aws/ssm",
    "alias/aws/xray",
]

# list of key names that should be skipped when serializing the encryption context
IGNORED_CONTEXT_KEYS = ["aws-crypto-public-key"]


def _serialize_ciphertext_blob(ciphertext: Ciphertext) -> bytes:
    header = struct.pack(
        CIPHERTEXT_HEADER_FORMAT,
        ciphertext.key_id.encode("utf-8"),
        ciphertext.iv,
        ciphertext.tag,
    )
    return header + ciphertext.ciphertext


def deserialize_ciphertext_blob(ciphertext_blob: bytes) -> Ciphertext:
    header = ciphertext_blob[:HEADER_LEN]
    ciphertext = ciphertext_blob[HEADER_LEN:]
    key_id, iv, tag = struct.unpack(CIPHERTEXT_HEADER_FORMAT, header)
    return Ciphertext(key_id=key_id.decode("utf-8"), iv=iv, ciphertext=ciphertext, tag=tag)


def _serialize_encryption_context(encryption_context: Optional[EncryptionContextType]) -> bytes:
    if encryption_context:
        aad = io.BytesIO()
        for key, value in sorted(encryption_context.items(), key=lambda x: x[0]):
            # remove the reserved key-value pair from additional authentication data
            if key not in IGNORED_CONTEXT_KEYS:
                aad.write(key.encode("utf-8"))
                aad.write(value.encode("utf-8"))
        return aad.getvalue()
    else:
        return b""


# Confusion alert!
# In KMS, there are two things that can be called "keys":
#   1. A cryptographic key, i.e. a string of characters, a private/public/symmetrical key for cryptographic encoding
#   and decoding etc. It is modeled here by KmsCryptoKey class.
#   2. An AWS object that stores both a cryptographic key and some relevant metadata, e.g. creation time, a unique ID,
#   some state. It is modeled by KmsKey class.
#
# While KmsKeys always contain KmsCryptoKeys, sometimes KmsCryptoKeys exist without corresponding KmsKeys,
# e.g. GenerateDataKeyPair API call returns contents of a new KmsCryptoKey that is not associated with any KmsKey,
# but is partially encrypted by some pre-existing KmsKey.


class KmsCryptoKey:
    """
    KmsCryptoKeys used to model both of the two cases where AWS generates keys:
    1. Keys that are created to be used inside of AWS. For such a key, its key material / private key are not to
    leave AWS unencrypted. If they have to leave AWS, a different KmsCryptoKey is used to encrypt the data first.
    2. Keys that AWS creates for customers for some external use. Such a key might be returned to a customer with its
    key material or public key unencrypted - see KMS GenerateDataKey / GenerateDataKeyPair. But such a key is not stored
    by AWS and is not used by AWS.
    """

    public_key: Optional[bytes]
    private_key: Optional[bytes]
    key_material: bytes

    def __init__(self, key_spec: str):
        self.private_key = None
        self.public_key = None
        # Technically, key_material, being a symmetric encryption key, is only relevant for
        #   key_spec == SYMMETRIC_DEFAULT.
        # But LocalStack uses symmetric encryption with this key_material even for other specs. Asymmetric keys are
        # generated, but are not actually used.
        self.key_material = os.urandom(SYMMETRIC_DEFAULT_MATERIAL_LENGTH)

        if key_spec == "SYMMETRIC_DEFAULT":
            return

        if key_spec.startswith("RSA"):
            key_size = RSA_CRYPTO_KEY_LENGTHS.get(key_spec)
            key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        elif key_spec.startswith("ECC"):
            curve = ECC_CURVES.get(key_spec)
            key = ec.generate_private_key(curve)
        elif key_spec.startswith("HMAC"):
            if key_spec not in HMAC_RANGE_KEY_LENGTHS:
                raise ValidationException(
                    f"1 validation error detected: Value '{key_spec}' at 'keySpec' "
                    f"failed to satisfy constraint: Member must satisfy enum value set: "
                    f"[RSA_2048, ECC_NIST_P384, ECC_NIST_P256, ECC_NIST_P521, HMAC_384, RSA_3072, "
                    f"ECC_SECG_P256K1, RSA_4096, SYMMETRIC_DEFAULT, HMAC_256, HMAC_224, HMAC_512]"
                )
            minimum_length, maximum_length = HMAC_RANGE_KEY_LENGTHS.get(key_spec)
            self.key_material = os.urandom(random.randint(minimum_length, maximum_length))
            return
        else:
            # We do not support SM2 - asymmetric keys both suitable for ENCRYPT_DECRYPT and SIGN_VERIFY,
            # but only used in China AWS regions.
            raise UnsupportedOperationException(f"KeySpec {key_spec} is not supported")

        self.private_key = key.private_bytes(
            crypto_serialization.Encoding.DER,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption(),
        )
        self.public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.DER,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def key(self) -> RSAPrivateKey:
        return crypto_serialization.load_der_private_key(
            self.private_key,
            password=None,
            backend=default_backend(),
        )


class KmsKey:
    metadata: KeyMetadata
    crypto_key: KmsCryptoKey
    tags: Dict[str, str]
    policy: str
    is_key_rotation_enabled: bool

    def __init__(
        self,
        create_key_request: CreateKeyRequest = None,
        account_id: str = None,
        region: str = None,
    ):
        create_key_request = create_key_request or CreateKeyRequest()
        self._populate_metadata(create_key_request, account_id, region)
        self.crypto_key = KmsCryptoKey(self.metadata.get("KeySpec"))
        # Please keep in mind that tags of a key could be present in the request, they are not a part of metadata. At
        # least in the sense of DescribeKey not returning them with the rest of the metadata. Instead, tags are more
        # like aliases:
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html
        # "DescribeKey does not return the following information: ... Tags on the KMS key."
        self.tags = {}
        self.add_tags(create_key_request.get("Tags"))
        # Same goes for the policy. It is in the request, but not in the metadata.
        self.policy = create_key_request.get("Policy") or self._get_default_key_policy(account_id)
        # https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html
        # "Automatic key rotation is disabled by default on customer managed keys but authorized users can enable and
        # disable it."
        self.is_key_rotation_enabled = False

    def calculate_and_set_arn(self, account_id, region):
        self.metadata["Arn"] = kms_key_arn(self.metadata.get("KeyId"), account_id, region)

    def generate_mac(self, msg: bytes, mac_algorithm: MacAlgorithmSpec) -> bytes:
        h = self._get_hmac_context(mac_algorithm)
        h.update(msg)
        return h.finalize()

    def verify_mac(self, msg: bytes, mac: bytes, mac_algorithm: MacAlgorithmSpec) -> bool:
        h = self._get_hmac_context(mac_algorithm)
        h.update(msg)
        try:
            h.verify(mac)
            return True
        except InvalidSignature:
            raise KMSInvalidMacException()

    # Encrypt is a method of KmsKey and not of KmsCryptoKey only because it requires KeyId, and KmsCryptoKeys do not
    # hold KeyIds. Maybe it would be possible to remodel this better.
    def encrypt(self, plaintext: bytes, encryption_context: EncryptionContextType = None) -> bytes:
        iv = os.urandom(IV_LEN)
        aad = _serialize_encryption_context(encryption_context=encryption_context)
        ciphertext, tag = encrypt(self.crypto_key.key_material, plaintext, iv, aad)
        return _serialize_ciphertext_blob(
            ciphertext=Ciphertext(
                key_id=self.metadata.get("KeyId"), iv=iv, ciphertext=ciphertext, tag=tag
            )
        )

    # The ciphertext has to be deserialized before this call.
    def decrypt(
        self, ciphertext: Ciphertext, encryption_context: EncryptionContextType = None
    ) -> bytes:
        aad = _serialize_encryption_context(encryption_context=encryption_context)
        return decrypt(
            self.crypto_key.key_material, ciphertext.ciphertext, ciphertext.iv, ciphertext.tag, aad
        )

    def sign(
        self, data: bytes, message_type: MessageType, signing_algorithm: SigningAlgorithmSpec
    ) -> bytes:
        kwargs = self._construct_sign_verify_kwargs(signing_algorithm, message_type)
        try:
            return self.crypto_key.key.sign(data=data, **kwargs)
        except ValueError as exc:
            raise ValidationException(str(exc))

    def verify(
        self,
        data: bytes,
        message_type: MessageType,
        signing_algorithm: SigningAlgorithmSpec,
        signature: bytes,
    ) -> bool:
        kwargs = self._construct_sign_verify_kwargs(signing_algorithm, message_type)
        try:
            self.crypto_key.key.public_key().verify(signature=signature, data=data, **kwargs)
            return True
        except ValueError as exc:
            raise ValidationException(str(exc))
        except InvalidSignature:
            # AWS itself raises this exception without any additional message.
            raise KMSInvalidSignatureException()

    def _get_hmac_context(self, mac_algorithm: MacAlgorithmSpec) -> hmac.HMAC:
        if mac_algorithm == "HMAC_SHA_224":
            h = hmac.HMAC(self.crypto_key.key_material, hashes.SHA224())
        elif mac_algorithm == "HMAC_SHA_256":
            h = hmac.HMAC(self.crypto_key.key_material, hashes.SHA256())
        elif mac_algorithm == "HMAC_SHA_384":
            h = hmac.HMAC(self.crypto_key.key_material, hashes.SHA384())
        elif mac_algorithm == "HMAC_SHA_512":
            h = hmac.HMAC(self.crypto_key.key_material, hashes.SHA512())
        else:
            raise ValidationException(
                f"1 validation error detected: Value '{mac_algorithm}' at 'macAlgorithm' "
                f"failed to satisfy constraint: Member must satisfy enum value set: "
                f"[HMAC_SHA_384, HMAC_SHA_256, HMAC_SHA_224, HMAC_SHA_512]"
            )
        return h

    def _construct_sign_verify_kwargs(
        self, signing_algorithm: SigningAlgorithmSpec, message_type: MessageType
    ) -> Dict:
        kwargs = {}

        if "SHA_256" in signing_algorithm:
            hasher = hashes.SHA256()
        elif "SHA_384" in signing_algorithm:
            hasher = hashes.SHA384()
        elif "SHA_512" in signing_algorithm:
            hasher = hashes.SHA512()
        else:
            raise ValidationException(
                f"Unsupported hash type in SigningAlgorithm '{signing_algorithm}'"
            )

        if message_type == MessageType.DIGEST:
            kwargs["algorithm"] = utils.Prehashed(hasher)
        else:
            kwargs["algorithm"] = hasher

        if signing_algorithm.startswith("ECDSA"):
            kwargs["signature_algorithm"] = ec.ECDSA(algorithm=kwargs.pop("algorithm", None))
            return kwargs

        if signing_algorithm.startswith("RSA"):
            if "PKCS" in signing_algorithm:
                kwargs["padding"] = padding.PKCS1v15()
            elif "PSS" in signing_algorithm:
                kwargs["padding"] = padding.PSS(
                    mgf=padding.MGF1(hasher), salt_length=padding.PSS.MAX_LENGTH
                )
            else:
                LOG.warning("Unsupported padding in SigningAlgorithm '%s'", signing_algorithm)

        return kwargs

    # Not a comment, rather some possibly relevant links for the future.
    # https://docs.aws.amazon.com/kms/latest/developerguide/asymm-create-key.html
    # "You cannot create an elliptic curve key pair for encryption and decryption."
    # https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#asymmetric-keys-concept
    # "You can create asymmetric KMS keys that represent RSA key pairs for public key encryption or signing and
    # verification, or elliptic curve key pairs for signing and verification."
    #
    # A useful link with a cheat-sheet of what operations are supported by what types of keys:
    # https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-compare.html
    #
    # https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#data-keys
    # "AWS KMS generates the data key. Then it encrypts a copy of the data key under a symmetric encryption KMS key that
    # you specify."
    #
    # Data keys are symmetric, data key pairs are asymmetric.
    def _populate_metadata(
        self, create_key_request: CreateKeyRequest, account_id: str, region: str
    ) -> None:
        self.metadata = KeyMetadata()
        # Metadata fields coming from a creation request
        #
        # We do not include tags into the metadata. Tags might be present in a key creation request, but our metadata
        # only contains data displayed by DescribeKey. And tags are not there:
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html
        # "DescribeKey does not return the following information: ... Tags on the KMS key."

        self.metadata["Description"] = create_key_request.get("Description") or ""
        self.metadata["MultiRegion"] = create_key_request.get("MultiRegion") or False
        self.metadata["Origin"] = create_key_request.get("Origin") or "AWS_KMS"
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html#KMS-CreateKey-request-CustomerMasterKeySpec
        # CustomerMasterKeySpec has been deprecated, still used for compatibility. Is replaced by KeySpec.
        # The meaning is the same, just the name differs.
        self.metadata["KeySpec"] = (
            create_key_request.get("KeySpec")
            or create_key_request.get("CustomerMasterKeySpec")
            or "SYMMETRIC_DEFAULT"
        )
        self.metadata["CustomerMasterKeySpec"] = self.metadata.get("KeySpec")
        self.metadata["KeyUsage"] = self._get_key_usage(
            create_key_request.get("KeyUsage"), self.metadata.get("KeySpec")
        )

        # Metadata fields AWS introduces automatically
        self.metadata["AWSAccountId"] = account_id
        self.metadata["CreationDate"] = datetime.datetime.now()
        self.metadata["Enabled"] = create_key_request.get("Origin") != OriginType.EXTERNAL
        self.metadata["KeyManager"] = "CUSTOMER"
        self.metadata["KeyState"] = (
            KeyState.Enabled
            if create_key_request.get("Origin") != OriginType.EXTERNAL
            else KeyState.PendingImport
        )
        # https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
        # "Notice that multi-Region keys have a distinctive key ID that begins with mrk-. You can use the mrk- prefix to
        # identify MRKs programmatically."
        # The ID for MultiRegion keys also do not have dashes.
        if self.metadata.get("MultiRegion"):
            self.metadata["KeyId"] = "mrk-" + str(uuid.uuid4().hex)
        else:
            self.metadata["KeyId"] = str(uuid.uuid4())
        self.calculate_and_set_arn(account_id, region)

        self._populate_encryption_algorithms(
            self.metadata.get("KeyUsage"), self.metadata.get("KeySpec")
        )
        self._populate_signing_algorithms(
            self.metadata.get("KeyUsage"), self.metadata.get("KeySpec")
        )
        self._populate_mac_algorithms(self.metadata.get("KeyUsage"), self.metadata.get("KeySpec"))

    def add_tags(self, tags: List) -> None:
        # Just in case we get None from somewhere.
        if not tags:
            return

        # Do not care if we overwrite an existing tag:
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_TagResource.html
        # "To edit a tag, specify an existing tag key and a new tag value."
        for tag in tags:
            self.tags[tag.get("TagKey")] = tag.get("TagValue")

    def schedule_key_deletion(self, pending_window_in_days: int) -> None:
        self.metadata["Enabled"] = False
        # TODO For MultiRegion keys, the status of replicas get set to "PendingDeletion", while the primary key
        #  becomes "PendingReplicaDeletion". Here we just set all keys to "PendingDeletion", as we do not have any
        #  notion of a primary key in LocalStack. Might be useful to improve it.
        #  https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-delete.html#primary-delete
        self.metadata["KeyState"] = "PendingDeletion"
        self.metadata["DeletionDate"] = datetime.datetime.now() + datetime.timedelta(
            days=pending_window_in_days
        )

    # An example of how the whole policy should look like:
    # https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html
    # The default statement is here:
    # https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#key-policy-default-allow-root-enable-iam
    def _get_default_key_policy(self, account_id: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Id": "key-default-1",
                "Statement": [
                    {
                        "Sid": "Enable IAM User Permissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ],
            }
        )

    def _populate_encryption_algorithms(self, key_usage: str, key_spec: str) -> None:
        # The two main usages for KMS keys are encryption/decryption and signing/verification.
        # Doesn't make sense to populate fields related to encryption/decryption unless the key is created with that
        # goal in mind.
        if key_usage != "ENCRYPT_DECRYPT":
            return
        if key_spec == "SYMMETRIC_DEFAULT":
            self.metadata["EncryptionAlgorithms"] = ["SYMMETRIC_DEFAULT"]
        else:
            self.metadata["EncryptionAlgorithms"] = ["RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"]

    def _populate_signing_algorithms(self, key_usage: str, key_spec: str) -> None:
        # The two main usages for KMS keys are encryption/decryption and signing/verification.
        # Doesn't make sense to populate fields related to signing/verification unless the key is created with that
        # goal in mind.
        if key_usage != "SIGN_VERIFY":
            return
        if key_spec in ["ECC_NIST_P256", "ECC_SECG_P256K1"]:
            self.metadata["SigningAlgorithms"] = ["ECDSA_SHA_256"]
        elif key_spec == "ECC_NIST_P384":
            self.metadata["SigningAlgorithms"] = ["ECDSA_SHA_384"]
        elif key_spec == "ECC_NIST_P521":
            self.metadata["SigningAlgorithms"] = ["ECDSA_SHA_512"]
        else:
            self.metadata["SigningAlgorithms"] = [
                "RSASSA_PKCS1_V1_5_SHA_256",
                "RSASSA_PKCS1_V1_5_SHA_384",
                "RSASSA_PKCS1_V1_5_SHA_512",
                "RSASSA_PSS_SHA_256",
                "RSASSA_PSS_SHA_384",
                "RSASSA_PSS_SHA_512",
            ]

    def _populate_mac_algorithms(self, key_usage: str, key_spec: str) -> None:
        if key_usage != "GENERATE_VERIFY_MAC":
            return
        if key_spec == "HMAC_224":
            self.metadata["MacAlgorithms"] = ["HMAC_SHA_224"]
        elif key_spec == "HMAC_256":
            self.metadata["MacAlgorithms"] = ["HMAC_SHA_256"]
        elif key_spec == "HMAC_384":
            self.metadata["MacAlgorithms"] = ["HMAC_SHA_384"]
        elif key_spec == "HMAC_512":
            self.metadata["MacAlgorithms"] = ["HMAC_SHA_512"]

    def _get_key_usage(self, request_key_usage: str, key_spec: str) -> str:
        if key_spec in HMAC_RANGE_KEY_LENGTHS:
            if request_key_usage is None:
                raise ValidationException(
                    "You must specify a KeyUsage value for all KMS keys except for symmetric encryption keys."
                )
            elif request_key_usage != "GENERATE_VERIFY_MAC":
                raise ValidationException(
                    f"1 validation error detected: Value '{request_key_usage}' at 'keyUsage' "
                    f"failed to satisfy constraint: Member must satisfy enum value set: "
                    f"[ENCRYPT_DECRYPT, SIGN_VERIFY, GENERATE_VERIFY_MAC]"
                )
            else:
                return "GENERATE_VERIFY_MAC"
        else:
            return request_key_usage or "ENCRYPT_DECRYPT"


class KmsGrant:
    # AWS documentation doesn't seem to mention any metadata object for grants like it does mention KeyMetadata for
    # keys. But, based on our understanding of AWS documentation for CreateGrant, ListGrants operations etc,
    # AWS has some set of fields for grants like it has for keys. So we are going to call them `metadata` here for
    # consistency.
    metadata: Dict
    # Tokens are not a part of metadata, as their use is more limited and specific than for the rest of the
    # metadata: https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token
    # Tokens are used to refer to a grant in a short period right after the grant gets created. Normally it might
    # take KMS up to 5 minutes to make a new grant available. In that time window referring to a grant by its
    # GrantId might not work, so tokens are supposed to be used. The tokens could possibly be used even
    # afterwards. But since the only way to get a token is through a CreateGrant operation (see below), the chances
    # of someone storing a token and using it later are slim.
    #
    # https://docs.aws.amazon.com/kms/latest/developerguide/grants.html#grant_token
    # "CreateGrant is the only operation that returns a grant token. You cannot get a grant token from any other
    # AWS KMS operation or from the CloudTrail log event for the CreateGrant operation. The ListGrants and
    # ListRetirableGrants operations return the grant ID, but not a grant token."
    #
    # Usually a grant might have multiple unique tokens. But here we just model it with a single token for
    # simplicity.
    token: str

    def __init__(self, create_grant_request: CreateGrantRequest, account_id: str, region_name: str):
        self.metadata = dict(create_grant_request)

        if is_valid_key_arn(self.metadata["KeyId"]):
            self.metadata["KeyArn"] = self.metadata["KeyId"]
        else:
            self.metadata["KeyArn"] = kms_key_arn(self.metadata["KeyId"], account_id, region_name)

        self.metadata["GrantId"] = long_uid()
        self.metadata["CreationDate"] = datetime.datetime.now()
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_GrantListEntry.html
        # "If a name was provided in the CreateGrant request, that name is returned. Otherwise this value is null."
        # According to the examples in AWS docs
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_ListGrants.html#API_ListGrants_Examples
        # The Name field is present with just an empty string value.
        self.metadata.setdefault("Name", "")

        # Encode account ID and region in grant token.
        # This way the grant can be located when being retired by grant principal.
        # The token consists of account ID, region name and a UUID concatenated with ':' and encoded with base64
        decoded_token = account_id + ":" + region_name + ":" + long_uid()
        self.token = to_str(base64.b64encode(to_bytes(decoded_token)))


class KmsAlias:
    # Like with grants (see comment for KmsGrant), there is no mention of some specific object modeling metadata
    # for KMS aliases. But there is data that is some metadata, so we model it in a way similar to KeyMetadata for keys.
    metadata: Dict

    def __init__(
        self,
        create_alias_request: CreateAliasRequest = None,
        account_id: str = None,
        region: str = None,
    ):
        create_alias_request = create_alias_request or CreateAliasRequest()
        self.metadata = {}
        self.metadata["AliasName"] = create_alias_request.get("AliasName")
        self.metadata["TargetKeyId"] = create_alias_request.get("TargetKeyId")
        self.update_date_of_last_update()
        self.metadata["CreationDate"] = self.metadata["LastUpdateDate"]
        self.metadata["AliasArn"] = kms_alias_arn(self.metadata["AliasName"], account_id, region)

    def update_date_of_last_update(self):
        self.metadata["LastUpdateDate"] = datetime.datetime.now()


@dataclass
class KeyImportState:
    key_id: str
    import_token: str
    wrapping_algo: str
    key: KmsKey


class KmsStore(BaseStore):
    # maps key ids to keys
    keys: Dict[str, KmsKey] = LocalAttribute(default=dict)

    # According to AWS documentation on grants https://docs.aws.amazon.com/kms/latest/APIReference/API_RetireGrant.html
    # "Cross-account use: Yes. You can retire a grant on a KMS key in a different AWS account."

    # maps grant ids to grants
    grants: Dict[str, KmsGrant] = LocalAttribute(default=dict)

    # maps from (grant names (used for idempotency), key id) to grant ids
    grant_names: Dict[Tuple[str, str], str] = LocalAttribute(default=dict)

    # maps grant tokens to grant ids
    grant_tokens: Dict[str, str] = LocalAttribute(default=dict)

    # maps key alias names to aliases
    aliases: Dict[str, KmsAlias] = LocalAttribute(default=dict)

    # maps import tokens to import data
    imports: Dict[str, KeyImportState] = LocalAttribute(default=dict)


kms_stores = AccountRegionBundle("kms", KmsStore)
