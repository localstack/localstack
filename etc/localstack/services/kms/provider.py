import datetime
import logging
import time
from dataclasses import dataclass
from typing import Dict, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from moto.kms.models import Key, kms_backends

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.kms import (
    AlgorithmSpec,
    AliasListEntry,
    CiphertextType,
    CreateGrantRequest,
    CreateGrantResponse,
    CreateKeyRequest,
    CreateKeyResponse,
    DateType,
    DecryptResponse,
    EncryptionAlgorithmSpec,
    EncryptionContextType,
    EncryptResponse,
    ExpirationModelType,
    GenerateDataKeyPairRequest,
    GenerateDataKeyPairResponse,
    GenerateDataKeyPairWithoutPlaintextRequest,
    GenerateDataKeyPairWithoutPlaintextResponse,
    GetParametersForImportResponse,
    GetPublicKeyResponse,
    GrantIdType,
    GrantTokenList,
    GrantTokenType,
    ImportKeyMaterialResponse,
    InvalidGrantTokenException,
    KeyIdType,
    KmsApi,
    KMSInvalidStateException,
    LimitType,
    ListAliasesResponse,
    ListGrantsRequest,
    ListGrantsResponse,
    MarkerType,
    MessageType,
    NotFoundException,
    PlaintextType,
    PrincipalIdType,
    SigningAlgorithmSpec,
    SignResponse,
    WrappingKeySpec,
)
from localstack.services.generic_proxy import RegionBackend
from localstack.services.moto import call_moto
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import kms_alias_arn
from localstack.utils.collections import PaginatedList, remove_attributes
from localstack.utils.common import select_attributes
from localstack.utils.crypto import decrypt, encrypt
from localstack.utils.strings import long_uid, short_uid, to_bytes, to_str

LOG = logging.getLogger(__name__)

# event types
EVENT_KMS_CREATE_KEY = "kms.ck"

# valid operations
VALID_OPERATIONS = [
    "Decrypt",
    "Encrypt",
    "GenerateDataKey",
    "GenerateDataKeyWithoutPlaintext",
    "ReEncryptFrom",
    "ReEncryptTo",
    "Sign",
    "Verify",
    "GetPublicKey",
    "CreateGrant",
    "RetireGrant",
    "DescribeKey",
    "GenerateDataKeyPair",
    "GenerateDataKeyPairWithoutPlaintext",
]

# grant attributes
KEY_ID = "KeyId"
GRANTEE_PRINCIPAL = "GranteePrincipal"
RETIRING_PRINCIPAL = "RetiringPrincipal"
OPERATIONS = "Operations"
GRANT_ID = "GrantId"
GRANT_TOKENS = "GrantTokens"
NAME = "Name"
CONSTRAINTS = "Constraints"
ISSUING_ACCOUNT = "IssuingAccount"
CREATION_DATE = "CreationDate"


@dataclass
class KeyImportState:
    key_id: str
    import_token: str
    wrapping_algo: str
    public_key: bytes
    private_key: bytes
    key_obj: RSAPrivateKey


class KMSBackend(RegionBackend):
    # maps grant ID to grant details
    grants: Dict[str, Dict]
    # maps pagination markers to result lists
    markers: Dict[str, List]
    # maps key ID to keypair details
    key_pairs: Dict[str, Dict]
    # maps import tokens to import states
    imports: Dict[str, KeyImportState]

    def __init__(self):
        self.grants = {}
        self.markers = {}
        self.key_pairs = {}
        self.imports = {}


class ValidationError(CommonServiceException):
    """General validation error type (defined in the AWS docs, but not part of the botocore spec)"""

    def __init__(self, message=None):
        super().__init__("ValidationError", message=message)


class KmsProvider(KmsApi):
    @handler("CreateKey", expand=False)
    def create_key(
        self,
        context: RequestContext,
        create_key_request: CreateKeyRequest = None,
    ) -> CreateKeyResponse:
        descr = create_key_request.get("Description") or ""
        event_publisher.fire_event(EVENT_KMS_CREATE_KEY, {"k": event_publisher.get_hash(descr)})
        result = call_moto(context)

        # generate keypair for signing, if this is a SIGN_VERIFY key
        key_usage = create_key_request.get("KeyUsage")
        if key_usage == "SIGN_VERIFY":
            create_key_request["KeyId"] = result["KeyMetadata"]["KeyId"]
            _generate_data_key_pair(create_key_request, create_cipher=False)

        return result

    @handler("CreateGrant", expand=False)
    def create_grant(
        self, context: RequestContext, create_grant_request: CreateGrantRequest
    ) -> CreateGrantResponse:
        self._validate_grant(create_grant_request)
        region_details = KMSBackend.get()

        grant = dict(create_grant_request)
        grant[GRANT_ID] = long_uid()
        grant[GRANT_TOKENS] = [long_uid()]
        if NAME not in grant:
            grant[NAME] = ""
        grant[CREATION_DATE] = time.time()

        region_details.grants[grant[GRANT_ID]] = grant
        return CreateGrantResponse(GrantId=grant[GRANT_ID], GrantToken=grant[GRANT_TOKENS][0])

    @handler("ListGrants", expand=False)
    def list_grants(
        self, context: RequestContext, list_grants_request: ListGrantsRequest
    ) -> ListGrantsResponse:
        key_id = list_grants_request.get(KEY_ID)
        if not key_id:
            raise ValidationError(f"Required input parameter '{KEY_ID}' not specified")
        region_details = KMSBackend.get()
        self._verify_key_exists(key_id)

        limit = list_grants_request.get("Limit", 50)

        if "Marker" in list_grants_request:
            filtered = region_details.markers.get(list_grants_request["Marker"], [])
        else:
            filtered = [
                grant
                for grant in region_details.grants.values()
                if grant[KEY_ID] == key_id
                and filter_grant_id(grant, list_grants_request)
                and filter_grantee_principal(grant, list_grants_request)
            ]

        # filter out attributes
        filtered = [remove_attributes(dict(grant), ["GrantTokens"]) for grant in filtered]

        if len(filtered) <= limit:
            return ListGrantsResponse(Grants=filtered, Truncated=False)

        in_limit = filtered[:limit]
        out_limit = filtered[limit:]

        marker_id = long_uid()
        region_details.markers[marker_id] = out_limit

        return ListGrantsResponse(Grants=in_limit, Truncated=True, NextMarker=marker_id)

    def revoke_grant(
        self, context: RequestContext, key_id: KeyIdType, grant_id: GrantIdType
    ) -> None:
        grants = KMSBackend.get().grants
        if grants[grant_id][KEY_ID] != key_id:
            raise ValidationError(f"Invalid {KEY_ID}={key_id} specified for grant {grant_id}")
        grants.pop(grant_id)

    def retire_grant(
        self,
        context: RequestContext,
        grant_token: GrantTokenType = None,
        key_id: KeyIdType = None,
        grant_id: GrantIdType = None,
    ) -> None:
        region_details = KMSBackend.get()
        grants = region_details.grants

        if grant_id and grants[grant_id][KEY_ID] == key_id:
            grants.pop(grant_id)
        elif grant_token:
            region_details.grants = {
                grant_id: grant
                for grant_id, grant in grants.items()
                if grant_token not in grant[GRANT_TOKENS]
            }
        else:
            raise InvalidGrantTokenException("Grant token OR (grant ID, key ID) must be specified")

    def list_retirable_grants(
        self,
        context: RequestContext,
        retiring_principal: PrincipalIdType,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListGrantsResponse:
        region_details = KMSBackend.get()
        grants = region_details.grants

        if not retiring_principal:
            raise ValidationError(f"Required input parameter '{RETIRING_PRINCIPAL}' not specified")

        limit = limit or 50

        if marker:
            markers = region_details.markers
            filtered = markers.get(marker, [])
        else:
            filtered = [
                grant
                for grant in grants.values()
                if RETIRING_PRINCIPAL in grant and grant[RETIRING_PRINCIPAL] == retiring_principal
            ]
        if len(filtered) <= limit:
            return ListGrantsResponse(Grants=filtered, Truncated=False)

        markers = region_details.markers

        in_limit = filtered[:limit]
        out_limit = filtered[limit:]

        marker_id = long_uid()
        markers[marker_id] = out_limit

        return ListGrantsResponse(Grants=in_limit, Truncated=True, NextMarker=marker_id)

    def get_public_key(
        self, context: RequestContext, key_id: KeyIdType, grant_tokens: GrantTokenList = None
    ) -> GetPublicKeyResponse:
        region_details = KMSBackend.get()
        result = region_details.key_pairs.get(key_id)
        if not result:
            raise NotFoundException()
        attrs = [
            "KeyId",
            "PublicKey",
            "KeySpec",
            "KeyUsage",
            "EncryptionAlgorithms",
            "SigningAlgorithms",
        ]
        result = select_attributes(result, attrs)
        return GetPublicKeyResponse(**result)

    @handler("GenerateDataKeyPair", expand=False)
    def generate_data_key_pair(
        self,
        context: RequestContext,
        generate_data_key_pair_request: GenerateDataKeyPairRequest,
    ) -> GenerateDataKeyPairResponse:
        result = _generate_data_key_pair(generate_data_key_pair_request)
        attrs = [
            "PrivateKeyCiphertextBlob",
            "PrivateKeyPlaintext",
            "PublicKey",
            "KeyId",
            "KeyPairSpec",
        ]
        result = select_attributes(result, attrs)
        return GenerateDataKeyPairResponse(**result)

    @handler("GenerateDataKeyPairWithoutPlaintext", expand=False)
    def generate_data_key_pair_without_plaintext(
        self,
        context: RequestContext,
        generate_data_key_pair_without_plaintext_request: GenerateDataKeyPairWithoutPlaintextRequest,
    ) -> GenerateDataKeyPairWithoutPlaintextResponse:
        result = _generate_data_key_pair(generate_data_key_pair_without_plaintext_request)
        result = select_attributes(
            result, ["PrivateKeyCiphertextBlob", "PublicKey", "KeyId", "KeyPairSpec"]
        )
        return GenerateDataKeyPairResponse(**result)

    def sign(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        message: PlaintextType,
        signing_algorithm: SigningAlgorithmSpec,
        message_type: MessageType = None,
        grant_tokens: GrantTokenList = None,
    ) -> SignResponse:
        region_details = KMSBackend.get()

        key_pair = region_details.key_pairs.get(key_id)
        if not key_pair:
            raise NotFoundException(f"Key ID {key_id} not found for signing")

        kwargs = {}
        if signing_algorithm.startswith("RSA"):
            if "PKCS" in signing_algorithm:
                kwargs["padding"] = padding.PKCS1v15()
            elif "PSS" in signing_algorithm:
                kwargs["padding"] = padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                )
            else:
                LOG.warning("Unsupported padding in SigningAlgorithm '%s'", signing_algorithm)

        if "SHA_256" in signing_algorithm:
            kwargs["algorithm"] = hashes.SHA256()
        elif "SHA_384" in signing_algorithm:
            kwargs["algorithm"] = hashes.SHA384()
        elif "SHA_512" in signing_algorithm:
            kwargs["algorithm"] = hashes.SHA512()
        else:
            LOG.warning("Unsupported hash type in SigningAlgorithm '%s'", signing_algorithm)
        if signing_algorithm.startswith("ECDSA"):
            kwargs["signature_algorithm"] = ec.ECDSA(algorithm=kwargs.pop("algorithm", None))

        # generate signature
        signature = key_pair["_key_"].sign(data=message, **kwargs)

        result = {
            "KeyId": key_id,
            "Signature": signature,
            "SigningAlgorithm": signing_algorithm,
        }
        return SignResponse(**result)

    def encrypt(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        plaintext: PlaintextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
    ) -> EncryptResponse:
        # check if we have imported custom key material for this key
        matching = [key for key in KMSBackend.get().imports.values() if key.key_id == key_id]
        if not matching:
            return call_moto(context)

        key_obj = kms_backends[context.region].keys.get(key_id)
        ciphertext_blob = encrypt(key_obj.key_material, plaintext)
        return EncryptResponse(
            CiphertextBlob=ciphertext_blob, KeyId=key_id, EncryptionAlgorithm=encryption_algorithm
        )

    def decrypt(
        self,
        context: RequestContext,
        ciphertext_blob: CiphertextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        key_id: KeyIdType = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
    ) -> DecryptResponse:
        # check if we have imported custom key material for this key
        matching = [key for key in KMSBackend.get().imports.values() if key.key_id == key_id]
        if not matching:
            return call_moto(context)

        key_obj = kms_backends[context.region].keys.get(key_id)
        plaintext = decrypt(key_obj.key_material, ciphertext_blob)
        return DecryptResponse(
            KeyId=key_id, Plaintext=plaintext, EncryptionAlgorithm=encryption_algorithm
        )

    def get_parameters_for_import(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        wrapping_algorithm: AlgorithmSpec,
        wrapping_key_spec: WrappingKeySpec,
    ) -> GetParametersForImportResponse:
        key = _generate_data_key_pair(
            {"KeySpec": wrapping_key_spec}, create_cipher=False, add_to_keys=False
        )
        import_token = short_uid()
        import_state = KeyImportState(
            key_id=key_id,
            import_token=import_token,
            private_key=key["PrivateKeyPlaintext"],
            public_key=key["PublicKey"],
            wrapping_algo=wrapping_algorithm,
            key_obj=key["_key_"],
        )
        KMSBackend.get().imports[import_token] = import_state
        expiry_date = datetime.datetime.now() + datetime.timedelta(days=100)
        return GetParametersForImportResponse(
            KeyId=key_id,
            ImportToken=to_bytes(import_state.import_token),
            PublicKey=import_state.public_key,
            ParametersValidTo=expiry_date,
        )

    def import_key_material(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        import_token: CiphertextType,
        encrypted_key_material: CiphertextType,
        valid_to: DateType = None,
        expiration_model: ExpirationModelType = None,
    ) -> ImportKeyMaterialResponse:
        import_token = to_str(import_token)
        import_state = KMSBackend.get().imports.get(import_token)
        if not import_state:
            raise NotFoundException(f"Unable to find key import token '{import_token}'")
        key_obj = kms_backends[context.region].keys.get(key_id)
        if not key_obj:
            raise NotFoundException(f"Unable to find key '{key_id}'")

        if import_state.wrapping_algo == AlgorithmSpec.RSAES_PKCS1_V1_5:
            decrypt_padding = padding.PKCS1v15()
        elif import_state.wrapping_algo == AlgorithmSpec.RSAES_OAEP_SHA_1:
            decrypt_padding = padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)
        elif import_state.wrapping_algo == AlgorithmSpec.RSAES_OAEP_SHA_256:
            decrypt_padding = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
        else:
            raise KMSInvalidStateException(
                f"Unsupported padding, requested wrapping algorithm:'{import_state.wrapping_algo}'"
            )

        key_material = import_state.key_obj.decrypt(encrypted_key_material, decrypt_padding)
        key_obj.key_material = key_material
        return ImportKeyMaterialResponse()

    def list_aliases(
        self,
        context: RequestContext,
        key_id: KeyIdType = None,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListAliasesResponse:
        if key_id is None:
            return call_moto(context)

        response_aliases = PaginatedList()

        if kms_backends.get(context.region).keys.get(key_id) is None:
            raise NotFoundException(f"Unable to find key '{key_id}'")

        aliases_of_key = kms_backends.get(context.region).get_all_aliases().get(key_id) or []

        for alias_name in aliases_of_key:
            response_aliases.append(
                AliasListEntry(
                    AliasArn=kms_alias_arn(alias_name, region_name=context.region),
                    AliasName=alias_name,
                    TargetKeyId=key_id,
                )
            )

        page, nxt = response_aliases.get_page(
            lambda a: a["AliasName"], next_token=marker, page_size=limit
        )

        return ListAliasesResponse(Aliases=page, NextMarker=nxt, Truncated=nxt is not None)

    def _verify_key_exists(self, key_id):
        try:
            kms_backends[aws_stack.get_region()].describe_key(key_id)
        except Exception:
            raise ValidationError(f"Invalid key ID '{key_id}'")

    def _validate_grant(self, data: Dict):
        if KEY_ID not in data or GRANTEE_PRINCIPAL not in data or OPERATIONS not in data:
            raise ValidationError("Grant ID, key ID and grantee principal must be specified")

        for operation in data[OPERATIONS]:
            if operation not in VALID_OPERATIONS:
                raise ValidationError(
                    f"Value {[OPERATIONS]} at 'operations' failed to satisfy constraint: Member must satisfy"
                    f" constraint: [Member must satisfy enum value set: {VALID_OPERATIONS}]"
                )

        self._verify_key_exists(data[KEY_ID])


# ---------------
# UTIL FUNCTIONS
# ---------------


def _generate_data_key_pair(data, create_cipher=True, add_to_keys=True):
    region_details = KMSBackend.get()
    kms = aws_stack.connect_to_service("kms")

    key_id = data.get("KeyId")
    key_spec = data.get("KeyPairSpec") or data.get("KeySpec") or data.get("CustomerMasterKeySpec")
    key = None
    public_format = None
    if key_spec.startswith("RSA"):
        rsa_key_sizes = {
            "RSA_2048": 2048,
            "RSA_3072": 3072,
            "RSA_4096": 4096,
        }
        key_size = rsa_key_sizes.get(key_spec)
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_format = crypto_serialization.PublicFormat.PKCS1
    if key_spec.startswith("ECC"):
        curve = None
        if key_spec == "ECC_NIST_P256":
            curve = ec.SECP256R1()
        elif key_spec == "ECC_NIST_P384":
            curve = ec.SECP384R1()
        elif key_spec == "ECC_NIST_P521":
            curve = ec.SECP521R1()
        elif key_spec == "ECC_SECG_P256K1":
            curve = ec.SECP256K1()
        key = ec.generate_private_key(curve)
        public_format = crypto_serialization.PublicFormat.SubjectPublicKeyInfo

    private_key = key.private_bytes(
        crypto_serialization.Encoding.DER,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption(),
    )
    public_key = key.public_key().public_bytes(crypto_serialization.Encoding.DER, public_format)
    cipher_text = None
    if create_cipher:
        cipher_text = kms.encrypt(KeyId=key_id, Plaintext=private_key)["CiphertextBlob"]

    region = region_details.get_current_request_region()
    result = {
        "PrivateKeyCiphertextBlob": cipher_text,
        "PrivateKeyPlaintext": private_key,
        "PublicKey": public_key,
        "KeyId": key_id,
        "KeyPairSpec": key_spec,
        "KeySpec": key_spec,
        "KeyUsage": "SIGN_VERIFY",
        "Policy": data.get("Policy"),
        "Region": region,
        "Description": data.get("Description"),
        "Arn": key_id and aws_stack.kms_key_arn(key_id),
        "_key_": key,
    }

    if add_to_keys:
        region_details.key_pairs[key_id] = result

    key = Key("", result["KeyUsage"], key_spec, result["Description"], region)
    key.id = key_id

    result = {**key.to_dict()["KeyMetadata"], **result}
    result.pop("Region")
    if add_to_keys:
        result.pop("_key_")

    return result


def filter_if_present(grant, data, filter_key):
    return filter_key not in data or grant[filter_key] == data[filter_key]


def filter_grantee_principal(grant, data):
    return filter_if_present(grant, data, GRANTEE_PRINCIPAL)


def filter_grant_id(grant, data):
    return filter_if_present(grant, data, GRANT_ID)


def set_key_managed(key_id: str) -> None:
    """
    Sets a KMS key to AWS managed
    :param key_id: ID of the KMS key
    """
    region_name = aws_stack.get_region()
    backend = kms_backends.get(region_name)
    key_data = backend.keys.get(key_id)
    if key_data:
        key_data.key_manager = "AWS"
