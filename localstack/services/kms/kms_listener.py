import base64
import json
import logging
import time
from typing import Dict, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from moto.kms.exceptions import ValidationException
from moto.kms.models import Key, kms_backends

from localstack.services.generic_proxy import ProxyListener, RegionBackend
from localstack.services.kms.kms_starter import KMS_PROVIDER
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import set_response_content
from localstack.utils.common import json_safe, long_uid, select_attributes, to_bytes, to_str

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


class KMSBackend(RegionBackend):
    # maps grant ID to grant details
    grants: Dict[str, Dict]
    # maps pagination markers to result lists
    markers: Dict[str, List]
    # maps key ID to keypair details
    key_pairs: Dict

    def __init__(self):
        self.grants = {}
        self.markers = {}
        self.key_pairs = {}


def verify_key_exists(key_id):
    try:
        aws_stack.connect_to_service("kms").describe_key(KeyId=key_id)
    # FIXME catch the proper exception
    except Exception:
        raise ValidationException(f"Invalid keyId {key_id}")


def validate_grant(data):
    if KEY_ID not in data or GRANTEE_PRINCIPAL not in data or OPERATIONS not in data:
        raise ValidationException("Grant ID, key ID and grantee principal must be specified")

    for operation in data[OPERATIONS]:
        if operation not in VALID_OPERATIONS:
            raise ValidationException(
                f"Value {[OPERATIONS]} at 'operations' failed to satisfy constraint: Member must satisfy"
                f" constraint: [Member must satisfy enum value set: {VALID_OPERATIONS}]"
            )

    verify_key_exists(data[KEY_ID])


def handle_create_grant(data):
    validate_grant(data)
    region_details = KMSBackend.get()

    data[GRANT_ID] = long_uid()
    data[GRANT_TOKENS] = [long_uid()]
    if NAME not in data:
        data[NAME] = ""
    data[CREATION_DATE] = time.time()

    region_details.grants[data[GRANT_ID]] = data
    return {GRANT_ID: data[GRANT_ID], "GrantToken": data[GRANT_TOKENS][0]}


def filter_if_present(grant, data, filter_key):
    return filter_key not in data or grant[filter_key] == data[filter_key]


def filter_grantee_principal(grant, data):
    return filter_if_present(grant, data, GRANTEE_PRINCIPAL)


def filter_grant_id(grant, data):
    return filter_if_present(grant, data, GRANT_ID)


def handle_list_grants(data):
    if KEY_ID not in data:
        raise ValidationException("KeyId must be specified")
    region_details = KMSBackend.get()
    verify_key_exists(data[KEY_ID])

    limit = data.get("Limit", 50)

    if "Marker" in data:
        filtered = region_details.markers.get(data["Marker"], [])
    else:
        filtered = [
            grant
            for grant in region_details.grants.values()
            if grant[KEY_ID] == data[KEY_ID]
            and filter_grant_id(grant, data)
            and filter_grantee_principal(grant, data)
        ]
    if len(filtered) <= limit:
        return {"Grants": filtered, "Truncated": False}

    in_limit = filtered[:limit]
    out_limit = filtered[limit:]

    marker_id = long_uid()
    region_details.markers[marker_id] = out_limit

    return {"Grants": in_limit, "Truncated": True, "NextMarker": marker_id}


def handle_retire_grant(data):
    region_details = KMSBackend.get()

    grants = region_details.grants

    if GRANT_ID in data and KEY_ID in data and grants[data[GRANT_ID]][KEY_ID] == data[KEY_ID]:
        del grants[data[GRANT_ID]]
    elif "GrantToken" in data:
        region_details.grants = {
            grant_id: grant
            for grant_id, grant in grants.items()
            if data["GrantToken"] not in grant[GRANT_TOKENS]
        }
    else:
        raise ValidationException("Grant token OR (grant ID, key ID) must be specified")
    return {}


def handle_revoke_grant(data):
    grants = KMSBackend.get().grants

    if GRANT_ID in data and KEY_ID in data and grants[data[GRANT_ID]][KEY_ID] == data[KEY_ID]:
        del grants[data[GRANT_ID]]
        return {}
    else:
        raise ValidationException("Grant ID, key ID must be specified")


def handle_list_retirable_grants(data):
    if RETIRING_PRINCIPAL not in data:
        raise ValidationException("Retiring principal must be specified")

    region_details = KMSBackend.get()
    grants = region_details.grants

    limit = data.get("Limit", 50)

    if "Marker" in data:
        markers = region_details.markers
        filtered = markers.get(data["Marker"], [])
    else:
        filtered = [
            grant
            for grant in grants.values()
            if RETIRING_PRINCIPAL in grant and grant[RETIRING_PRINCIPAL] == data[RETIRING_PRINCIPAL]
        ]
    if len(filtered) <= limit:
        return {"Grants": filtered, "Truncated": False}

    markers = region_details.markers

    in_limit = filtered[:limit]
    out_limit = filtered[limit:]

    marker_id = long_uid()
    markers[marker_id] = out_limit

    return {"Grants": in_limit, "Truncated": True, "NextMarker": marker_id}


def handle_get_public_key(data, response):
    region_details = KMSBackend.get()
    result = region_details.key_pairs.get(data.get("KeyId", ""))
    if not result:
        return 404
    attrs = [
        "KeyId",
        "PublicKey",
        "KeySpec",
        "KeyUsage",
        "EncryptionAlgorithms",
        "SigningAlgorithms",
    ]
    result = select_attributes(result, attrs)
    set_response_content(response, result)
    response.status_code = 200
    return response


def generate_data_key_pair(data, response):
    result = _generate_data_key_pair(data)
    set_response_content(response, result)
    response.status_code = 200
    return response


def generate_data_key_pair_without_plaintext(data, response):
    result = _generate_data_key_pair(data)
    result.pop("PrivateKeyPlaintext", None)
    set_response_content(response, result)
    response.status_code = 200
    return response


def _generate_data_key_pair(data, create_cipher=True):
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
            curve = ec.BrainpoolP256R1()
        elif key_spec == "ECC_NIST_P384":
            curve = ec.BrainpoolP384R1()
        elif key_spec == "ECC_NIST_P521":
            curve = ec.BrainpoolP512R1()
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
    cipher_text_blob = None
    if create_cipher:
        cipher_text = kms.encrypt(KeyId=key_id, Plaintext=private_key)["CiphertextBlob"]
        cipher_text_blob = base64.b64encode(cipher_text)

    region = region_details.get_current_request_region()
    result = {
        "PrivateKeyCiphertextBlob": cipher_text_blob,
        "PrivateKeyPlaintext": base64.b64encode(private_key),
        "PublicKey": base64.b64encode(public_key),
        "KeyId": key_id,
        "KeyPairSpec": key_spec,
        "KeySpec": key_spec,
        "KeyUsage": "SIGN_VERIFY",
        "Policy": data.get("Policy"),
        "Region": region,
        "Description": data.get("Description"),
        "Arn": aws_stack.kms_key_arn(key_id),
        "_key_": key,
    }
    region_details.key_pairs[key_id] = result

    key = Key("", result["KeyUsage"], key_spec, result["Description"], region)
    key.id = key_id

    return {**key.to_dict()["KeyMetadata"], **result}


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


def create_key(data: Dict):
    key_usage = data.get("KeyUsage")
    if key_usage != "SIGN_VERIFY" or KMS_PROVIDER == "local-kms":
        return

    data["KeyId"] = long_uid()
    result = _generate_data_key_pair(data, create_cipher=False)
    result = {"KeyMetadata": json_safe(result)}
    return result


def sign(data, response):
    region_details = KMSBackend.get()
    response.status_code = 200
    algo = data.get("SigningAlgorithm")
    key_id = data.get("KeyId")
    message = base64.b64decode(to_bytes(data.get("Message")))

    key_pair = region_details.key_pairs.get(key_id)
    kwargs = {}
    if algo.startswith("RSA"):
        if "PKCS" in algo:
            kwargs["padding"] = padding.PKCS1v15()
        elif "PSS" in algo:
            kwargs["padding"] = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            )
        else:
            LOG.warning("Unsupported padding in SigningAlgorithm '%s'", algo)

    if "SHA_256" in algo:
        kwargs["algorithm"] = hashes.SHA256()
    elif "SHA_384" in algo:
        kwargs["algorithm"] = hashes.SHA384()
    elif "SHA_512" in algo:
        kwargs["algorithm"] = hashes.SHA512()
    else:
        LOG.warning("Unsupported hash type in SigningAlgorithm '%s'", algo)
    if algo.startswith("ECDSA"):
        kwargs["signature_algorithm"] = ec.ECDSA(algorithm=kwargs.pop("algorithm", None))

    # generate signature
    signature = key_pair["_key_"].sign(data=message, **kwargs)

    result = {
        "KeyId": key_id,
        "Signature": to_str(base64.b64encode(signature)),
        "SigningAlgorithm": algo,
    }
    set_response_content(response, json.dumps(result))
    return response


def search_key_pair(data, response):
    key_pairs = KMSBackend.get().key_pairs
    key = key_pairs.get(data.get("KeyId"))
    if not key:
        return response

    key_object = Key(
        key["Policy"], key["KeyUsage"], key["KeySpec"], key["Description"], key["Region"]
    )
    key_object.id = key["KeyId"]

    response.status_code = 200
    set_response_content(response, json.dumps(key_object.to_dict()))
    return response


def add_key_pairs(response):
    key_pairs = KMSBackend.get().key_pairs
    response.status_code = 200
    content = json.loads(to_str(response.content))
    prev_keys = content["Keys"]

    for id in key_pairs:
        prev_keys.append(
            {
                "KeyId": key_pairs[id]["KeyId"],
                "KeyArn": key_pairs[id]["Arn"],
            }
        )

    content["Keys"] = prev_keys
    set_response_content(response, json.dumps(content))
    return response


class ProxyListenerKMS(ProxyListener):
    def forward_request(self, method, path, data, headers):
        action = headers.get("X-Amz-Target") or ""
        action = action.split(".")[-1]
        if method == "POST" and path == "/":
            parsed_data = json.loads(to_str(data))

            if action == "CreateKey":
                descr = parsed_data.get("Description") or ""
                event_publisher.fire_event(
                    EVENT_KMS_CREATE_KEY, {"k": event_publisher.get_hash(descr)}
                )
                result = create_key(parsed_data)
                if result is not None:
                    return result
            elif action == "CreateGrant":
                return handle_create_grant(parsed_data)
            elif action == "ListGrants":
                return handle_list_grants(parsed_data)
            elif action == "RevokeGrant":
                return handle_revoke_grant(parsed_data)
            elif action == "RetireGrant":
                return handle_retire_grant(parsed_data)
            elif action == "ListRetirableGrants":
                return handle_list_retirable_grants(parsed_data)
        return True

    def return_response(self, method, path, data, headers, response):

        if method == "POST" and path == "/":
            parsed_data = json.loads(to_str(data))
            action = headers.get("X-Amz-Target") or ""
            action = action.split(".")[-1]
            if response.status_code == 501:
                if action == "GetPublicKey":
                    return handle_get_public_key(parsed_data, response)
                if action == "GenerateDataKeyPair":
                    return generate_data_key_pair(parsed_data, response)
                if action == "GenerateDataKeyPairWithoutPlaintext":
                    return generate_data_key_pair_without_plaintext(parsed_data, response)
                if action == "Sign":
                    return sign(parsed_data, response)
            if response.status_code == 400 and action == "DescribeKey":
                return search_key_pair(parsed_data, response)

            if action == "ListKeys":
                add_key_pairs(response)


# instantiate listener
UPDATE_KMS = ProxyListenerKMS()
