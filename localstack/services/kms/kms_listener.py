import base64
import json
import logging
import time
from typing import Dict, List

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from moto.kms.exceptions import ValidationException
from moto.kms.models import kms_backends

from localstack.services.generic_proxy import ProxyListener, RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import set_response_content
from localstack.utils.common import long_uid, select_attributes, to_str

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

ATTR_KEY_PAIRS = "_key_pairs"


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

    grants = KMSBackend.get().grants

    data[GRANT_ID] = long_uid()
    data[GRANT_TOKENS] = [long_uid()]
    if NAME not in data:
        data[NAME] = ""
    data[CREATION_DATE] = time.time()

    grants[data[GRANT_ID]] = data
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
    verify_key_exists(data[KEY_ID])

    grants = KMSBackend.get().grants

    limit = data.get("Limit", 50)

    if "Marker" in data:
        markers = KMSBackend.get().markers
        filtered = markers.get(data["Marker"], [])
    else:
        filtered = [
            grant
            for grant in grants.values()
            if grant[KEY_ID] == data[KEY_ID]
            and filter_grant_id(grant, data)
            and filter_grantee_principal(grant, data)
        ]
    if len(filtered) <= limit:
        return {"Grants": filtered, "Truncated": False}

    markers = KMSBackend.get().markers

    in_limit = filtered[:limit]
    out_limit = filtered[limit:]

    marker_id = long_uid()
    markers[marker_id] = out_limit

    return {"Grants": in_limit, "Truncated": True, "NextMarker": marker_id}


def handle_retire_grant(data):
    grants = KMSBackend.get().grants

    if GRANT_ID in data and KEY_ID in data and grants[data[GRANT_ID]][KEY_ID] == data[KEY_ID]:
        del grants[data[GRANT_ID]]
    elif "GrantToken" in data:
        KMSBackend.get().grants = {
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

    grants = KMSBackend.get().grants

    limit = data.get("Limit", 50)

    if "Marker" in data:
        markers = KMSBackend.get().markers
        filtered = markers.get(data["Marker"], [])
    else:
        filtered = [
            grant
            for grant in grants.values()
            if RETIRING_PRINCIPAL in grant and grant[RETIRING_PRINCIPAL] == data[RETIRING_PRINCIPAL]
        ]
    if len(filtered) <= limit:
        return {"Grants": filtered, "Truncated": False}

    markers = KMSBackend.get().markers

    in_limit = filtered[:limit]
    out_limit = filtered[limit:]

    marker_id = long_uid()
    markers[marker_id] = out_limit

    return {"Grants": in_limit, "Truncated": True, "NextMarker": marker_id}


def handle_get_public_key(data, response):
    key_pairs = _get_key_pairs()
    result = key_pairs.get(data.get("KeyId", ""))
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


def _generate_data_key_pair(data):
    key_id = data.get("KeyId")
    rsa_key_sizes = {
        "RSA_2048": 2048,
        "RSA_3072": 3072,
        "RSA_4096": 4096,
    }
    key_spec = data["KeyPairSpec"]
    key_size = rsa_key_sizes.get(key_spec)
    if not key_size:
        # TODO: support other crypto/keypair types!
        LOG.warning("Unsupported KeyPairSpec specified to generate key pair: '%s'", key_spec)
        key_size = 2048
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_key = key.private_bytes(
        crypto_serialization.Encoding.DER,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption(),
    )
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.DER, crypto_serialization.PublicFormat.PKCS1
    )
    kms = aws_stack.connect_to_service("kms")
    cipher_text = kms.encrypt(KeyId=key_id, Plaintext=private_key)["CiphertextBlob"]
    result = {
        "PrivateKeyCiphertextBlob": base64.b64encode(cipher_text),
        "PrivateKeyPlaintext": base64.b64encode(private_key),
        "PublicKey": base64.b64encode(public_key),
        "KeyId": key_id,
        "KeyPairSpec": data.get("KeyPairSpec"),
    }
    key_pairs = _get_key_pairs()
    key_pairs[key_id] = result
    return result


def _get_key_pairs():
    region_name = aws_stack.get_region()
    backend = kms_backends.get(region_name)
    key_pairs = getattr(backend, ATTR_KEY_PAIRS, {})
    setattr(backend, ATTR_KEY_PAIRS, key_pairs)
    return key_pairs


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


class KMSBackend(RegionBackend):
    # maps grant ID to grant details
    grants: Dict[str, Dict]
    # maps pagination markers to result lists
    markers: Dict[str, List]

    def __init__(self):
        self.grants = {}
        self.markers = {}


# instantiate listener
UPDATE_KMS = ProxyListenerKMS()
