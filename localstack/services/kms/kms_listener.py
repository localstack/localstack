import json
import logging

from localstack.services.generic_proxy import ProxyListener, RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.common import to_str, short_uid, long_uid
from requests.models import Response
from localstack.constants import APPLICATION_JSON

LOG = logging.getLogger(__name__)

# event types
EVENT_KMS_CREATE_KEY = "kms.ck"


def validate_grant(data):
    # TODO required fields (keyid, grantee-principal, operations)
    # TODO kms key exists
    # TODO grantee principal is ARN for principal (possible?)
    # TODO Operations are the proper list
    # TODO retiring principal is ARN for principal (possible?)
    return True


def handle_create_grant(data):
    if not validate_grant(data):
        return False

    grants = KMSBackend.get().grants

    data["GrantId"] = long_uid()
    data["GrantToken"] = long_uid()

    grants[data["GrantId"]] = data
    return {"GrantId": data["GrantId"], "GrantToken": data["GrantToken"]}


def filter_if_present(grant, data, filter_key):
    return filter_key not in data or grant[filter_key] == data[filter_key]


def filter_grantee_principal(grant, data):
    return filter_if_present(grant, data, "GranteePrincipal")


def filter_grant_id(grant, data):
    return filter_if_present(grant, data, "GrantId")


def handle_list_grants(data):
    if "KeyId" not in data:
        return False

    grants = KMSBackend.get().grants

    limit = data.get("Limit", 50)

    # TODO marker

    # TODO use limit
    filtered = [grant for grant in grants.values() if
                grant["KeyId"] == data["KeyId"] and
                filter_grant_id(grant, data) and
                filter_grantee_principal(grant, data)
                ]

    if len(filtered) == 0:
        return False

    # TODO add NextMarker for when truncated
    return {"Grants": filtered, "Truncated": False}


def handle_retire_grant(data):
    grants = KMSBackend.get().grants

    if "GrantId" in data and "KeyId" in data and grants[data["GrantId"]]["KeyId"] == data["KeyId"]:
        del grants[data["GrantId"]]
    elif "GrantToken" in data:
        KMSBackend.get().grants = {grant_id: grant for grant_id, grant in grants.items() if
                                   data["GrantToken"] != grant["GrantToken"]}
    else:
        return False
    return True


def handle_revoke_grant(data):
    grants = KMSBackend.get().grants

    if "GrantId" in data and "KeyId" in data and grants[data["GrantId"]]["KeyId"] == data["KeyId"]:
        del grants[data["GrantId"]]
        return True
    else:
        return False


def handle_list_retirable_grants(data):
    if "RetiringPrincipal" not in data:
        return False

    grants = KMSBackend.get().grants

    limit = data.get("Limit", 50)

    # TODO marker

    # TODO use limit
    filtered = [grant for grant in grants.values() if
                "RetiringPrincipal" in grant and grant["RetiringPrincipal"] == data["RetiringPrincipal"]
                ]

    if len(filtered) == 0:
        return False

    # TODO add NextMarker for when truncated
    return {"Grants": filtered, "Truncated": False}



class ProxyListenerKMS(ProxyListener):
    def forward_request(self, method, path, data, headers):
        action = headers.get("X-Amz-Target") or ""
        if method == "POST" and path == "/":
            parsed_data = json.loads(to_str(data))

            if action.endswith(".CreateKey"):
                descr = parsed_data.get("Description") or ""
                event_publisher.fire_event(EVENT_KMS_CREATE_KEY, {"k": event_publisher.get_hash(descr)})
            elif action.endswith(".CreateGrant"):
                return handle_create_grant(parsed_data)
            elif action.endswith(".ListGrants"):
                return handle_list_grants(parsed_data)
            elif action.endswith(".RevokeGrant"):
                return handle_revoke_grant(parsed_data)
            elif action.endswith(".RetireGrant"):
                return handle_retire_grant(parsed_data)
            elif action.endswith(".ListRetirableGrants"):
                return handle_list_retirable_grants(parsed_data)
        return True


class KMSBackend(RegionBackend):
    def __init__(self):
        self.grants = {}


# instantiate listener
UPDATE_KMS = ProxyListenerKMS()
