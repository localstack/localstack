import json
import logging

from localstack.services.generic_proxy import ProxyListener
from localstack.utils.analytics import event_publisher
from localstack.utils.common import to_str

LOG = logging.getLogger(__name__)

# event types
EVENT_KMS_CREATE_KEY = "kms.ck"


class ProxyListenerKMS(ProxyListener):
    def forward_request(self, method, path, data, headers):
        action = headers.get("X-Amz-Target") or ""
        if action.endswith(".CreateKey"):
            data1 = json.loads(to_str(data))
            descr = data1.get("Description") or ""
            event_publisher.fire_event(EVENT_KMS_CREATE_KEY, {"k": event_publisher.get_hash(descr)})
        return True


# instantiate listener
UPDATE_KMS = ProxyListenerKMS()
