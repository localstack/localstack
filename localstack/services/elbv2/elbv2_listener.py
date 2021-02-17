import re
import logging
from localstack.utils.common import to_str, to_bytes
from localstack.services.generic_proxy import ProxyListener
from moto.elbv2 import urls

LOG = logging.getLogger(__name__)


class ProxyListenerELBV2(ProxyListener):
    pass


# # instantiate listener
UPDATE_ELBV2 = ProxyListenerELBV2()
