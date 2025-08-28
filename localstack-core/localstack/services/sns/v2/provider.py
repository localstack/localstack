# set up logger
import logging

from localstack.aws.api.sns import SnsApi
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class SnsProvider(SnsApi, ServiceLifecycleHook): ...
