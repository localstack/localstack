import logging

from localstack.aws.api.ram import RamApi
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class RamProvider(RamApi, ServiceLifecycleHook):
    pass
