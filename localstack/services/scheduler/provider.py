import logging

from localstack_ext.aws.api.scheduler import SchedulerApi

from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class SchedulerProvider(SchedulerApi, ServiceLifecycleHook):
    pass
