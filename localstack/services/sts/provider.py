from localstack.aws.api.sts import StsApi
from localstack.services.plugins import ServiceLifecycleHook


class StsProvider(StsApi, ServiceLifecycleHook):
    pass
