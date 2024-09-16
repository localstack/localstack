from abc import ABC

from localstack.aws.api.support import SupportApi


class SupportProvider(SupportApi, ABC):
    pass
