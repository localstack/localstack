import logging

from localstack.utils.catalog.common import FeatureSupportInLatestVersion
from localstack.utils.objects import singleton_factory

LOG = logging.getLogger(__name__)


class AwsServicesCatalog:
    # Build catalog in constructor
    # def __init__(self):
    #     catalog = self._build_catalog()

    @staticmethod
    @singleton_factory
    def get() -> "AwsServicesCatalog":
        return AwsServicesCatalog()

    @staticmethod
    def _load_catalog_data():
        raise NotImplementedError()

    @staticmethod
    def _build_catalog() -> dict[str, dict[str, dict]]:
        raise NotImplementedError()

    def get_support_status(
        self, service_name: str, operation_name: str
    ) -> FeatureSupportInLatestVersion:
        raise NotImplementedError()
