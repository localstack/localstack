import logging

from localstack.utils.catalog.common import CloudFormationResourcesSupportInLatest
from localstack.utils.objects import singleton_factory

LOG = logging.getLogger(__name__)


class CloudFormationCatalog:
    @staticmethod
    @singleton_factory
    def get() -> "CloudFormationCatalog":
        return CloudFormationCatalog()

    @staticmethod
    def _load_catalog_data():
        raise NotImplementedError()

    @staticmethod
    def _detect_runtime_resources():
        raise NotImplementedError()

    @staticmethod
    def _build_catalog():
        raise NotImplementedError()

    def get_support_status(
        self, resource_name: str, operation_name: str
    ) -> CloudFormationResourcesSupportInLatest:
        raise NotImplementedError()
