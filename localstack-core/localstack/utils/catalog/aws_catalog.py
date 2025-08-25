import logging

from localstack.utils.catalog.common import (
    AwsServiceOperationsSupportInLatest,
    AwsServicesSupportInLatest,
)
from localstack.utils.objects import singleton_factory

LOG = logging.getLogger(__name__)


class AwsServicesCatalog:
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
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportInLatest | AwsServiceOperationsSupportInLatest:
        # TODO: firstly checks if service is supported, after that if operation is supported
        raise NotImplementedError()
