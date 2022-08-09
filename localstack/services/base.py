from typing import Optional

from moto.backends import get_backend as moto_get_backend
from moto.core.utils import BackendDict

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import RequestContext
from localstack.datatypes import BaseBackendType, BaseStoreType
from localstack.services.stores import STORES_DIRECTORY, AccountRegionBundle
from localstack.utils.aws import aws_stack


class BaseProvider:
    """
    Base class which adds glue between providers and backends/stores.
    """

    service: str

    @staticmethod
    def account_id_from_ctx(context: Optional[RequestContext]) -> str:
        """Extract account ID from RequestContext if available, else retrieve from global context."""
        if context:
            return context.account_id
        return get_aws_account_id()

    @staticmethod
    def region_name_from_ctx(context: Optional[RequestContext]) -> str:
        """Extract region name from RequestContext if available, else retrieve from global context."""
        if context:
            return context.region
        return aws_stack.get_region()

    @classmethod
    def get_store(cls, context: RequestContext = None) -> BaseStoreType:
        """Get the Store for current context account ID and region."""
        account_id = cls.account_id_from_ctx(context)
        region_name = cls.region_name_from_ctx(context)

        if store := cls.get_account_region_bundle()[account_id][region_name]:
            return store

        raise RuntimeError(f"Store not found store directory: {cls.service}")

    @classmethod
    def get_backend(cls, context: RequestContext = None) -> BaseBackendType:
        """Get the Moto Backend for current context account ID and region."""
        account_id = cls.account_id_from_ctx(context)
        region_name = cls.region_name_from_ctx(context)

        return cls.get_backend()[account_id][region_name]

    @classmethod
    def get_backend_dict(cls) -> Optional[BackendDict]:
        """Get the entire BackendDict for a service, if it exists."""
        return moto_get_backend(cls.service)

    @classmethod
    def get_account_region_bundle(cls) -> Optional[AccountRegionBundle]:
        """Get the entire AccountRegionBundle for a service, if it exists."""
        return STORES_DIRECTORY.get(cls.service)
