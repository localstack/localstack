"""
Base class and utilities for provider stores.

These are analoguos to Moto's BackendDict and provide storage for AWS service providers.

By convention, Stores are to be defined in `models` submodule of the service
by subclassing BaseStore e.g. `localstack.services.sqs.models.SqsStore`
Also by convention, cross-region attributes are declared in CAPITAL_CASE

    class SqsStore(BaseStore):
        queues: Dict[str, SqsQueue]
        DELETED: CrossRegionAttribute(default=dict)  # type: Dict[str, float]

        def __init__(self):
            self.queues = {}

Stores are then wrapped in AccountRegionStore and declared as a singleton

    sqs_stores = AccountRegionStore('sqs', SqsStore)

Access patterns are as follows

    account_id = '001122334455'
    sqs_stores[account_id]  # -> RegionStore
    sqs_stores[account_id]['ap-south-1']  # -> SqsStore
    sqs_stores[account_id]['ap-south-1'].queues  # -> {}
"""

import re
from collections.abc import Callable
from typing import Any, Type, TypeVar, Union

from boto3 import Session

BaseStoreType = TypeVar("BaseStoreType", bound="BaseStore")


class CrossRegionAttribute:
    """
    Descriptor protocol for marking attributes in stores as shared across all regions.

    It makes use of the `_global` dict in RegionStore where all cross-region data
    is stored.
    """

    def __init__(self, default: Union[Callable, int, float, str, bool, None]):
        """
        :param default: The default value assigned to the cross-region attribute.
            This must be a scalar or a callable otherwise.
        """
        self.default = default

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, obj: "BaseStore", objtype=None) -> Any:
        self._check_region_store_association(obj)

        if self.name not in obj._global.keys():
            if isinstance(self.default, Callable):
                obj._global[self.name] = self.default()
            else:
                obj._global[self.name] = self.default

        return obj._global[self.name]

    def __set__(self, obj: "BaseStore", value: Any):
        self._check_region_store_association(obj)

        obj._global[self.name] = value

    def _check_region_store_association(self, obj):
        if not hasattr(obj, "_global"):
            # Raise if a Store is instantiated outside of a RegionStore
            raise AttributeError(
                "Could not resolve cross-region attribute because there is no associated RegionStore"
            )


class BaseStore:
    """
    Base class for defining stores for LocalStack providers.
    """

    def __repr__(self):
        try:
            repr_templ = "<{name} object for {service_name} at {account_id}/{region_name}>"
            return repr_templ.format(
                name=self.__class__.__name__,
                service_name=self._service_name,
                account_id=self._account_id,
                region_name=self._region_name,
            )
        except AttributeError:
            return super().__repr__()


class RegionStore(dict):
    """
    Encapsulation for stores across all regions for a specific AWS account ID.
    """

    def __init__(
        self, service_name: str, store: Type[BaseStoreType], account_id: str, validate: bool = True
    ):
        self.store = store
        self.account_id = account_id
        self.service_name = service_name
        self.validate = validate

        self.valid_regions = Session().get_available_regions(service_name)

        # Keeps track of all cross-region attributes
        self._global = {}

    def __getitem__(self, region_name) -> BaseStoreType:
        if region_name in self.keys():
            return super().__getitem__(region_name)

        if self.validate and region_name not in self.valid_regions:
            # Tip: Try using a valid region or valid service name
            raise ValueError(
                f"'{region_name}' is not a valid AWS region name for {self.service_name}"
            )

        store_obj = self.store()

        store_obj._global = self._global
        store_obj._service_name = self.service_name
        store_obj._account_id = self.account_id
        store_obj._region_name = region_name

        self[region_name] = store_obj

        return super().__getitem__(region_name)


class AccountRegionStore(dict):
    """
    Encapsulation for all stores for all AWS account IDs.
    """

    def __init__(self, service_name: str, store: Type[BaseStoreType], validate: bool = True):
        """
        :param service_name: Name of the service
        :param store: Class definition of the Store
        :param validate: Whether to raise if invalid region names or account IDs are used during subscription
        """
        self.service_name = service_name
        self.store = store
        self.validate = validate

    def __getitem__(self, account_id: str) -> RegionStore:
        if self.validate and not re.match(r"\d{12}", account_id):
            raise ValueError(f"'{account_id}' is not a valid AWS account ID")

        if account_id not in self.keys():
            self[account_id] = RegionStore(
                service_name=self.service_name,
                store=self.store,
                account_id=account_id,
                validate=self.validate,
            )
        return super().__getitem__(account_id)
