"""
Base class and utilities for provider stores.

Stores provide storage for AWS service providers and are analogous to Moto's BackendDict.

By convention, Stores are to be defined in `models` submodule of the service
by subclassing BaseStore e.g. `localstack.services.sqs.models.SqsStore`
Also by convention, cross-region and cross-account attributes are declared in CAPITAL_CASE

    class SqsStore(BaseStore):
        queues: dict[str, SqsQueue] =  LocalAttribute(default=dict)
        DELETED: dict[str, float] = CrossRegionAttribute(default=dict)

Stores are then wrapped in AccountRegionBundle

    sqs_stores = AccountRegionBundle('sqs', SqsStore)

Access patterns are as follows

    account_id = '001122334455'
    sqs_stores[account_id]  # -> RegionBundle
    sqs_stores[account_id]['ap-south-1']  # -> SqsStore
    sqs_stores[account_id]['ap-south-1'].queues  # -> {}

There should be a single declaration of a Store for a given service. If a service
has both Community and Pro providers, it must be declared as in Community codebase.
All Pro attributes must be declared within.

While not recommended, store classes may define member helper functions and properties.
"""

import re
from threading import RLock
from typing import Type

from localstack import config
from localstack.utils.aws.aws_stack import get_valid_regions_for_service

from localstack_stores.models import CrossAccountAttribute, CrossRegionAttribute, LocalAttribute  # noqa
from localstack_stores.models import BaseStore, BaseStoreType  # noqa
from localstack_stores.models import GenericAccountRegionBundle, GenericRegionBundle


#
# Encapsulations
#


class RegionBundle(GenericRegionBundle):
    """
    Encapsulation for stores across all regions for a specific AWS account ID.
    We're overriding the base-class to implement AWS-specific validation
    """

    def __init__(
        self,
        service_name: str,
        store: Type[BaseStoreType],
        account_id: str,
        validate: bool = True,
        lock: RLock = None,
        universal: dict = None,
    ):
        super().__init__(
            service_name=service_name,
            store=store,
            account_id=account_id,
            lock=lock,
            universal=universal
        )
        self.validate = validate
        self.valid_regions = get_valid_regions_for_service(service_name)

    def validate_item(self, region_name: str) -> None:
        if (
            not config.ALLOW_NONSTANDARD_REGIONS
            and self.validate
            and region_name not in self.valid_regions
        ):
            raise ValueError(
                f"'{region_name}' is not a valid AWS region name for {self.service_name}"
            )


class AccountRegionBundle(GenericAccountRegionBundle):
    """
    Encapsulation for all stores for all AWS account IDs.
    """

    def __init__(self, service_name: str, store: Type[BaseStoreType], validate: bool = True):
        super().__init__(service_name=service_name, store=store, region_bundle_type=RegionBundle)
        self.validate = validate

    def validate_item(self, account_id: str):
        if self.validate and not re.match(r"\d{12}", account_id):
            raise ValueError(f"'{account_id}' is not a valid AWS account ID")
