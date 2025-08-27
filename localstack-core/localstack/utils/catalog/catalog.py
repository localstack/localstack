import json
import logging
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import TypedDict

from localstack.utils.catalog.common import (
    AwsServiceOperationsSupportInLatest,
    AwsServicesSupportInLatest,
)

ServiceName = str
ServiceOperations = set[str]

LOG = logging.getLogger(__name__)

LICENSE_CATALOG_PATH = ""


class AwsRemoteCatalog(TypedDict):
    schema_version: str
    localstack: dict[str, str]
    services: dict
    cloudformation_resources: dict


class Catalog(ABC):
    @classmethod
    def load_catalog_file(cls) -> AwsRemoteCatalog:
        with open(LICENSE_CATALOG_PATH) as f:
            return AwsRemoteCatalog(**json.load(f))  # TODO: safe loading, validate schema

    @abstractmethod
    def get_support_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportInLatest | AwsServiceOperationsSupportInLatest | None:
        pass


class LocalstackEmulatorType(StrEnum):
    COMMUNITY = "community"
    PRO = "pro"


class AwsCatalog(Catalog):
    current_emulator_type: LocalstackEmulatorType = LocalstackEmulatorType.COMMUNITY
    services_in_latest: dict[ServiceName, dict[LocalstackEmulatorType, ServiceOperations]] = {}

    def __init__(self) -> None:
        services = self.load_catalog_file().get("services", {})
        for service_name in services.keys():
            service = services[service_name]
            for emulator_type in list(LocalstackEmulatorType):
                if emulator_type in service:
                    service_provider = service[emulator_type]
                    operations = service_provider.get("operations") or set()
                    self.services_in_latest.setdefault(service_name, {})[emulator_type] = operations

    def get_support_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportInLatest | AwsServiceOperationsSupportInLatest | None:
        if not self.services_in_latest:
            return None
        if service_name not in self.services_in_latest:
            return AwsServicesSupportInLatest.NOT_SUPPORTED
        if AwsCatalog.current_emulator_type not in self.services_in_latest[service_name]:
            return AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE
        if operation_name is None:
            return AwsServicesSupportInLatest.SUPPORTED
        providers_operations = self.services_in_latest[service_name][
            AwsCatalog.current_emulator_type
        ]
        if operation_name in providers_operations:
            return AwsServiceOperationsSupportInLatest.SUPPORTED
        return AwsServiceOperationsSupportInLatest.NOT_SUPPORTED
