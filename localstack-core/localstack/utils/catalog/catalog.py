import logging
from abc import abstractmethod
from typing import TypeAlias

from plux import Plugin

from localstack.services.cloudformation.resource_provider import (
    plugin_manager as cfn_plugin_manager,
)
from localstack.utils.catalog.catalog_loader import RemoteCatalogLoader
from localstack.utils.catalog.common import (
    AwsServiceOperationsSupportInLatest,
    AwsServicesSupportInLatest,
    AwsServiceSupportAtRuntime,
    CloudFormationResourcesSupportAtRuntime,
    CloudFormationResourcesSupportInLatest,
    LocalstackEmulatorType,
)

ServiceName = str
ServiceOperations = set[str]
ProviderName = str
CfnResourceName = str
CfnResourceMethodName = str
AwsServicesSupportStatus: TypeAlias = (
    AwsServiceSupportAtRuntime | AwsServicesSupportInLatest | AwsServiceOperationsSupportInLatest
)
CfnResourceSupportStatus: TypeAlias = (
    CloudFormationResourcesSupportInLatest | CloudFormationResourcesSupportAtRuntime
)
CfnResourceCatalog = dict[LocalstackEmulatorType, dict[CfnResourceName, set[CfnResourceMethodName]]]

LOG = logging.getLogger(__name__)


class CatalogPlugin(Plugin):
    namespace = "localstack.utils.catalog"

    @staticmethod
    def _get_cfn_resources_catalog(cloudformation_resources: dict) -> CfnResourceCatalog:
        cfn_resources_catalog = {}
        for emulator_type, resources in cloudformation_resources.items():
            cfn_resources_catalog[emulator_type] = {}
            for resource_name, resource in resources.items():
                cfn_resources_catalog[emulator_type][resource_name] = set(resource.methods)
        return cfn_resources_catalog

    @staticmethod
    def _get_services_at_runtime() -> set[ServiceName]:
        from localstack.services.plugins import SERVICE_PLUGINS

        return set(SERVICE_PLUGINS.list_available())

    @staticmethod
    def _get_cfn_resources_available_at_runtime() -> set[CfnResourceName]:
        return set(cfn_plugin_manager.list_names())

    @abstractmethod
    def get_aws_service_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportStatus | None:
        pass

    @abstractmethod
    def get_cloudformation_resource_status(
        self, resource_name: str, service_name: str, is_pro_resource: bool = False
    ) -> CfnResourceSupportStatus | AwsServicesSupportInLatest | None:
        pass


class AwsCatalogRuntimePlugin(CatalogPlugin):
    name = "aws-catalog-runtime-only"

    def get_aws_service_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportStatus | None:
        return None

    def get_cloudformation_resource_status(
        self, resource_name: str, service_name: str, is_pro_resource: bool = False
    ) -> CfnResourceSupportStatus | AwsServicesSupportInLatest | None:
        return None


class AwsCatalogRemoteStatePlugin(CatalogPlugin):
    name = "aws-catalog-remote-state"
    current_emulator_type: LocalstackEmulatorType = LocalstackEmulatorType.COMMUNITY
    services_in_latest: dict[ServiceName, dict[LocalstackEmulatorType, ServiceOperations]] = {}
    services_at_runtime: set[ServiceName] = set()
    cfn_resources_in_latest: CfnResourceCatalog = {}
    cfn_resources_at_runtime: set[CfnResourceName] = set()

    def __init__(self, remote_catalog_loader: RemoteCatalogLoader | None = None) -> None:
        catalog_loader = remote_catalog_loader or RemoteCatalogLoader()
        remote_catalog = catalog_loader.get_remote_catalog()
        for service_name, emulators in remote_catalog.services.items():
            for emulator_type, service_provider in emulators.items():
                self.services_in_latest.setdefault(service_name, {})[emulator_type] = set(
                    service_provider.operations
                )

        self.cfn_resources_in_latest = self._get_cfn_resources_catalog(
            remote_catalog.cloudformation_resources
        )
        self.cfn_resources_at_runtime = self._get_cfn_resources_available_at_runtime()
        self.services_at_runtime = self._get_services_at_runtime()

    def get_aws_service_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportStatus | None:
        if not self.services_in_latest:
            return None
        if service_name not in self.services_in_latest:
            return AwsServicesSupportInLatest.NOT_SUPPORTED
        if self.current_emulator_type not in self.services_in_latest[service_name]:
            return AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE
        if not operation_name:
            return AwsServicesSupportInLatest.SUPPORTED
        if operation_name in self.services_in_latest[service_name][self.current_emulator_type]:
            return AwsServiceOperationsSupportInLatest.SUPPORTED
        for emulator_type in self.services_in_latest[service_name]:
            if emulator_type is self.current_emulator_type:
                continue
            if operation_name in self.services_in_latest[service_name][emulator_type]:
                return AwsServiceOperationsSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE
        return AwsServiceOperationsSupportInLatest.NOT_SUPPORTED

    def get_cloudformation_resource_status(
        self, resource_name: str, service_name: str, is_pro_resource: bool = False
    ) -> CfnResourceSupportStatus | AwsServicesSupportInLatest | None:
        if resource_name in self.cfn_resources_at_runtime:
            return CloudFormationResourcesSupportAtRuntime.AVAILABLE
        if service_name in self.services_at_runtime:
            if resource_name in self.cfn_resources_in_latest[self.current_emulator_type]:
                return CloudFormationResourcesSupportInLatest.SUPPORTED
            else:
                return CloudFormationResourcesSupportInLatest.NOT_SUPPORTED
        if service_name in self.services_in_latest:
            return self.get_aws_service_status(service_name, operation_name=None)
        return AwsServicesSupportInLatest.NOT_SUPPORTED
