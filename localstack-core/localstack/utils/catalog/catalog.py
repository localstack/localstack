import logging
from abc import abstractmethod

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
AwsServicesSupportStatus = (
    AwsServiceSupportAtRuntime | AwsServicesSupportInLatest | AwsServiceOperationsSupportInLatest
)
CfnResourceSupportStatus = (
    CloudFormationResourcesSupportInLatest | CloudFormationResourcesSupportAtRuntime
)

LOG = logging.getLogger(__name__)


class CatalogPlugin(Plugin):
    namespace = "localstack.utils.catalog"

    @staticmethod
    def get_cfn_resources_catalog(cloudformation_resources: dict):
        cfn_resources_catalog = {}
        for emulator_type, resources in cloudformation_resources.items():
            for resource_name, resource in resources.items():
                cfn_resources_catalog[emulator_type] = {resource_name: set(resource.methods)}
        return cfn_resources_catalog

    @staticmethod
    def get_aws_services_at_runtime():
        from localstack.services.plugins import SERVICE_PLUGINS

        return SERVICE_PLUGINS.list_available()

    @abstractmethod
    def get_aws_service_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportStatus | None:
        pass

    @abstractmethod
    def get_cloudformation_resource_status(
        self, resource_name: str, service_name: str
    ) -> CfnResourceSupportStatus | AwsServicesSupportInLatest | None:
        pass


class AwsCatalogRuntimePlugin(CatalogPlugin):
    name = "aws-catalog-runtime-only"

    def get_aws_service_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportStatus | None:
        return None

    def get_cloudformation_resource_status(
        self, resource_name: str, service_name: str
    ) -> CfnResourceSupportStatus | AwsServicesSupportInLatest | None:
        return None


class AwsCatalogRemoteStatePlugin(CatalogPlugin):
    name = "aws-catalog-remote-state"
    current_emulator_type: LocalstackEmulatorType = LocalstackEmulatorType.COMMUNITY
    services_in_latest: dict[ServiceName, dict[LocalstackEmulatorType, ServiceOperations]] = {}
    services_at_runtime: set[ServiceName] = set()
    cfn_resources_in_latest: dict[
        LocalstackEmulatorType, dict[CfnResourceName, set[CfnResourceMethodName]]
    ] = {}
    cfn_resources_at_runtime: set[CfnResourceName] = set()

    def __init__(self, remote_catalog_loader: RemoteCatalogLoader | None = None) -> None:
        catalog_loader = remote_catalog_loader or RemoteCatalogLoader()
        remote_catalog = catalog_loader.get_remote_catalog()
        for service_name, emulators in remote_catalog.services.items():
            for emulator_type, service_provider in emulators.items():
                self.services_in_latest.setdefault(service_name, {})[emulator_type] = set(
                    service_provider.operations
                )

        self.cfn_resources_in_latest = self.get_cfn_resources_catalog(
            remote_catalog.cloudformation_resources
        )
        self.cfn_resources_at_runtime = set(cfn_plugin_manager.list_names())
        self.services_at_runtime = self.get_aws_services_at_runtime()

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
        self, resource_name: str, service_name: str
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
