import logging
from abc import abstractmethod
from enum import StrEnum

from plux import Plugin

from localstack.services.cloudformation.resource_provider import (
    plugin_manager as cfn_plugin_manager,
)
from localstack.utils.catalog.common import (
    AwsServiceOperationsSupportInLatest,
    AwsServicesSupportInLatest,
    CloudFormationResourcesSupportAtRuntime,
    CloudFormationResourcesSupportInLatest,
)
from localstack.utils.catalog.loader import RemoteCatalogLoader

ServiceName = str
ServiceOperations = set[str]
ProviderName = str
CfnResourceName = str
CfnResourceMethodName = str
AwsServicesSupportStatus = AwsServicesSupportInLatest | AwsServiceOperationsSupportInLatest
CfnResourceSupportStatus = (
    CloudFormationResourcesSupportInLatest | CloudFormationResourcesSupportAtRuntime
)

LOG = logging.getLogger(__name__)


class LocalstackEmulatorType(StrEnum):
    COMMUNITY = "community"
    PRO = "pro"


class CatalogPlugin(Plugin):
    namespace = "localstack.utils.catalog"

    @staticmethod
    def get_cfn_resources_catalog(cloudformation_resources: dict):
        cfn_resources_catalog = {}
        for emulator_type in list(LocalstackEmulatorType):
            if emulator_type in cloudformation_resources:
                for resource_name in cloudformation_resources[emulator_type].keys():
                    cfn_resources_catalog[emulator_type] = {
                        resource_name: set(
                            cloudformation_resources[emulator_type][resource_name]["methods"]
                        )
                    }
        return cfn_resources_catalog

    @abstractmethod
    def get_aws_service_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportStatus | None:
        pass

    @abstractmethod
    def get_cloudformation_resource_status(
        self, resource_name: str
    ) -> CfnResourceSupportStatus | AwsServicesSupportStatus | None:
        pass


class AwsCatalogPlugin(CatalogPlugin):
    name = "aws_catalog"
    current_emulator_type: LocalstackEmulatorType = LocalstackEmulatorType.COMMUNITY
    services_in_latest: dict[ServiceName, dict[LocalstackEmulatorType, ServiceOperations]] = {}
    services_at_runtime: set[ServiceName] = set()
    cfn_resources_in_latest: dict[
        LocalstackEmulatorType, dict[CfnResourceName, set[CfnResourceMethodName]]
    ] = {}
    cfn_resources_at_runtime: set[CfnResourceName] = set()

    @staticmethod
    def get_aws_services_at_runtime():
        from localstack.services.plugins import SERVICE_PLUGINS

        return {
            provider_name.split(".")[0]
            for provider_name in SERVICE_PLUGINS.plugin_manager.list_names()
        }

    def __init__(self, remote_catalog_loader: RemoteCatalogLoader | None = None) -> None:
        catalog_loader = remote_catalog_loader or RemoteCatalogLoader()
        remote_catalog = catalog_loader.get_remote_catalog()
        for service_name in remote_catalog.services.keys():
            service = remote_catalog.services[service_name]
            for emulator_type in list(LocalstackEmulatorType):
                if emulator_type in service:
                    service_provider = service[emulator_type]
                    operations = service_provider.get("operations") or set()
                    self.services_in_latest.setdefault(service_name, {})[emulator_type] = operations

        self.cfn_resources_in_latest = AwsCatalogPlugin.get_cfn_resources_catalog(
            remote_catalog.cloudformation_resources
        )
        self.cfn_resources_at_runtime = set(cfn_plugin_manager.list_names())
        self.services_at_runtime = AwsCatalogPlugin.get_aws_services_at_runtime()

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
        for emulator_type in self.services_in_latest[service_name].keys():
            if emulator_type is self.current_emulator_type:
                continue
            if operation_name in self.services_in_latest[service_name][emulator_type]:
                return AwsServiceOperationsSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE
        return AwsServiceOperationsSupportInLatest.NOT_SUPPORTED

    def get_cloudformation_resource_status(
        self, resource_name: str
    ) -> CfnResourceSupportStatus | AwsServicesSupportStatus | None:
        if resource_name in self.cfn_resources_at_runtime:
            return CloudFormationResourcesSupportAtRuntime.AVAILABLE
        if len(rsc_name := resource_name.split("::")) >= 2:
            service_name = rsc_name[1].lower()
        else:
            return None
        if service_name in self.services_at_runtime:
            for emulator_type in list(LocalstackEmulatorType):
                if resource_name in self.cfn_resources_in_latest[emulator_type]:
                    if emulator_type is self.current_emulator_type:
                        return CloudFormationResourcesSupportInLatest.SUPPORTED
                    else:
                        return CloudFormationResourcesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE
            return CloudFormationResourcesSupportInLatest.NOT_SUPPORTED
        if service_name in self.services_in_latest:
            return self.get_aws_service_status(service_name, operation_name=None)
        return AwsServiceOperationsSupportInLatest.NOT_SUPPORTED
