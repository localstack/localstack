from plux import PluginManager

from localstack.utils.catalog.catalog import Catalog
from localstack.utils.catalog.plugins import CatalogPlugin
from localstack.utils.objects import singleton_factory

CATALOG_PLUGIN_MANAGER: PluginManager[type[Catalog]] = PluginManager(CatalogPlugin.namespace)


@singleton_factory
def get_aws_services_catalog() -> type[Catalog]:
    plugin_name = "aws_catalog_pro"
    if not CATALOG_PLUGIN_MANAGER.exists(plugin_name):
        plugin_name = "aws_catalog"
    return CATALOG_PLUGIN_MANAGER.load(plugin_name).load()()
