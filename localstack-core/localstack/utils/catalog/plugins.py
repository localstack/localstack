from plux import PluginManager

from localstack.utils.catalog.catalog import CatalogPlugin
from localstack.utils.objects import singleton_factory


@singleton_factory
def get_aws_catalog() -> CatalogPlugin:
    plugin_manager = PluginManager(CatalogPlugin.namespace)
    plugin_name = "aws_catalog_pro"
    if not plugin_manager.exists(plugin_name):
        plugin_name = "aws_catalog"
    return plugin_manager.load(plugin_name)
