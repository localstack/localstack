import logging

from plux import PluginManager

from localstack.utils.catalog.catalog import CatalogPlugin
from localstack.utils.objects import singleton_factory

LOG = logging.getLogger(__name__)


@singleton_factory
def get_aws_catalog() -> CatalogPlugin:
    plugin_manager = PluginManager(CatalogPlugin.namespace)
    try:
        plugin_name = "aws-catalog-remote-state-with-license"
        if not plugin_manager.exists(plugin_name):
            plugin_name = "aws-catalog-remote-state"
        return plugin_manager.load(plugin_name)
    except Exception as e:
        LOG.debug(
            "Failed to load catalog plugin with the latest LocalStack services support data, falling back to catalog without remote state: %s",
            e,
        )
        # Try to load runtime catalog from pro version first
        fallback_plugin_name = "aws-catalog-runtime-only-with-license"
        if not plugin_manager.exists(fallback_plugin_name):
            fallback_plugin_name = "aws-catalog-runtime-only"
        return plugin_manager.load(fallback_plugin_name)
