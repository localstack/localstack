import logging
from typing import Type

from plugin import Plugin, PluginManager

from localstack.services.awslambda.layerfetcher.layer_fetcher import LayerFetcher

LOG = logging.getLogger(__name__)


class LayerFetcherPlugin(Plugin):
    namespace = "localstack.lambda.layerfetcher"


LAYER_FETCHER_PLUGIN_MANAGER: PluginManager[Type[LayerFetcher]] = PluginManager(
    LayerFetcherPlugin.namespace
)


def get_aws_layer_fetcher_class() -> Type[LayerFetcher] | None:
    plugin_name = "aws"
    if not LAYER_FETCHER_PLUGIN_MANAGER.exists(plugin_name):
        LOG.debug("Layer fetcher pro plugin not available")
        return None
    return LAYER_FETCHER_PLUGIN_MANAGER.load(plugin_name).load()()


def get_aws_layer_fetcher_fun():
    # Function-plugin
    # all_funs = PluginManager("localstack.lambda.layerfetcher").load_all()
    lf_factory = (
        PluginManager("localstack.lambda.layerfetcher").load("get_aws_layer_fetcher").load()
    )
    return lf_factory()
