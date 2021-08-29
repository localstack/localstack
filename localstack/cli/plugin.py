import abc
import logging
import os

import click

LOG = logging.getLogger(__name__)


class Plugin:
    # TODO: extract as base class for a localstack plugin

    name: str
    """ the plugin name which has to be unique within the plugin namespace """

    def is_active(self):
        return True

    def load(self):
        """
        Runs plugin loading logic if is_active returns True.
        """
        pass


class LocalstackCli:
    group: click.Group

    def __call__(self, *args, **kwargs):
        self.group(*args, **kwargs)


class LocalstackCliPlugin(Plugin):
    namespace = "localstack.plugins.cli"

    @abc.abstractmethod
    def attach(self, cli) -> None:
        """
        Attach commands to the `localstack` CLI.

        :param cli: the cli object
        """


def load_cli_plugins(cli):
    # TODO: generalize into a loading mechanism together with plugin
    from stevedore.extension import ExtensionManager

    if os.environ.get("DEBUG_PLUGINS", "0").lower() in ("true", "1"):
        # importing localstack.config is still quite expensive...
        logging.basicConfig(level=logging.DEBUG)

    namespace = LocalstackCliPlugin.namespace

    # this line actually imports the plugin code
    manager = ExtensionManager(namespace=namespace, invoke_on_load=False)

    for name, ext in manager.items():
        LOG.debug("loading plugin %s:%s type: %s", namespace, name, ext.plugin)

        try:
            plugin: LocalstackCliPlugin = ext.plugin()

            if not plugin.is_active():
                LOG.debug("plugin %s is deactivated, skipping")
                continue

            LOG.info("loading %s:%s", namespace, name)
            plugin.load()
            LOG.info("attaching to CLI %s:%s", namespace, name)
            plugin.attach(cli)
        except Exception:
            LOG.exception("error loading plugin %s:%s", namespace, name)
            pass
