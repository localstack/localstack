import abc
import logging
import os

import click

from localstack.plugin import Plugin

LOG = logging.getLogger(__name__)


class LocalstackCli:
    group: click.Group

    def __call__(self, *args, **kwargs):
        self.group(*args, **kwargs)


class LocalstackCliPlugin(Plugin):
    namespace = "localstack.plugins.cli"

    def load(self, cli) -> None:
        self.attach(cli)

    @abc.abstractmethod
    def attach(self, cli: LocalstackCli) -> None:
        """
        Attach commands to the `localstack` CLI.

        :param cli: the cli object
        """


def load_cli_plugins(cli):
    from localstack.plugin.manager import PluginManager

    if os.environ.get("DEBUG_PLUGINS", "0").lower() in ("true", "1"):
        # importing localstack.config is still quite expensive...
        logging.basicConfig(level=logging.DEBUG)

    loader = PluginManager("localstack.plugins.cli", load_args=(cli,))
    loader.load_all()
