import os

from localstack.plugin import PluginSpec
from localstack.plugin.discovery import ModuleScanningPluginFinder, PackagePathPluginFinder

from .plugins import sample_plugins


class TestModuleScanningPluginFinder:
    def test_find_plugins(self):
        finder = ModuleScanningPluginFinder(modules=[sample_plugins])
        plugins = finder.find_plugins()

        # update when adding plugins to sample_plugins
        assert PluginSpec("namespace_2", "simple", sample_plugins.SimplePlugin) in plugins
        assert PluginSpec("namespace_1", "plugin_1", sample_plugins.AbstractSamplePlugin) in plugins
        assert PluginSpec("namespace_1", "plugin_2", sample_plugins.AbstractSamplePlugin) in plugins
        assert len(plugins) == 3


class TestPackagePathPluginFinder:
    def test_find_plugins(self):
        where = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))

        finder = PackagePathPluginFinder(where=where, include=("tests.unit.plugin.plugins",))
        plugins = finder.find_plugins()

        # update when adding plugins to sample_plugins
        assert PluginSpec("namespace_2", "simple", sample_plugins.SimplePlugin) in plugins
        assert PluginSpec("namespace_1", "plugin_1", sample_plugins.AbstractSamplePlugin) in plugins
        assert PluginSpec("namespace_1", "plugin_2", sample_plugins.AbstractSamplePlugin) in plugins
        assert len(plugins) == 3
