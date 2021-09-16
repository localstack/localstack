from typing import Dict, List, Tuple

import pytest

from localstack.plugin import Plugin, PluginFinder, PluginManager, PluginSpec


class DummyPlugin(Plugin):
    load_calls: List[Tuple[Tuple, Dict]]

    def __init__(self) -> None:
        super().__init__()
        self.load_calls = list()

    def load(self, *args, **kwargs):
        self.load_calls.append((args, kwargs))


class ShouldNotLoadPlugin(DummyPlugin):
    def should_load(self) -> bool:
        return False


class GoodPlugin(DummyPlugin):
    pass


class ThrowsExceptionOnLoadPlugin(DummyPlugin):
    def load(self, *args, **kwargs):
        super().load(*args, **kwargs)
        raise ValueError("controlled load fail")


class ThrowsExceptionOnInitPlugin(DummyPlugin):
    def __init__(self) -> None:
        super().__init__()
        raise ValueError("controlled __init__ fail")


class DummyPluginFinder(PluginFinder):
    def __init__(self, specs: List[PluginSpec]):
        self.specs = specs

    def find_plugins(self) -> List[PluginSpec]:
        return self.specs


@pytest.fixture
def dummy_plugin_finder():
    return DummyPluginFinder(
        [
            PluginSpec("test.plugins.dummy", "shouldload", GoodPlugin),
            PluginSpec("test.plugins.dummy", "shouldnotload", ShouldNotLoadPlugin),
            PluginSpec("test.plugins.dummy", "load_errors", ThrowsExceptionOnLoadPlugin),
            PluginSpec("test.plugins.dummy", "init_errors", ThrowsExceptionOnInitPlugin),
            PluginSpec("test.plugins.dummy", "shouldalsoload", GoodPlugin),
            PluginSpec("test.plugins.others", "shouldload", DummyPlugin),  # different namespace
        ]
    )


class TestPluginManager:
    def test_load_all(self, dummy_plugin_finder):
        manager = PluginManager("test.plugins.dummy", finder=dummy_plugin_finder)

        assert manager.is_loaded("shouldload") is False
        assert manager.is_loaded("shouldalsoload") is False
        assert manager.is_loaded("shouldnotload") is False
        assert manager.is_loaded("load_errors") is False
        assert manager.is_loaded("init_errors") is False

        plugins = manager.load_all()

        assert manager.is_loaded("shouldload") is True
        assert manager.is_loaded("shouldalsoload") is True
        assert manager.is_loaded("shouldnotload") is False
        assert manager.is_loaded("load_errors") is False
        assert manager.is_loaded("init_errors") is False

        assert len(plugins) == 2  # shouldload and shouldalsoload

        assert type(plugins[0]) is GoodPlugin
        assert type(plugins[1]) is GoodPlugin

    def test_list_names(self, dummy_plugin_finder):
        manager = PluginManager("test.plugins.dummy", finder=dummy_plugin_finder)
        names = manager.list_names()

        assert len(names) == 5
        assert "shouldload" in names
        assert "shouldnotload" in names
        assert "load_errors" in names
        assert "init_errors" in names
        assert "shouldalsoload" in names

    def test_exists(self, dummy_plugin_finder):
        manager = PluginManager("test.plugins.dummy", finder=dummy_plugin_finder)

        assert manager.exists("shouldload")
        assert manager.exists("shouldnotload")
        assert manager.exists("load_errors")
        assert manager.exists("init_errors")
        assert manager.exists("shouldalsoload")
        assert not manager.exists("foobar")

    def test_load_all_load_is_only_called_once(self):
        finder = DummyPluginFinder(
            [
                PluginSpec("test.plugins.dummy", "shouldload", GoodPlugin),
                PluginSpec("test.plugins.dummy", "shouldalsoload", GoodPlugin),
            ]
        )

        manager: PluginManager[DummyPlugin] = PluginManager("test.plugins.dummy", finder=finder)

        plugins = manager.load_all()
        assert len(plugins[0].load_calls) == 1
        assert len(plugins[1].load_calls) == 1

        plugins = manager.load_all()
        assert len(plugins[0].load_calls) == 1
        assert len(plugins[1].load_calls) == 1

    def test_load_on_non_existing_plugin(self):
        manager = PluginManager("test.plugins.dummy", finder=DummyPluginFinder([]))

        with pytest.raises(ValueError) as ex:
            manager.load("foo")

        ex.match("no plugin named foo in namespace test.plugins.dummy")

    def test_load_all_container_has_errors(self, dummy_plugin_finder):
        manager = PluginManager("test.plugins.dummy", finder=dummy_plugin_finder)

        c_shouldload = manager.get_container("shouldload")
        c_shouldnotload = manager.get_container("shouldnotload")
        c_load_errors = manager.get_container("load_errors")
        c_init_errors = manager.get_container("init_errors")
        c_shouldalsoload = manager.get_container("shouldalsoload")

        manager.load_all()

        assert c_shouldload.init_error is None
        assert c_shouldnotload.init_error is None
        assert type(c_init_errors.init_error) == ValueError
        assert c_load_errors.init_error is None
        assert c_shouldalsoload.init_error is None

        assert c_shouldload.load_error is None
        assert c_shouldnotload.load_error is None
        assert c_init_errors.load_error is None
        assert type(c_load_errors.load_error) == ValueError
        assert c_shouldalsoload.load_error is None

    def test_load_all_propagate_exception(self):
        manager = PluginManager(
            "test.plugins.dummy",
            finder=DummyPluginFinder(
                [
                    PluginSpec("test.plugins.dummy", "load_errors", ThrowsExceptionOnLoadPlugin),
                ]
            ),
        )

        with pytest.raises(ValueError) as ex:
            manager.load_all(propagate_exceptions=True)

        ex.match("controlled load fail")

    # TODO: test lifecycle listeners
