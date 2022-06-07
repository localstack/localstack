import pytest
from _pytest.config import Config, PytestPluginManager
from _pytest.config.argparsing import Parser
from _pytest.main import Session
from _pytest.nodes import Item


@pytest.hookimpl
def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption("--filter-fixtures", action="store")


@pytest.hookimpl
def pytest_collection_modifyitems(session: Session, config: Config, items: list[Item]):
    ff = config.getoption("--filter-fixtures")
    if ff:
        # TODO: add more sophisticated combinations (=> like pytest -m and -k)
        #   currently this is implemented in a way that any overlap between the fixture names will lead to selection
        filter_fixtures = set(ff.split(","))
        selected = []
        deselected = []
        for item in items:
            if hasattr(item, "fixturenames") and filter_fixtures.isdisjoint(set(item.fixturenames)):
                deselected.append(item)
            else:
                selected.append(item)
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)
