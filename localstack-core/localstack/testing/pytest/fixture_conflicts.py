"""
This pytest plugin makes sure there's only a single fixture definition for each fixture name when executing a test.

The behavior here can be disabled with the option --ignore-fixture-conflicts which will then behave like pytest does by default (i.e. allow multiple defs).
"""

import logging

import pytest
from _pytest.config import PytestPluginManager
from _pytest.config.argparsing import Parser
from _pytest.nodes import Item
from _pytest.python import Function

LOG = logging.getLogger(__name__)


@pytest.hookimpl
def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption(
        "--ignore-fixture-conflicts",
        action="store_true",
        help="When enabled, allows multiple fixture definitions to exist for a single fixture name.",
    )


@pytest.hookimpl
def pytest_runtest_setup(item: Item):
    if not item.config.getoption("--ignore-fixture-conflicts", False):
        if isinstance(item, Function):
            # unfortunately there don't seem to be proper fixture initialization hooks and
            # the fixture names only include a single entry even when multiple definitions are found
            # so we need to check the internal name2fixturedefs dict instead
            defs = item._fixtureinfo.name2fixturedefs
            multi_defs = [k for k, v in defs.items() if len(v) > 1 and "snapshot" not in k]
            if multi_defs:
                pytest.exit(f"Aborting. Detected multiple defs for fixtures: {multi_defs}")
