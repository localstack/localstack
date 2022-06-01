import json
import logging
import os
from typing import Optional

import pytest
from _pytest.config import PytestPluginManager
from _pytest.config.argparsing import Parser
from _pytest.fixtures import SubRequest
from _pytest.nodes import Item
from _pytest.reports import TestReport
from _pytest.runner import CallInfo
from pluggy.callers import _Result

from localstack.testing.pytest.fixtures import (  # TODO(!) fix. shouldn't import from a plugin module
    _client,
)
from localstack.testing.snapshots import SnapshotAssertionError, SnapshotSession

LOG = logging.getLogger(__name__)


@pytest.hookimpl
def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption("--snapshot-update", action="store_true")
    parser.addoption("--snapshot-verify", action="store_true")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Item, call: CallInfo[None]) -> Optional[TestReport]:
    result: _Result = yield
    report: TestReport = result.result

    if call.excinfo is not None and isinstance(call.excinfo.value, SnapshotAssertionError):
        err: SnapshotAssertionError = call.excinfo.value
        report.longrepr = json.dumps(json.loads(err.result.result.to_json()), indent=2)
    return report


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: Item) -> None:
    call: CallInfo = yield  # noqa
    # TODO: extremely dirty... maybe it would be better to find a way to fail the test itself instead?
    sm = item.funcargs.get("snapshot")
    if sm:
        sm.assert_all()


@pytest.fixture(name="account_id", scope="session")
def fixture_account_id():
    sts_client = _client("sts")  # TODO: extract client factory from fixtures plugin
    yield sts_client.get_caller_identity()["Account"]


@pytest.fixture(name="snapshot", scope="function")
def fixture_snapshot(request: SubRequest, account_id):
    sm = SnapshotSession(
        file_path=os.path.join(
            request.fspath.dirname, f"{request.fspath.purebasename}.snapshot.json"
        ),
        scope_key=request.node.nodeid,
        update=request.config.option.snapshot_update,
        verify=request.config.option.snapshot_verify,
    )
    sm.register_account_id(account_id)

    yield sm

    sm.persist_state()
