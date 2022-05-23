import json
import logging
import os
import re
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
from localstack.testing.snapshots.transformer import (
    PATTERN_ISO8601,
    PATTERN_UUID,
    KeyValueBasedTransformer,
    RegexTransformer,
)

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
        error_report = ""
        for res in err.result:
            if not res:
                error_report = f"{error_report}Match failed for '{res.key}':\n{json.dumps(json.loads(res.result.to_json()), indent=2)}\n\n"
        report.longrepr = error_report
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


@pytest.fixture(name="region", scope="session")
def fixture_region():
    sts_client = _client("sts")  # TODO: extract client factory from fixtures plugin
    yield sts_client.meta.region_name


@pytest.fixture(name="snapshot", scope="function")
def fixture_snapshot(request: SubRequest, account_id, region):
    sm = SnapshotSession(
        file_path=os.path.join(
            request.fspath.dirname, f"{request.fspath.purebasename}.snapshot.json"
        ),
        scope_key=request.node.nodeid,
        update=request.config.option.snapshot_update,
        verify=request.config.option.snapshot_verify,
    )
    sm.add_transformer(RegexTransformer(account_id, "1" * 12), priority=-1)
    sm.add_transformer(RegexTransformer(region, "<region>"), priority=-1)
    sm.add_transformer(
        KeyValueBasedTransformer(
            lambda k, v: (
                v
                if (isinstance(v, str) and k.lower().endswith("id") and re.match(PATTERN_UUID, v))
                else None
            ),
            "uuid",
        )
    )

    # TODO: new transformer api
    sm.skip_key(re.compile("HTTPHeaders"), "HTTPHeaders")
    sm.register_replacement(PATTERN_ISO8601, "date")
    # sm.register_replacement(PATTERN_SQS_URL, "<sqs-url>")
    # sm.skip_key(re.compile(r"^.*Name$"), "<name>")
    # sm.skip_key(re.compile(r"^.*Location$"), "<location>")
    # sm.skip_key(re.compile(r"^.*timestamp.*$", flags=re.IGNORECASE), "<timestamp>")
    # sm.skip_key(
    #     re.compile(r"^.*sha.*$", flags=re.IGNORECASE), "<sha>"
    # )

    yield sm

    sm.persist_state()
