import json
import os
from typing import Optional

import pytest
from _pytest.config import Config, PytestPluginManager
from _pytest.config.argparsing import Parser
from _pytest.fixtures import SubRequest
from _pytest.nodes import Item
from _pytest.reports import TestReport
from _pytest.runner import CallInfo
from pluggy import Result

from localstack.constants import TEST_AWS_REGION_NAME
from localstack.testing.snapshots import SnapshotAssertionError, SnapshotSession
from localstack.testing.snapshots.report import render_report
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.testing.snapshots.transformer_utility import (
    SNAPSHOT_BASIC_TRANSFORMER,
    SNAPSHOT_BASIC_TRANSFORMER_NEW,
)
from localstack.utils.bootstrap import is_api_enabled


def is_aws():
    return os.environ.get("TEST_TARGET", "") == "AWS_CLOUD"


@pytest.hookimpl
def pytest_configure(config: Config):
    config.addinivalue_line("markers", "skip_snapshot_verify")


@pytest.hookimpl
def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption("--snapshot-update", action="store_true")
    parser.addoption("--snapshot-raw", action="store_true")
    parser.addoption("--snapshot-skip-all", action="store_true")
    parser.addoption("--snapshot-verify", action="store_true")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Item, call: CallInfo[None]) -> Optional[TestReport]:
    use_legacy_report = os.environ.get("SNAPSHOT_LEGACY_REPORT", "0") == "1"

    result: Result = yield
    report: TestReport = result.get_result()

    if call.excinfo is not None and isinstance(call.excinfo.value, SnapshotAssertionError):
        err: SnapshotAssertionError = call.excinfo.value

        if use_legacy_report:
            error_report = ""
            for res in err.result:
                if not res:
                    error_report = f"{error_report}Match failed for '{res.key}':\n{json.dumps(json.loads(res.result.to_json()), indent=2)}\n\n"
            report.longrepr = error_report
        else:
            report.longrepr = "\n".join([str(render_report(r)) for r in err.result if not r])
    return report


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: Item) -> None:
    call: CallInfo = yield  # noqa

    if call.excinfo:
        return

    # TODO: extremely dirty... maybe it would be better to find a way to fail the test itself instead?
    sm = item.funcargs.get("snapshot")

    if sm:
        verify = True
        paths = []

        if not is_aws():  # only skip for local tests
            for m in item.iter_markers(name="skip_snapshot_verify"):
                skip_paths = m.kwargs.get("paths", [])

                skip_condition = m.kwargs.get("condition")
                # can optionally include a condition, when this will be skipped
                # a condition must be a Callable returning something truthy/falsey
                if skip_condition:
                    if not callable(skip_condition):
                        raise ValueError("condition must be a callable")

                    # special case where one of the marks has a skip condition but no paths
                    # since we interpret a missing paths key as "all paths",
                    # this should skip all paths, no matter what the other marks say
                    if skip_condition() and not skip_paths:
                        verify = False
                        paths.clear()  # in case some other marker already added paths
                        break

                    if not skip_condition():
                        continue  # don't skip

                # we skip verification if no condition has been specified
                verify = False
                paths.extend(skip_paths)

        sm._assert_all(verify, paths)


@pytest.fixture(name="region", scope="session")
def fixture_region(aws_client):
    if is_aws() or is_api_enabled("sts"):
        return aws_client.sts.meta.region_name
    else:
        return TEST_AWS_REGION_NAME


@pytest.fixture(scope="function")
def _snapshot_session(request: SubRequest, account_id, region):
    update_overwrite = os.environ.get("SNAPSHOT_UPDATE") == "1"
    raw_overwrite = os.environ.get("SNAPSHOT_RAW") == "1"

    sm = SnapshotSession(
        base_file_path=os.path.join(request.fspath.dirname, request.fspath.purebasename),
        scope_key=request.node.nodeid,
        update=update_overwrite or request.config.option.snapshot_update,
        raw=raw_overwrite or request.config.option.snapshot_raw,
        verify=False if request.config.option.snapshot_skip_all else True,
    )
    sm.add_transformer(RegexTransformer(account_id, "1" * 12), priority=2)
    sm.add_transformer(RegexTransformer(region, "<region>"), priority=2)

    # TODO: temporary to migrate to new default transformers.
    #   remove this after all exemptions are gone
    exemptions = [
        "tests/aws/services/acm",
        "tests/aws/services/apigateway",
        "tests/aws/services/cloudwatch",
        "tests/aws/services/cloudformation",
        "tests/aws/services/dynamodb",
        "tests/aws/services/events",
        "tests/aws/services/iam",
        "tests/aws/services/kinesis",
        "tests/aws/services/kms",
        "tests/aws/services/lambda_",
        "tests/aws/services/logs",
        "tests/aws/services/route53",
        "tests/aws/services/route53resolver",
        "tests/aws/services/s3",
        "tests/aws/services/secretsmanager",
        "tests/aws/services/ses",
        "tests/aws/services/sns",
        "tests/aws/services/stepfunctions",
        "tests/aws/services/sqs",
        "tests/aws/services/transcribe",
        "tests/aws/scenario/bookstore",
        "tests/aws/scenario/note_taking",
        "tests/aws/scenario/lambda_destination",
        "tests/aws/scenario/loan_broker",
        "localstack_ext",
        "localstack-ext",
    ]
    if any([e in request.fspath.dirname for e in exemptions]):
        sm.add_transformer(SNAPSHOT_BASIC_TRANSFORMER, priority=2)
    else:
        sm.add_transformer(SNAPSHOT_BASIC_TRANSFORMER_NEW, priority=2)

    yield sm

    sm._persist_state()


# FIXME: remove after fixture is added in -ext
@pytest.fixture(scope="function")
def snapshot(_snapshot_session):
    return _snapshot_session
