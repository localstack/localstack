import json
import logging
import os
import re
from datetime import datetime
from typing import Optional

import pytest
from _pytest.fixtures import SubRequest
from _pytest.nodes import Item
from _pytest.reports import TestReport
from _pytest.runner import CallInfo
from botocore.response import StreamingBody
from deepdiff import DeepDiff
from deepdiff.operator import BaseOperator
from pluggy.callers import _Result

LOG = logging.getLogger(__name__)


@pytest.fixture(name="snapshot", scope="function")
def fixture_snapshot(request: SubRequest):
    sm = SnapshotManager(
        file_path=os.path.join(
            request.fspath.dirname, f"{request.fspath.purebasename}.snapshot.json"
        ),
        write=request.config.option.snapshot_write,
        scope_key=request.node.nodeid,
        strict=request.config.option.snapshot_strict,
    )
    yield sm
    sm.persist_state()


ARN_PATTERN = re.compile(
    r"arn:(aws[a-zA-Z-]*)?:([a-zA-Z0-9-_.]+)?:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?(:[^:\\\"]+)+"
)

# TODO: instead of skipping, make zip building reproducable
# TODO: ignore => replace/match instead
IGNORE_VALUE_PATTERNS = [
    # generalized ARN (also shorthand versions)
    re.compile(
        r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
    ),  # UUID
    re.compile(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}(\+[0-9]{4})?"
    ),  # Date (2022-01-28T11:55:54.732+0000)
    # TODO: Queue URL
    # TODO: s3 bucket URL
    # TODO: apigateway
]

IGNORE_KEY_PATTERNS = [
    # re.compile(r"^.*Arn$"),
    re.compile(r"^.*Name$"),
    re.compile(r"^.*ResponseMetadata$"),
    re.compile(r"^.*Location$"),
    re.compile(r"^.*sha.*$", flags=re.RegexFlag.IGNORECASE),
]


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Item, call: CallInfo[None]) -> Optional[TestReport]:
    result: _Result = yield
    report: TestReport = result.result

    if call.excinfo is not None and isinstance(call.excinfo.value, SnapshotAssertionError):
        err: SnapshotAssertionError = call.excinfo.value
        # report.longrepr = err.result.result.pretty()
        # report.longrepr = err.result.result.__repr__()
        # report.longrepr = err.result.result.to_json()
        report.longrepr = json.dumps(json.loads(err.result.result.to_json()), indent=2)
    return report


# def pytest_runtest_logreport(report: TestReport):
# def pytest_assertrepr_compare(config: Config, op: str, left: object, right: object) -> list[str] | None:


# TODO custom DeepDiff operators
class ArnComparator(BaseOperator):
    pass


class SnapshotMatchResult:
    def __init__(self, a: dict, b: dict):
        self.a = a
        self.b = b
        self.result = DeepDiff(a, b, custom_operators=[])

    def __bool__(self) -> bool:
        return not self.result

    def __repr__(self):
        return self.result.pretty()


class SnapshotAssertionError(AssertionError):
    def __init__(self, msg: str, result: SnapshotMatchResult):
        self.msg = msg
        self.result = result
        super(SnapshotAssertionError, self).__init__(msg)


class SnapshotManager:
    """
    snapshot handler for a single test function with potentially multiple assertions\
    Since it technically only  modifies a subset of the underlying snapshot file,
    it assumes that a single snapshot file is only being written to sequentially
    """

    results = []
    state = {}

    def __init__(
        self, *, file_path: str, write: bool, scope_key: str, strict: Optional[bool] = False
    ):
        self.strict = strict
        self.write = write
        self.file_path = file_path
        self.scope_key = scope_key
        self.state = self.load_state()
        if scope_key not in self.state:
            self.state[scope_key] = {}

    def persist_state(self) -> None:
        if self.write:
            with open(self.file_path, "w") as fd:
                fd.write(json.dumps(self.state, indent=2))

    def load_state(self) -> dict:
        try:
            with open(self.file_path, "r") as fd:
                return json.loads(fd.read())
        except FileNotFoundError:
            return {}

    def match(self, key: str, obj: dict) -> SnapshotMatchResult:
        __tracebackhide__ = True

        obj_state = self._extract_state(obj)
        if self.write:
            self.state[self.scope_key][key] = obj_state
            return SnapshotMatchResult({}, {})

        sub_state = self.state[self.scope_key].get(key)
        if sub_state is None:
            raise Exception("Please execute this first with --snapshot-write")

        return SnapshotMatchResult(sub_state, obj_state)

    def assert_match(self, key: str, obj: dict) -> None:
        """
        Primary tester-facing interface. (Call this method in your test case.)
        Internally this raises an AssertionError and properly handles output formatting for the diff
        """
        __tracebackhide__ = True
        result = self.match(key, obj)
        self.results.append(result)
        if not result and self.strict:
            raise SnapshotAssertionError("Parity snapshot failed", result=result)

    # TODO: add cleaning/anonymization step
    def _extract_state(self, old: dict) -> dict:
        """build a persistable state definition that can later be compared against"""

        new_dict = dict()
        for k, v in old.items():
            if any([p.match(k) for p in IGNORE_KEY_PATTERNS]):
                LOG.warning(f"Skipping key: {k}")
                continue

            if isinstance(v, dict):
                new_dict[k] = self._extract_state(v)

            elif isinstance(v, list):
                # assumption: no nested lists in API calls
                new_list = []

                for i in v:
                    if isinstance(i, dict):
                        new_list.append(self._extract_state(i))
                    elif isinstance(i, str):
                        if any([p.match(i) for p in IGNORE_VALUE_PATTERNS]):
                            LOG.warning(f"Skipping value: {v} for key: {k}")
                        else:
                            new_list.append(i)
                    else:  # assumption: has to be an int or boolean, jus ttaking them over
                        new_list.append(v)

                new_dict[k] = new_list

            elif isinstance(v, str):
                if any([p.match(v) for p in IGNORE_VALUE_PATTERNS]):
                    LOG.warning(f"Skipping value: {v} for key: {k}")
                else:
                    new_dict[k] = v

            elif isinstance(v, StreamingBody):
                read_val = v.read().decode("utf-8")
                if any([p.match(read_val) for p in IGNORE_VALUE_PATTERNS]):
                    LOG.warning(f"Skipping value: {read_val} for key: {k}")
                else:
                    new_dict[k] = read_val

            elif isinstance(v, datetime):  # TODO: remove when structural matching is implemented
                new_dict[k] = "2022-04-06T16:46:20.061000+02:00"
                # new_dict[k] = v.isoformat()

            else:
                new_dict[k] = v

        tmp_str = json.dumps(new_dict)
        tmp_str = re.sub(ARN_PATTERN, "<arn>", tmp_str)
        return json.loads(tmp_str)
