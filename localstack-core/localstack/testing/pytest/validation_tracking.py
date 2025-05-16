"""
When a test (in tests/aws) is executed against AWS, we want to track the date of the last successful run.

Keeping a record of how long ago a test was validated last,
we can periodically re-validate ALL AWS-targeting tests (and therefore not only just snapshot-using tests).
"""

import datetime
import json
import os
from pathlib import Path
from typing import Dict, Optional

import pytest
from _pytest.stash import StashKey

from localstack.testing.aws.util import is_aws_cloud

durations_key = StashKey[Dict[str, float]]()
"""
Used to store information on the test node between execution phases.
See https://docs.pytest.org/en/latest/reference/reference.html#pytest.Stash
"""


def find_validation_data_for_item(item: pytest.Item) -> Optional[dict]:
    base_path = os.path.join(item.fspath.dirname, item.fspath.purebasename)
    snapshot_path = f"{base_path}.validation.json"

    if not os.path.exists(snapshot_path):
        return None

    with open(snapshot_path, "r") as fd:
        file_content = json.load(fd)
        return file_content.get(item.nodeid)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    report = yield

    # only update the file when running against AWS and the test finishes successfully
    if not is_aws_cloud() or call.excinfo:
        return report

    # this hook is run 3 times: on test setup, call and teardown
    execution_phase = call.when

    item.stash.setdefault(durations_key, {})
    item.stash[durations_key][execution_phase] = round(call.duration, 2)

    # only write to file after the teardown phase
    if execution_phase != "teardown":
        return report

    base_path = os.path.join(item.fspath.dirname, item.fspath.purebasename)
    file_path = Path(f"{base_path}.validation.json")
    file_path.touch()
    with file_path.open(mode="r+") as fd:
        # read existing state from file
        try:
            content = json.load(fd)
        except json.JSONDecodeError:  # expected on the first try (empty file)
            content = {}

        test_execution_data = content.setdefault(item.nodeid, {})

        timestamp = datetime.datetime.now(tz=datetime.timezone.utc)
        test_execution_data["last_validated_date"] = timestamp.isoformat(timespec="seconds")

        durations_by_phase = item.stash[durations_key]
        test_execution_data["durations_by_phase"] = durations_by_phase

        total_duration = sum(durations_by_phase.values())
        test_execution_data["total_duration"] = round(total_duration, 2)

        # For json.dump sorted test entries enable consistent diffs.
        # But test execution data is more readable in insert order for each step (setup, call, teardown).
        # Hence, not using global sort_keys=True for json.dump but rather additionally sorting top-level dict only.
        content = dict(sorted(content.items()))

        # save updates
        fd.truncate(0)  # clear existing content
        fd.seek(0)
        json.dump(content, fd, indent=2)
        fd.write("\n")  # add trailing newline for linter and Git compliance

    return report


@pytest.hookimpl
def pytest_addoption(parser: pytest.Parser, pluginmanager: pytest.PytestPluginManager):
    parser.addoption("--validation-date-limit-days", action="store")
    parser.addoption("--validation-date-limit-timestamp", action="store")


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(
    session: pytest.Session, config: pytest.Config, items: list[pytest.Item]
):
    """
    Collect only items that have a validation timestamp earlier than the user-provided reference timestamp

    Example usage:
    - pytest ... --validation-date-limit-days=10
    - pytest ... --validation-date-limit-timestamp="2023-12-01T00:00:00"

    """
    # handle two potential config options (relative vs. absolute limits)
    if config.option.validation_date_limit_days is not None:
        reference_date = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
            days=int(config.option.validation_date_limit_days)
        )
    elif config.option.validation_date_limit_timestamp is not None:
        reference_date = datetime.datetime.fromisoformat(
            config.option.validation_date_limit_timestamp
        )
    else:
        return

    selected = []  # items to collect
    deselected = []  # items to drop

    for item in items:
        validation_data = find_validation_data_for_item(item)
        if not validation_data:
            deselected.append(item)
            continue

        last_validated_date = datetime.datetime.fromisoformat(
            validation_data["last_validated_date"]
        )

        if last_validated_date < reference_date:
            selected.append(item)
        else:
            deselected.append(item)

    items[:] = selected
    config.hook.pytest_deselected(items=deselected)
