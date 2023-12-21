"""
When a test (in tests/aws) is executed against AWS, we want to track the date of the last successful run.

Keeping a record of how long ago a test was validated last,
we can periodically re-validate ALL AWS-targeting tests (and therefore not only just snapshot-using tests).
"""

import datetime
import json
import os
from typing import Optional

import pluggy
import pytest

from localstack.testing.aws.util import is_aws_cloud


def find_snapshot_for_item(item: pytest.Item) -> Optional[dict]:
    base_path = os.path.join(item.fspath.dirname, item.fspath.purebasename)
    snapshot_path = f"{base_path}.snapshot.json"

    if not os.path.exists(snapshot_path):
        return None

    with open(snapshot_path, "r") as fd:
        file_content = json.load(fd)
        return file_content.get(item.nodeid)


def find_validation_data_for_item(item: pytest.Item) -> Optional[dict]:
    base_path = os.path.join(item.fspath.dirname, item.fspath.purebasename)
    snapshot_path = f"{base_path}.validation.json"

    if not os.path.exists(snapshot_path):
        return None

    with open(snapshot_path, "r") as fd:
        file_content = json.load(fd)
        return file_content.get(item.nodeid)


def record_passed_validation(item: pytest.Item, timestamp: Optional[datetime.datetime] = None):
    base_path = os.path.join(item.fspath.dirname, item.fspath.purebasename)
    with open(f"{base_path}.validation.json", "w+") as fd:
        # read existing state from file
        try:
            content = json.load(fd)
        except json.JSONDecodeError:  # expected on first try (empty file)
            content = {}

        # update for this pytest node
        if not timestamp:
            timestamp = datetime.datetime.now(tz=datetime.timezone.utc)
        content[item.nodeid] = {"last_validated_date": timestamp.isoformat(timespec="seconds")}

        # save updates
        fd.seek(0)
        json.dump(content, fd, indent=2)


# TODO: we should skip if we're updating snapshots
# make sure this is *AFTER* snapshot comparison => tryfirst=True
@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_call(item: pytest.Item):
    outcome: pluggy.Result = yield

    # we only want to track passed runs against AWS
    if not is_aws_cloud() or outcome.excinfo:
        return

    record_passed_validation(item)


# this is a sort of utility used for retroactively creating validation files in accordance with existing snapshot files
# it takes the recorded date from a snapshot and sets it to the last validated date
# @pytest.hookimpl(trylast=True)
# def pytest_collection_modifyitems(session, config, items: list[pytest.Item]):
#     for item in items:
#         snapshot_entry = find_snapshot_for_item(item)
#         if not snapshot_entry:
#             continue
#
#         snapshot_update_timestamp = datetime.datetime.strptime(snapshot_entry["recorded-date"], "%d-%m-%Y, %H:%M:%S").astimezone(tz=datetime.timezone.utc)
#
#         record_passed_validation(item, snapshot_update_timestamp)


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
