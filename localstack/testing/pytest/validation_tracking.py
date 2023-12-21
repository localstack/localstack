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
