"""
A pytest plugin that limits test selection based on an input file.
The input file is a plaintext file with one subpath entry per line.
After gathering all potential tests, the candidates are filtered by matching with these entries.
At least one entry has to match for the test to be included in the test run.

Example usage: `pytest --path-filter=test_selection.txt`

File content of `test_selection.txt`:

```
tests/mymodule/
tests/myothermodule/test_conrete_thing.py
```

There are also special values that represent
a) SENTINEL_NO_TEST: change is not classified (=> run everything)
b) SENTINEL_ALL_TESTS: change that is explicitly classified but doesn't require running a test

If all detected changes are in category b) there will be NO tests executed (!).
If any change in category a) is detected, ALL tests will be executed.

"""

import os

import pytest
from _pytest.main import Session

from localstack.testing.testselection.matching import SENTINEL_ALL_TESTS, SENTINEL_NO_TEST


def pytest_addoption(parser):
    parser.addoption(
        "--path-filter",
        action="store",
        help="Path to the file containing path substrings for test selection",
    )


# tryfirst would IMO make the most sense since I don't see a reason why other plugins should operate on the other tests at all
# the pytest-split plugin is executed with trylast=True, so it should come after this one
@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    pathfilter_file = config.getoption("--path-filter")
    if not pathfilter_file:
        return

    if not os.path.exists(pathfilter_file):
        raise ValueError(f"Pathfilter file does not exist: {pathfilter_file}")

    with open(pathfilter_file, "r") as f:
        pathfilter_substrings = [line.strip() for line in f.readlines() if line.strip()]

        if not pathfilter_substrings:
            return  # No filtering if the list is empty => full test suite

        # this is technically redundant since we can just add "tests/" instead as a line item. still prefer to be explicit here
        if any(p == SENTINEL_ALL_TESTS for p in pathfilter_substrings):
            return  # at least one change should lead to a full run

        # technically doesn't even need to be checked since the loop below will take care of it
        if all(p == SENTINEL_NO_TEST for p in pathfilter_substrings):
            items[:] = []
            #  we only got sentinal values that signal a change that doesn't need to be tested, so delesect all
            config.hook.pytest_deselected(items=items)
            return

        # Filter tests based on the path substrings
        selected = []
        deselected = []
        for item in items:
            if any(substr in item.fspath.strpath for substr in pathfilter_substrings):
                selected.append(item)
            else:
                deselected.append(item)

        # Update list of test items to only those selected
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)


def pytest_sessionfinish(session: Session, exitstatus):
    """
    Tests might be split and thus there can be splits which don't select any tests right now

    This is only applied if we're actually using the plugin
    """
    pathfilter_file = session.config.getoption("--path-filter")
    if pathfilter_file and exitstatus == 5:
        session.exitstatus = 0
