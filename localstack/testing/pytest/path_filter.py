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

from localstack.testing.testselection import SENTINEL_ALL_TESTS, SENTINEL_NO_TEST


def pytest_addoption(parser):
    parser.addoption(
        "--path-filter",
        action="store",
        help="Path to the file containing path substrings for test selection",
    )


# TODO: should we add an explicit order? e.g. first/last?
# tryfirst would IMO make the most sense since I don't see a reason why other plugins should operate on the other tests at all
# @pytest.hookimpl(trylast=True)
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

        # TODO: this is technically redundant since we can just add "tests/" instead as a line item
        if any([p == SENTINEL_ALL_TESTS for p in pathfilter_substrings]):
            return  # at least one change should lead to a full run

        # TODO: can also be redundant / doesn't even need to be checked since the loop below will take care of it
        if all([p == SENTINEL_NO_TEST for p in pathfilter_substrings]):
            items[:] = []
            config.hook.pytest_deselected(items=items)
            return  #  we only got sentinal values that signal a change that doesn't need to be tested, so delesect all

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
