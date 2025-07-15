import pytest


def write_item(item: pytest.Item, arg, outfile):
    print(f"{arg} {item.nodeid}", file=outfile)


def pytest_collection_modifyitems(session, config, items: list[pytest.Item]):
    with open("/tmp/skippedtests.log", "w") as outfile:
        for item in items:
            if skipped_marker := item.get_closest_marker("skip"):
                for arg in skipped_marker.args:
                    if arg.startswith("CFNV2:"):
                        write_item(item, arg, outfile)
                        break
                # check for reason in kwargs
                for argument_value in skipped_marker.kwargs.values():
                    if argument_value.startswith("CFNV2:"):
                        write_item(item, argument_value, outfile)
                        break
