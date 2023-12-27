from pytest import CallInfo, Item, TestReport

# import _pytest.hookspec
# _pytest.hookspec.pytest_runtest_protocol
# _pytest.hookspec.pytest_runtest_call()
# _pytest.hookspec.pytest_runtest_setup()
# _pytest.hookspec.pytest_runtest_makereport()


def pytest_runtest_makereport(item: Item, call: CallInfo[None]) -> TestReport | None:
    # TODO
    pass
