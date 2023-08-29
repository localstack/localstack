import pytest

from localstack import config


@pytest.fixture(autouse=True)
def _setup_cli_environment(monkeypatch):
    # normally we are setting LOCALSTACK_CLI in localstack/cli/main.py, which is not actually run in the tests
    monkeypatch.setenv("LOCALSTACK_CLI", "1")
    monkeypatch.setattr(config, "dirs", config.Directories.for_cli())
