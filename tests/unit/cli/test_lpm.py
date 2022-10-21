import os.path

import pytest
from click.testing import CliRunner

from localstack.cli.lpm import cli, console


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.skip_offline
def test_list(runner, monkeypatch):
    monkeypatch.setattr(console, "no_color", True)

    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "elasticmq/community" in result.output


@pytest.mark.skip_offline
def test_install_with_non_existing_package_fails(runner):
    result = runner.invoke(cli, ["install", "elasticmq", "funny"])
    assert result.exit_code == 1
    assert "unable to locate installer for package funny" in result.output


@pytest.mark.skip_offline
def test_install_failure_returns_non_zero_exit_code(runner, monkeypatch):
    # TODO Migrate to new structure
    pass


@pytest.mark.skip_offline
def test_install_with_package(runner):
    from localstack.services.sqs.legacy.packages import elasticmq_package

    # TODO The scope is now mandatory
    result = runner.invoke(cli, ["install", "elasticmq"])
    assert result.exit_code == 0
    assert os.path.exists(elasticmq_package.get_installed_dir())
