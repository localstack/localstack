import os.path

import pytest
from click.testing import CliRunner

from localstack.cli.lpm import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_list(runner, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")

    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "elasticmq/community" in result.output


def test_install_with_non_existing_package_fails(runner):
    result = runner.invoke(cli, ["install", "elasticmq", "funny"])
    assert result.exit_code == 1
    assert "unable to locate installer for package funny"


def test_install_with_package(runner):
    from localstack.services.install import INSTALL_PATH_ELASTICMQ_JAR

    result = runner.invoke(cli, ["install", "elasticmq"])
    assert result.exit_code == 0
    assert os.path.exists(INSTALL_PATH_ELASTICMQ_JAR)
