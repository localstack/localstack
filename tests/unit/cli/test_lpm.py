import os.path
from typing import List

import pytest
from click.testing import CliRunner

from localstack.cli.lpm import cli, console
from localstack.services.install import CommunityInstallerRepository, Installer


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
    def failing_installer():
        raise Exception("failing installer")

    def successful_installer():
        pass

    def patched_get_installer(self) -> List[Installer]:
        return [
            ("failing-installer", failing_installer),
            ("successful-installer", successful_installer),
        ]

    monkeypatch.setattr(CommunityInstallerRepository, "get_installer", patched_get_installer)

    result = runner.invoke(cli, ["install", "successful-installer", "failing-installer"])
    assert result.exit_code == 1
    assert "one or more package installations failed." in result.output


@pytest.mark.skip_offline
def test_install_with_package(runner):
    from localstack.services.install import INSTALL_PATH_ELASTICMQ_JAR

    result = runner.invoke(cli, ["install", "elasticmq"])
    assert result.exit_code == 0
    assert os.path.exists(INSTALL_PATH_ELASTICMQ_JAR)
