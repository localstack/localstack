import json
import re
import threading

import click
import pytest
from click.testing import CliRunner

from localstack import config, constants
from localstack.cli.localstack import create_with_plugins
from localstack.cli.localstack import localstack as cli
from localstack.utils.common import is_command_available

cli: click.Group


@pytest.fixture
def runner():
    return CliRunner()


def test_create_with_plugins(runner):
    localstack_cli = create_with_plugins()
    result = runner.invoke(localstack_cli.group, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == constants.VERSION


def test_version(runner):
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == constants.VERSION


def test_status_services_error(runner):
    result = runner.invoke(cli, ["status", "services"])
    assert result.exit_code == 1
    assert "ERROR" in result.output


def test_start_docker_is_default(runner, monkeypatch):
    from localstack.utils import bootstrap

    called = threading.Event()

    def mock_call():
        called.set()

    monkeypatch.setattr(bootstrap, "start_infra_in_docker", mock_call)
    runner.invoke(cli, ["start"])
    assert called.is_set()


def test_start_host(runner, monkeypatch):
    from localstack.utils import bootstrap

    called = threading.Event()

    def mock_call():
        called.set()

    monkeypatch.setattr(bootstrap, "start_infra_locally", mock_call)
    runner.invoke(cli, ["start", "--host"])
    assert called.is_set()


def test_status_services(runner, httpserver, monkeypatch):
    monkeypatch.setattr(config, "EDGE_PORT_HTTP", httpserver.port)
    monkeypatch.setattr(config, "EDGE_PORT", httpserver.port)

    services = {"dynamodb": "starting", "s3": "running"}
    httpserver.expect_request("/health", method="GET").respond_with_json({"services": services})

    result = runner.invoke(cli, ["status", "services"])

    assert result.exit_code == 0

    assert "dynamodb" in result.output
    assert "s3" in result.output

    for line in result.output.splitlines():
        if "dynamodb" in line:
            assert "starting" in line
            assert "running" not in line
        if "s3" in line:
            assert "running" in line
            assert "starting" not in line


def test_validate_config(runner, monkeypatch, tmp_path):
    if not is_command_available("docker-compose"):
        pytest.skip("config validation needs the docker-compose command")

    file = tmp_path / "docker-compose.yml"
    file.touch()

    file.write_text(
        """version: "3.3"
services:
  localstack:
    container_name: "${LOCALSTACK_DOCKER_NAME-localstack_main}"
    image: localstack/localstack
    network_mode: bridge
    ports:
      - "127.0.0.1:53:53"
      - "127.0.0.1:53:53/udp"
      - "127.0.0.1:443:443"
      - "127.0.0.1:4566:4566"
      - "127.0.0.1:4571:4571"
    environment:
      - SERVICES=${SERVICES- }
      - DEBUG=${DEBUG- }
      - DATA_DIR=${DATA_DIR- }
      - LAMBDA_EXECUTOR=${LAMBDA_EXECUTOR- }
      - LOCALSTACK_API_KEY=${LOCALSTACK_API_KEY- }
      - KINESIS_ERROR_PROBABILITY=${KINESIS_ERROR_PROBABILITY- }
      - DOCKER_HOST=unix:///var/run/docker.sock
      - HOST_TMP_FOLDER=${TMPDIR}
    volumes:
      - "${TMPDIR:-/tmp/localstack}:/tmp/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
"""
    )

    result = runner.invoke(cli, ["config", "validate", "--file", str(file)])

    assert result.exit_code == 0
    assert "config valid" in result.output


def test_validate_config_syntax_error(runner, monkeypatch, tmp_path):
    if not is_command_available("docker-compose"):
        pytest.skip("config validation needs the docker-compose command")

    file = tmp_path / "docker-compose.yml"
    file.touch()

    file.write_text("foobar.---\n")

    result = runner.invoke(cli, ["config", "validate", "--file", str(file)])

    assert result.exit_code == 1
    assert "error" in result.output


def test_config_show_table(runner):
    result = runner.invoke(cli, ["config", "show"])
    assert result.exit_code == 0
    assert "DATA_DIR" in result.output
    assert "DEBUG" in result.output


def test_config_show_json(runner):
    result = runner.invoke(cli, ["config", "show", "--format=json"])
    assert result.exit_code == 0

    # remove control characters and color/formatting codes like "\x1b[32m"
    output = re.sub(r"\x1b\[[;0-9]+m", "", result.output, flags=re.MULTILINE)
    doc = json.loads(output)
    assert "DATA_DIR" in doc
    assert "DEBUG" in doc
    assert type(doc["DEBUG"]) == bool


def test_config_show_plain(runner, monkeypatch):
    monkeypatch.setenv("DEBUG", "1")
    monkeypatch.setattr(config, "DEBUG", True)

    result = runner.invoke(cli, ["config", "show", "--format=plain"])
    assert result.exit_code == 0

    # using regex here, as output string may contain the color/formatting codes like "\x1b[32m"
    assert re.search(r"DATA_DIR[^=]*=", result.output)
    assert re.search(r"DEBUG[^=]*=(\x1b\[3;92m)?True", result.output)


def test_config_show_dict(runner, monkeypatch):
    monkeypatch.setenv("DEBUG", "1")
    monkeypatch.setattr(config, "DEBUG", True)

    result = runner.invoke(cli, ["config", "show", "--format=dict"])
    assert result.exit_code == 0

    assert "'DATA_DIR'" in result.output
    # using regex here, as output string may contain the color/formatting codes like "\x1b[32m"
    assert re.search(r"'DEBUG'[^:]*: [^']*True", result.output)
