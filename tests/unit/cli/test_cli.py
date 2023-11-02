import json
import logging
import sys
import threading
from queue import Queue

import click
import pytest
from click.testing import CliRunner

import localstack.constants
import localstack.utils.analytics.cli
from localstack import config, constants
from localstack.cli.localstack import create_with_plugins, is_frozen_bundle
from localstack.cli.localstack import localstack as cli
from localstack.utils import testutil
from localstack.utils.common import is_command_available
from localstack.utils.container_utils.container_client import ContainerException, DockerNotAvailable

cli: click.Group


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.parametrize(
    "exception,expected_message",
    [
        (KeyboardInterrupt(), "Aborted!"),
        (DockerNotAvailable(), "Docker could not be found on the system"),
        (ContainerException("example message"), "example message"),
        (click.ClickException("example message"), "example message"),
        (click.exceptions.Exit(code=1), ""),
    ],
)
def test_error_handling(runner: CliRunner, monkeypatch, exception, expected_message):
    """Test different globally handled exceptions, their status code, and error message."""

    def mock_call(*args, **kwargs):
        raise exception

    from localstack.utils import bootstrap

    monkeypatch.setattr(bootstrap, "start_infra_locally", mock_call)
    result = runner.invoke(cli, ["start", "--host"])
    assert result.exit_code == 1
    assert expected_message in result.output


def test_error_handling_help(runner):
    """Make sure the help command is not interpreted as an error (Exit exception is raised)."""
    result = runner.invoke(cli, ["-h"])
    assert result.exit_code == 0
    assert "Usage: localstack" in result.output


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
    assert "Error" in result.output


@pytest.mark.parametrize("command", ["ssh", "stop"])
def test_container_not_runnin_error(runner, command):
    result = runner.invoke(cli, [command])
    assert result.exit_code == 1
    assert "Error" in result.output
    assert "Expected a running LocalStack container" in result.output


def test_start_docker_is_default(runner, monkeypatch):
    from localstack.utils import bootstrap

    called = threading.Event()

    def mock_call(*args, **kwargs):
        called.set()

    monkeypatch.setattr(bootstrap, "start_infra_in_docker", mock_call)
    runner.invoke(cli, ["start"])
    assert called.is_set()


def test_start_host(runner, monkeypatch):
    from localstack.utils import bootstrap

    called = threading.Event()

    def mock_call(*args, **kwargs):
        called.set()

    monkeypatch.setattr(bootstrap, "start_infra_locally", mock_call)
    runner.invoke(cli, ["start", "--host"])
    assert called.is_set()


def test_status_services(runner, httpserver, monkeypatch):
    # TODO: legacy API, switch to use GATEWAY_LISTEN in the next step
    monkeypatch.setattr(config, "EDGE_PORT_HTTP", httpserver.port)
    monkeypatch.setattr(config, "EDGE_PORT", httpserver.port)

    services = {"dynamodb": "starting", "s3": "running"}
    httpserver.expect_request("/_localstack/health", method="GET").respond_with_json(
        {"services": services}
    )

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
    container_name: "${LOCALSTACK_DOCKER_NAME-localstack-main}"
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
    assert "Error" in result.output


@pytest.mark.parametrize(
    "cli_input,expected_cmd,expected_params",
    [
        ("stop", "localstack stop", []),
        ("config show", "localstack config show", ["format_"]),
        ("--debug config show --format plain", "localstack config show", ["format_"]),
    ],
)
def test_publish_analytics_event_on_command_invocation(
    cli_input, expected_cmd, expected_params, runner, monkeypatch, caplog
):
    # must suppress pytest logging due to weird issue with click https://github.com/pytest-dev/pytest/issues/3344
    caplog.set_level(logging.CRITICAL)
    monkeypatch.setattr(localstack.utils.analytics.cli, "ANALYTICS_API_RESPONSE_TIMEOUT_SECS", 3)
    request_data = Queue()
    input = cli_input.split(" ")

    def handler(request, data):
        request_data.put((request.__dict__, data))

    with testutil.http_server(handler) as url:
        monkeypatch.setenv("ANALYTICS_API", url)
        monkeypatch.setattr(localstack.constants, "ANALYTICS_API", url)
        runner.invoke(cli, input)
        _, request_payload = request_data.get(timeout=5)

    assert request_data.qsize() == 0
    payload = json.loads(request_payload)
    events = payload["events"]
    assert len(events) == 1
    event = events[0]
    metadata = event["metadata"]
    assert "client_time" in metadata
    assert "session_id" in metadata
    assert event["name"] == "cli_cmd"
    assert event["payload"]["cmd"] == expected_cmd
    assert event["payload"]["params"] == expected_params


@pytest.mark.parametrize(
    "cli_input",
    [
        "invalid",
        "status services",
        "config show --format invalid",
    ],
)
def test_do_not_publish_analytics_event_on_invalid_command_invocation(
    cli_input, runner, monkeypatch, caplog
):
    # must suppress pytest logging due to weird issue with click https://github.com/pytest-dev/pytest/issues/3344
    caplog.set_level(logging.CRITICAL)
    monkeypatch.setattr(localstack.utils.analytics.cli, "ANALYTICS_API_RESPONSE_TIMEOUT_SECS", 3)
    request_data = []
    input = cli_input.split(" ")

    def handler(request, data):
        request_data.append(data)

    with testutil.http_server(handler) as url:
        monkeypatch.setenv("ANALYTICS_API", url)
        runner.invoke(cli, input)
        assert (
            len(request_data) == 0
        ), "analytics API should not be invoked when an invalid command is supplied"


def test_disable_publish_analytics_event_on_command_invocation(runner, monkeypatch, caplog):
    # must suppress pytest logging due to weird issue with click https://github.com/pytest-dev/pytest/issues/3344
    caplog.set_level(logging.CRITICAL)
    monkeypatch.setattr(localstack.utils.analytics.cli, "ANALYTICS_API_RESPONSE_TIMEOUT_SECS", 3)
    monkeypatch.setattr(localstack.config, "DISABLE_EVENTS", True)
    request_data = []

    def handler(request, data):
        request_data.append(data)

    with testutil.http_server(handler) as url:
        monkeypatch.setenv("ANALYTICS_API", url)
        runner.invoke(cli, ["config", "show"])
        assert (
            len(request_data) == 0
        ), "analytics API should not be invoked when DISABLE_EVENTS is set"


def test_timeout_publishing_command_invocation(runner, monkeypatch, caplog):
    # must suppress pytest logging due to weird issue with click https://github.com/pytest-dev/pytest/issues/3344
    caplog.set_level(logging.CRITICAL)
    monkeypatch.setattr(
        # simulate slow API call by turning timeout way down
        localstack.utils.analytics.cli,
        "ANALYTICS_API_RESPONSE_TIMEOUT_SECS",
        0.001,
    )
    request_data = []

    def handler(request, data):
        request_data.append(data)

    with testutil.http_server(handler) as url:
        monkeypatch.setenv("ANALYTICS_API", url)
        runner.invoke(cli, ["config", "show"])
        assert (
            len(request_data) == 0
        ), "analytics event publisher process should time out if request is taking too long"


def test_is_frozen(monkeypatch):
    # mimic a frozen pyinstaller binary according to https://pyinstaller.org/en/stable/runtime-information.html
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", "/absolute/path/to/bundle/folder", raising=False)
    assert is_frozen_bundle()


def test_not_is_frozen(monkeypatch):
    # mimic running from source
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert not is_frozen_bundle()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    assert not is_frozen_bundle()


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion(monkeypatch, runner, shell: str):
    test_binary_name = "testbinaryname"
    monkeypatch.setattr(localstack.config, "DISABLE_EVENTS", True)
    monkeypatch.setattr(sys, "argv", [test_binary_name])
    result = runner.invoke(cli, ["completion", shell])
    assert result.exit_code == 0
    assert f"_{test_binary_name.upper()}_COMPLETE={shell}_complete" in result.output


def test_completion_unknown_shell(monkeypatch, runner):
    monkeypatch.setattr(localstack.config, "DISABLE_EVENTS", True)
    result = runner.invoke(cli, ["completion", "unknown_shell"])
    assert result.exit_code != 0
