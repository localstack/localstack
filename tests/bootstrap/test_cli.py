import pytest
import requests
from click.testing import CliRunner

from localstack import config, constants
from localstack.cli.localstack import localstack as cli
from localstack.config import get_edge_url, in_docker
from localstack.utils import docker_utils
from localstack.utils.common import poll_condition


@pytest.fixture
def runner():
    return CliRunner()


def container_exists(client, container_name):
    try:
        container_id = client.get_container_id(container_name)
        return True if container_id else False
    except Exception:
        return False


@pytest.fixture(autouse=True)
def container_client():
    client = docker_utils.SdkDockerClient()

    yield client

    try:
        client.stop_container(config.MAIN_CONTAINER_NAME)
    except Exception:
        pass

    # wait until container has been removed
    assert poll_condition(
        lambda: not container_exists(client, config.MAIN_CONTAINER_NAME), timeout=20
    )


@pytest.mark.skipif(condition=in_docker(), reason="cannot run CLI tests in docker")
class TestCliContainerLifecycle:
    def test_start_wait_stop(self, runner, container_client):
        result = runner.invoke(cli, ["start", "-d"])
        assert result.exit_code == 0
        assert "starting LocalStack" in result.output

        result = runner.invoke(cli, ["wait", "-t", "60"])
        assert result.exit_code == 0

        assert container_client.is_container_running(
            config.MAIN_CONTAINER_NAME
        ), "container name was not running after wait"

        health = requests.get(get_edge_url() + "/health")
        assert health.ok, "health request did not return OK: %s" % health.text

        result = runner.invoke(cli, ["stop"])
        assert result.exit_code == 0

        with pytest.raises(requests.ConnectionError):
            requests.get(get_edge_url() + "/health")

    def test_wait_timeout_raises_exception(self, runner, container_client):
        result = runner.invoke(cli, ["start", "-d"])
        assert result.exit_code == 0
        assert "starting LocalStack" in result.output

        result = runner.invoke(cli, ["wait", "-t", "0.5"])
        # one day this test will surely fail ;-)
        assert result.exit_code != 0

    def test_logs(self, runner, container_client):
        result = runner.invoke(cli, ["logs"])
        assert result.exit_code != 0

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        result = runner.invoke(cli, ["logs"])
        assert constants.READY_MARKER_OUTPUT in result.output

    def test_status_services(self, runner):
        result = runner.invoke(cli, ["status", "services"])
        assert result.exit_code != 0
        assert "could not connect to LocalStack health endpoint" in result.output

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        result = runner.invoke(cli, ["status", "services"])

        # just a smoke test
        assert "dynamodb" in result.output
        for line in result.output.splitlines():
            if "dynamodb" in line:
                assert "available" in line

    def test_custom_docker_flags(self, runner, tmp_path, monkeypatch, container_client):
        volume = tmp_path / "volume"
        volume.mkdir()

        monkeypatch.setattr(config, "DOCKER_FLAGS", f"-p 42069 -v {volume}:{volume}")

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        inspect = container_client.inspect_container(config.MAIN_CONTAINER_NAME)
        assert "42069/tcp" in inspect["HostConfig"]["PortBindings"]
        assert f"{volume}:{volume}" in inspect["HostConfig"]["Binds"]
