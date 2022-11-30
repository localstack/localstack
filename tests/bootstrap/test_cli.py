import json
import os.path

import pytest
import requests
from click.testing import CliRunner

import localstack.utils.container_utils.docker_cmd_client
from localstack import config, constants
from localstack.cli.localstack import localstack as cli
from localstack.config import DOCKER_SOCK, get_edge_url, in_docker
from localstack.constants import MODULE_MAIN_PATH
from localstack.utils.bootstrap import in_ci
from localstack.utils.common import poll_condition
from localstack.utils.files import mkdir
from localstack.utils.run import run, to_str


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
    client = localstack.utils.container_utils.docker_cmd_client.CmdDockerClient()

    yield client

    try:
        client.stop_container(config.MAIN_CONTAINER_NAME, timeout=5)
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

        health = requests.get(get_edge_url() + "/_localstack/health")
        assert health.ok, "health request did not return OK: %s" % health.text

        result = runner.invoke(cli, ["stop"])
        assert result.exit_code == 0

        with pytest.raises(requests.ConnectionError):
            requests.get(get_edge_url() + "/_localstack/health")

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

    @pytest.mark.skipif(
        condition=not config.LEGACY_DIRECTORIES, reason="this test targets LEGACY_DIRECTORIES=1"
    )
    def test_directories_mounted_correctly(self, runner, tmp_path, monkeypatch, container_client):
        data_dir = tmp_path / "data_dir"
        tmp_folder = tmp_path / "tmp"

        # set different directories and make sure they are mounted correctly
        monkeypatch.setenv("DATA_DIR", str(data_dir))
        monkeypatch.setattr(config, "DATA_DIR", str(data_dir))
        monkeypatch.setattr(config, "TMP_FOLDER", str(tmp_folder))
        # reload directories from manipulated config
        monkeypatch.setattr(config, "dirs", config.Directories.legacy_from_config())

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        # check that mounts were created correctly
        inspect = container_client.inspect_container(config.MAIN_CONTAINER_NAME)
        container_dirs = config.Directories.for_container()
        binds = inspect["HostConfig"]["Binds"]
        assert f"{tmp_folder}:{container_dirs.tmp}" in binds
        assert f"{data_dir}:{container_dirs.data}" in binds
        assert f"{DOCKER_SOCK}:{DOCKER_SOCK}" in binds

    @pytest.mark.skipif(
        condition=config.LEGACY_DIRECTORIES, reason="this test targets LEGACY_DIRECTORIES=0"
    )
    def test_volume_dir_mounted_correctly(self, runner, tmp_path, monkeypatch, container_client):
        volume_dir = tmp_path / "volume"

        # set different directories and make sure they are mounted correctly
        monkeypatch.setenv("LOCALSTACK_VOLUME_DIR", str(volume_dir))
        monkeypatch.setattr(config, "VOLUME_DIR", str(volume_dir))

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        # check that mounts were created correctly
        inspect = container_client.inspect_container(config.MAIN_CONTAINER_NAME)
        binds = inspect["HostConfig"]["Binds"]
        assert f"{volume_dir}:{constants.DEFAULT_VOLUME_DIR}" in binds

    def test_container_starts_non_root(self, runner, monkeypatch, container_client):
        user = "localstack"
        monkeypatch.setattr(config, "DOCKER_FLAGS", f"--user={user}")

        if in_ci() and os.path.exists("/home/runner"):
            logs_dir = "/home/runner/.cache/localstack/volume/logs"
            mkdir(logs_dir)
            run(["sudo", "chmod", "-R", "777", logs_dir])

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        cmd = ["awslocal", "stepfunctions", "list-state-machines"]
        output = container_client.exec_in_container(config.MAIN_CONTAINER_NAME, cmd)
        result = json.loads(output[0])
        assert "stateMachines" in result

        output = container_client.exec_in_container(config.MAIN_CONTAINER_NAME, ["ps", "-u", user])
        assert "supervisord" in to_str(output[0])

    def test_start_cli_within_container(self, runner, container_client):
        output = container_client.run_container(
            "localstack/localstack",
            remove=True,
            entrypoint="",
            command=["bin/localstack", "start", "-d"],
            mount_volumes=[
                ("/var/run/docker.sock", "/var/run/docker.sock"),
                (MODULE_MAIN_PATH, "/opt/code/localstack/localstack"),
            ],
            env_vars={"LOCALSTACK_VOLUME_DIR": "/tmp/ls-volume"},
        )
        stdout = to_str(output[0])
        assert "starting LocalStack" in stdout
        assert "detaching" in stdout

        # assert that container is running
        runner.invoke(cli, ["wait", "-t", "60"])
