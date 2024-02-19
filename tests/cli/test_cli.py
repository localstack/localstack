import json
import logging
import os.path
import socket
from contextlib import closing

import pytest
import requests
from click.testing import CliRunner

import localstack.utils.container_utils.docker_cmd_client
from localstack import config, constants
from localstack.cli.localstack import localstack as cli
from localstack.config import Directories, in_docker
from localstack.constants import LOCALHOST_HOSTNAME, LOCALHOST_IP, MODULE_MAIN_PATH, TRUE_STRINGS
from localstack.utils import bootstrap
from localstack.utils.bootstrap import in_ci
from localstack.utils.common import poll_condition
from localstack.utils.container_utils.container_client import ContainerClient, NoSuchImage
from localstack.utils.files import mkdir
from localstack.utils.net import get_free_udp_port, send_dns_query
from localstack.utils.run import run, to_str

LOG = logging.getLogger(__name__)


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


@pytest.fixture
def backup_and_remove_image(monkeypatch, container_client: ContainerClient):
    """
    To test whether the image is pulled correctly, we must remove the image.
    However we do not want to do this and remove the current image, so "back it
    up" - i.e. tag it with another tag, and restore it afterwards.
    """

    source_image_name = f"{constants.DOCKER_IMAGE_NAME}:latest"
    tagged_image_name = f"{constants.DOCKER_IMAGE_NAME}:backup"
    container_client.tag_image(source_image_name, tagged_image_name)
    container_client.remove_image(source_image_name, force=True)
    monkeypatch.setenv("IMAGE_NAME", source_image_name)

    yield

    container_client.tag_image(tagged_image_name, source_image_name)


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

        # Note: if `LOCALSTACK_HOST` is set to a domain that does not resolve to `127.0.0.1` then
        # this test will fail
        health = requests.get(config.external_service_url() + "/_localstack/health")
        assert health.ok, "health request did not return OK: %s" % health.text

        result = runner.invoke(cli, ["stop"])
        assert result.exit_code == 0

        with pytest.raises(requests.ConnectionError):
            requests.get(config.external_service_url() + "/_localstack/health")

    @pytest.mark.usefixtures("backup_and_remove_image")
    def test_pulling_image_message(self, runner, container_client: ContainerClient):
        image_name_and_tag = f"{constants.DOCKER_IMAGE_NAME}:latest"
        with pytest.raises(NoSuchImage):
            container_client.inspect_image(image_name_and_tag, pull=False)

        result = runner.invoke(cli, ["start", "-d"])

        assert result.exit_code == 0, result.output

        # we cannot check for "Pulling container image" which would be more accurate
        # since it is printed in a temporary status line and may not be present in
        # the output if the docker pull is fast enough, but we can check for the
        # presence of another message which is present when pulling the image.
        assert "download complete" in result.output

    def test_start_already_running(self, runner, container_client):
        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "180"])
        result = runner.invoke(cli, ["start"])
        assert container_exists(container_client, config.MAIN_CONTAINER_NAME)
        assert result.exit_code == 1
        assert "Error" in result.output
        assert "is already running" in result.output

    def test_wait_timeout_raises_exception(self, runner, container_client):
        # assume a wait without start fails
        result = runner.invoke(cli, ["wait", "-t", "0.5"])
        assert result.exit_code != 0

    def test_logs(self, runner, container_client):
        result = runner.invoke(cli, ["logs"])
        assert result.exit_code != 0

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        result = runner.invoke(cli, ["logs", "--tail", "20"])
        assert constants.READY_MARKER_OUTPUT in result.output.splitlines()

    def test_restart(self, runner, container_client):
        result = runner.invoke(cli, ["restart"])
        assert result.exit_code != 0

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        result = runner.invoke(cli, ["restart"])
        assert result.exit_code == 0
        assert "restarted" in result.output

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
            volume_dir = "/home/runner/.cache/localstack/volume/"
            mkdir(volume_dir)
            run(["sudo", "chmod", "-R", "777", volume_dir])

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        cmd = ["awslocal", "stepfunctions", "list-state-machines"]
        output = container_client.exec_in_container(config.MAIN_CONTAINER_NAME, cmd)
        result = json.loads(output[0])
        assert "stateMachines" in result

        output = container_client.exec_in_container(config.MAIN_CONTAINER_NAME, ["ps", "-fu", user])
        assert "localstack-supervisor" in to_str(output[0])

    def test_start_cli_within_container(self, runner, container_client, tmp_path):
        output = container_client.run_container(
            # CAVEAT: Updates to the Docker image are not immediately reflected when using the latest image from
            # DockerHub in the CI. Re-build the Docker image locally through `make docker-build` for local testing.
            "localstack/localstack",
            remove=True,
            entrypoint="",
            command=["bin/localstack", "start", "-d"],
            mount_volumes=[
                ("/var/run/docker.sock", "/var/run/docker.sock"),
                (MODULE_MAIN_PATH, "/opt/code/localstack/localstack"),
            ],
            env_vars={"LOCALSTACK_VOLUME_DIR": f"{tmp_path}/ls-volume"},
        )
        stdout = to_str(output[0])
        assert "starting LocalStack" in stdout
        assert "detaching" in stdout

        # assert that container is running
        runner.invoke(cli, ["wait", "-t", "60"])


@pytest.mark.skipif(condition=in_docker(), reason="cannot run CLI tests in docker")
class TestDNSServer:
    def test_dns_port_published(self, runner, container_client, monkeypatch):
        port = get_free_udp_port()
        monkeypatch.setenv("DEBUG", "1")
        monkeypatch.setenv("DNS_PORT", str(port))
        monkeypatch.setattr(config, "DNS_PORT", port)

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        inspect = container_client.inspect_container(config.MAIN_CONTAINER_NAME)
        assert f"{port}/udp" in inspect["HostConfig"]["PortBindings"]

    @pytest.mark.skip(reason="For this change, the tests run on the previous image")
    def test_dns_server_custom_port(self, runner, container_client, monkeypatch):
        port = get_free_udp_port()
        monkeypatch.setenv("DEBUG", "1")
        monkeypatch.setenv("DNS_PORT", str(port))
        monkeypatch.setattr(config, "DNS_PORT", port)

        runner.invoke(cli, ["start", "-d"])
        runner.invoke(cli, ["wait", "-t", "60"])

        reply = send_dns_query(name=LOCALHOST_HOSTNAME, port=port)
        assert str(reply.a.rdata) == LOCALHOST_IP

    @pytest.mark.skip(reason="For this change, the tests run on the previous image")
    def test_dns_server_starts_if_host_port_bound(
        self, runner, container_client, monkeypatch, dns_query_from_container
    ):
        port = get_free_udp_port()
        monkeypatch.setenv("DEBUG", "1")
        monkeypatch.setenv("DNS_PORT", str(port))
        monkeypatch.setattr(config, "DNS_PORT", port)

        # bind the port
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", port))

        with closing(s):
            runner.invoke(cli, ["start", "-d"])
            runner.invoke(cli, ["wait", "-t", "60"])

            inspect = container_client.inspect_container(config.MAIN_CONTAINER_NAME)
            assert f"{port}/udp" not in inspect["HostConfig"]["PortBindings"]
            ip_address = list(inspect["NetworkSettings"]["Networks"].values())[0]["IPAddress"]

            with pytest.raises(TimeoutError):
                send_dns_query(name=LOCALHOST_HOSTNAME, port=port)

            # use a docker container to test the DNS
            stdout, _ = dns_query_from_container(
                name=LOCALHOST_HOSTNAME, ip_address=ip_address, port=port
            )
            assert ip_address in stdout.decode().splitlines()


class TestHooks:
    def test_prepare_host_hook_called_with_correct_dirs(self, runner, monkeypatch):
        """
        Assert that the prepare_host(..) hook is called with the appropriate dirs layout (e.g., cache
        dir writeable). Required, for example, for API key activation and local key caching.
        """

        # simulate that we're running in Docker
        monkeypatch.setattr(config, "is_in_docker", True)

        result_configs = []

        def _prepare_host(*args, **kwargs):
            # store the configs that will be passed to prepare_host hooks (Docker status, infra process, dirs layout)
            result_configs.append(
                (config.is_in_docker, os.getenv(constants.LOCALSTACK_INFRA_PROCESS), config.dirs)
            )

        # patch the prepare_host function which calls the hooks
        monkeypatch.setattr(bootstrap, "prepare_host", _prepare_host)

        def noop(*args, **kwargs):
            pass

        # patch start_infra_in_docker to be a no-op (we don't actually want to start the container for this test)
        assert bootstrap.start_infra_in_docker
        monkeypatch.setattr(bootstrap, "start_infra_in_docker", noop)

        # run the 'start' command, which should call the prepare_host hooks
        runner.invoke(cli, ["start"])

        # assert that result configs are as expected
        assert len(result_configs) == 1
        dirs: Directories
        in_docker, is_infra_process, dirs = result_configs[0]
        assert in_docker is False
        assert is_infra_process not in TRUE_STRINGS
        # cache dir should exist and be writeable
        assert os.path.exists(dirs.cache)
        assert os.access(dirs.cache, os.W_OK)


class TestImports:
    """Simple tests to assert that certain code paths can be imported from the CLI"""

    def test_import_venv(self):
        from localstack.utils.venv import VirtualEnvironment

        assert VirtualEnvironment
