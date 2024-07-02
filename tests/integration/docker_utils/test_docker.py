import datetime
import ipaddress
import json
import logging
import os
import re
import textwrap
import time
from typing import NamedTuple, Type

import pytest
from docker.models.containers import Container

from localstack import config
from localstack.config import in_docker
from localstack.testing.pytest import markers
from localstack.utils import docker_utils
from localstack.utils.common import is_ipv4_address, save_file, short_uid, to_str
from localstack.utils.container_utils.container_client import (
    AccessDenied,
    ContainerClient,
    ContainerException,
    DockerContainerStatus,
    DockerNotAvailable,
    LogConfig,
    NoSuchContainer,
    NoSuchImage,
    NoSuchNetwork,
    PortMappings,
    RegistryConnectionError,
    Ulimit,
    Util,
    VolumeInfo,
)
from localstack.utils.container_utils.docker_cmd_client import CmdDockerClient
from localstack.utils.container_utils.docker_sdk_client import SdkDockerClient
from localstack.utils.docker_utils import (
    container_ports_can_be_bound,
    is_container_port_reserved,
    is_port_available_for_containers,
    reserve_available_container_port,
    reserve_container_port,
)
from localstack.utils.net import Port, PortNotAvailableException, get_free_tcp_port
from localstack.utils.strings import to_bytes
from localstack.utils.sync import retry
from localstack.utils.threads import FuncThread
from tests.integration.docker_utils.conftest import is_podman_test, skip_for_podman

ContainerInfo = NamedTuple(
    "ContainerInfo",
    [
        ("container_id", str),
        ("container_name", str),
    ],
)

LOG = logging.getLogger(__name__)

container_name_prefix = "lst_test_"


def _random_container_name() -> str:
    return f"{container_name_prefix}{short_uid()}"


def _is_podman_test() -> bool:
    """Return whether this is a test running against Podman"""
    return os.getenv("DOCKER_CMD") == "podman"


@pytest.fixture
def dummy_container(create_container):
    """Returns a container that is created but not started"""
    return create_container("alpine", command=["sh", "-c", "while true; do sleep 1; done"])


@pytest.fixture
def create_container(docker_client: ContainerClient, create_network):
    """
    Uses the factory as fixture pattern to wrap ContainerClient.create_container as a factory that
    removes the containers after the fixture is cleaned up.

    Depends on create network for correct cleanup order
    """
    containers = []

    def _create_container(image_name: str, **kwargs):
        kwargs["name"] = kwargs.get("name", _random_container_name())
        cid = docker_client.create_container(image_name, **kwargs)
        cid = cid.strip()
        containers.append(cid)
        return ContainerInfo(cid, kwargs["name"])  # FIXME name should come from docker_client

    yield _create_container

    for c in containers:
        try:
            docker_client.remove_container(c)
        except Exception:
            LOG.warning("failed to remove test container %s", c)


@pytest.fixture
def create_network(docker_client: ContainerClient):
    """
    Uses the factory as fixture pattern to wrap the creation of networks as a factory that
    removes the networks after the fixture is cleaned up.
    """
    networks = []

    def _create_network(network_name: str):
        network_id = docker_client.create_network(network_name=network_name)
        networks.append(network_id)
        return network_id

    yield _create_network

    for network in networks:
        try:
            LOG.debug("Removing network %s", network)
            docker_client.delete_network(network_name=network)
        except ContainerException as e:
            LOG.debug("Error while cleaning up network %s: %s", network, e)


class TestDockerClient:
    def test_get_system_info(self, docker_client: ContainerClient):
        info = docker_client.get_system_info()
        assert "ID" in info
        assert "OperatingSystem" in info
        assert "Architecture" in info

    def test_get_system_id(self, docker_client: ContainerClient):
        assert len(docker_client.get_system_id()) > 1
        assert docker_client.get_system_id() == docker_client.get_system_id()

    def test_container_lifecycle_commands(self, docker_client: ContainerClient):
        container_name = _random_container_name()
        output = docker_client.create_container(
            "alpine",
            name=container_name,
            command=["sh", "-c", "for i in `seq 30`; do sleep 1; echo $i; done"],
        )
        container_id = output.strip()
        assert container_id

        try:
            docker_client.start_container(container_id)
            assert DockerContainerStatus.UP == docker_client.get_container_status(container_name)

            # consider different "paused" statuses for Docker / Podman
            docker_client.pause_container(container_id)
            expected_statuses = (DockerContainerStatus.PAUSED, DockerContainerStatus.DOWN)
            container_status = docker_client.get_container_status(container_name)
            assert container_status in expected_statuses

            docker_client.unpause_container(container_id)
            assert DockerContainerStatus.UP == docker_client.get_container_status(container_name)

            docker_client.restart_container(container_id)
            assert docker_client.get_container_status(container_name) == DockerContainerStatus.UP

            docker_client.stop_container(container_id)
            assert DockerContainerStatus.DOWN == docker_client.get_container_status(container_name)
        finally:
            docker_client.remove_container(container_id)

        assert DockerContainerStatus.NON_EXISTENT == docker_client.get_container_status(
            container_name
        )

    def test_create_container_remove_removes_container(
        self, docker_client: ContainerClient, create_container
    ):
        info = create_container("alpine", remove=True, command=["echo", "foobar"])
        # make sure it was correctly created
        assert 1 == len(docker_client.list_containers(f"id={info.container_id}"))

        # start the container
        output, _ = docker_client.start_container(info.container_id, attach=True)
        output = to_str(output)
        time.sleep(1)  # give the docker daemon some time to remove the container after execution

        assert 0 == len(docker_client.list_containers(f"id={info.container_id}"))

        # it takes a while for it to be removed
        assert "foobar" in output

    @markers.skip_offline
    def test_create_container_non_existing_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.create_container("this_image_does_hopefully_not_exist_42069")

    def test_exec_in_container(
        self, docker_client: ContainerClient, dummy_container: ContainerInfo
    ):
        docker_client.start_container(dummy_container.container_id)

        output, _ = docker_client.exec_in_container(
            dummy_container.container_id, command=["echo", "foobar"]
        )
        output = to_str(output)
        assert "foobar" == output.strip()

    def test_exec_in_container_not_running_raises_exception(
        self, docker_client: ContainerClient, dummy_container
    ):
        with pytest.raises(ContainerException):
            # can't exec into a non-running container
            docker_client.exec_in_container(
                dummy_container.container_id, command=["echo", "foobar"]
            )

    def test_exec_in_container_with_workdir(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        workdir = "/proc/sys"

        output, _ = docker_client.exec_in_container(
            dummy_container.container_id, command=["pwd"], workdir=workdir
        )
        assert to_str(output).strip() == workdir

    def test_exec_in_container_with_env(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)

        env = {"MYVAR": "foo_var"}

        output, _ = docker_client.exec_in_container(
            dummy_container.container_id, env_vars=env, command=["env"]
        )
        output = output.decode(config.DEFAULT_ENCODING)
        assert "MYVAR=foo_var" in output

    @skip_for_podman
    def test_exec_in_container_with_env_deletion(
        self, docker_client: ContainerClient, create_container
    ):
        container_info = create_container(
            "alpine",
            command=["sh", "-c", "env; while true; do sleep 1; done"],
            env_vars={"MYVAR": "SHOULD_BE_OVERWRITTEN"},
        )
        docker_client.start_container(container_info.container_id)
        log_output = docker_client.get_container_logs(
            container_name_or_id=container_info.container_id
        )
        assert "MYVAR=SHOULD_BE_OVERWRITTEN" in log_output

        env = {"MYVAR": "test123"}
        output, _ = docker_client.exec_in_container(
            container_info.container_id, env_vars=env, command=["env"]
        )
        assert "MYVAR=test123" in to_str(output)

        # TODO: doesn't work for podman CmdDockerClient - check if we're relying on this behavior
        env = {"MYVAR": None}
        output, _ = docker_client.exec_in_container(
            container_info.container_id, env_vars=env, command=["env"]
        )
        assert "MYVAR" not in to_str(output)

    def test_exec_error_in_container(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)

        with pytest.raises(ContainerException) as ex:
            docker_client.exec_in_container(
                dummy_container.container_id, command=["./doesnotexist"]
            )

        # consider different error messages for Docker/Podman
        error_messages = ("doesnotexist: no such file or directory", "No such file or directory")
        assert any(msg in str(ex) for msg in error_messages)

    def test_create_container_with_max_env_vars(
        self, docker_client: ContainerClient, create_container
    ):
        # default ARG_MAX=131072 in Docker
        env = {f"IVAR_{i:05d}": f"VAL_{i:05d}" for i in range(2000)}

        # make sure we're really triggering the relevant code
        assert len(str(dict(env))) >= Util.MAX_ENV_ARGS_LENGTH

        info = create_container("alpine", env_vars=env, command=["env"])
        output, _ = docker_client.start_container(info.container_id, attach=True)
        output = output.decode(config.DEFAULT_ENCODING)

        assert "IVAR_00001=VAL_00001" in output
        assert "IVAR_01000=VAL_01000" in output
        assert "IVAR_01999=VAL_01999" in output

    def test_run_container(self, docker_client: ContainerClient):
        container_name = _random_container_name()
        try:
            output, _ = docker_client.run_container(
                "alpine",
                name=container_name,
                command=["echo", "foobared"],
            )
            output = output.decode(config.DEFAULT_ENCODING)
            assert "foobared" in output
        finally:
            docker_client.remove_container(container_name)

    def test_run_container_error(self, docker_client: ContainerClient):
        container_name = _random_container_name()
        try:
            with pytest.raises(ContainerException):
                docker_client.run_container(
                    "alpine",
                    name=container_name,
                    command=["./doesnotexist"],
                )
        finally:
            docker_client.remove_container(container_name)

    def test_stop_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.stop_container("this_container_does_not_exist")

    def test_restart_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.restart_container("this_container_does_not_exist")

    def test_pause_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.pause_container("this_container_does_not_exist")

    def test_unpause_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.pause_container("this_container_does_not_exist")

    def test_remove_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.remove_container("this_container_does_not_exist", force=False)

    def test_start_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.start_container("this_container_does_not_exist")

    def test_docker_not_available(self, docker_client_class: Type[ContainerClient], monkeypatch):
        monkeypatch.setattr(config, "DOCKER_CMD", "non-existing-binary")
        monkeypatch.setenv("DOCKER_HOST", "/var/run/docker.sock1")
        # initialize the client after mocking the environment
        docker_client = docker_client_class()
        with pytest.raises(DockerNotAvailable):
            # perform a command to trigger the exception
            docker_client.list_containers()

    def test_create_container_with_init(self, docker_client, create_container):
        try:
            container_name = _random_container_name()
            docker_client.create_container(
                "alpine", init=True, command=["sh", "-c", "/bin/true"], name=container_name
            )
            assert docker_client.inspect_container(container_name)["HostConfig"]["Init"]
        finally:
            docker_client.remove_container(container_name)

    def test_run_container_with_init(self, docker_client, create_container):
        try:
            container_name = _random_container_name()
            docker_client.run_container(
                "alpine", init=True, command=["sh", "-c", "/bin/true"], name=container_name
            )
            assert docker_client.inspect_container(container_name)["HostConfig"]["Init"]
        finally:
            docker_client.remove_container(container_name)

    # TODO: currently failing under Podman in CI (works locally under MacOS)
    @pytest.mark.skipif(
        condition=_is_podman_test(),
        reason="Podman get_networks(..) does not return list of networks in CI",
    )
    def test_get_network(self, docker_client: ContainerClient, dummy_container):
        networks = docker_client.get_networks(dummy_container.container_name)
        expected_networks = [_get_default_network()]
        assert networks == expected_networks

    # TODO: skipped due to "Error: "slirp4netns" is not supported: invalid network mode" in CI
    @skip_for_podman
    def test_get_network_multiple_networks(
        self, docker_client: ContainerClient, dummy_container, create_network
    ):
        network_name = f"test-network-{short_uid()}"
        network_id = create_network(network_name)
        docker_client.connect_container_to_network(
            network_name=network_id, container_name_or_id=dummy_container.container_id
        )
        docker_client.start_container(dummy_container.container_id)
        networks = docker_client.get_networks(dummy_container.container_id)
        assert network_name in networks
        assert _get_default_network() in networks
        assert len(networks) == 2

    # TODO: skipped due to "Error: "slirp4netns" is not supported: invalid network mode" in CI
    @skip_for_podman
    def test_get_container_ip_for_network(
        self, docker_client: ContainerClient, dummy_container, create_network
    ):
        network_name = f"test-network-{short_uid()}"
        network_id = create_network(network_name)
        docker_client.connect_container_to_network(
            network_name=network_id, container_name_or_id=dummy_container.container_id
        )
        docker_client.start_container(dummy_container.container_id)
        default_network = _get_default_network()
        result_bridge_network = docker_client.get_container_ipv4_for_network(
            container_name_or_id=dummy_container.container_id, container_network=default_network
        ).strip()
        assert is_ipv4_address(result_bridge_network)
        bridge_network = docker_client.inspect_network(default_network)["IPAM"]["Config"][0][
            "Subnet"
        ]
        assert ipaddress.IPv4Address(result_bridge_network) in ipaddress.IPv4Network(bridge_network)
        result_custom_network = docker_client.get_container_ipv4_for_network(
            container_name_or_id=dummy_container.container_id, container_network=network_name
        ).strip()
        assert is_ipv4_address(result_custom_network)
        assert result_custom_network != result_bridge_network
        custom_network = docker_client.inspect_network(network_name)["IPAM"]["Config"][0]["Subnet"]
        assert ipaddress.IPv4Address(result_custom_network) in ipaddress.IPv4Network(custom_network)

    # TODO: currently failing under Podman
    @pytest.mark.skipif(
        condition=_is_podman_test(),
        reason="Podman inspect_network does not return `Containers` attribute",
    )
    def test_get_container_ip_for_network_wrong_network(
        self, docker_client: ContainerClient, dummy_container, create_network
    ):
        network_name = f"test-network-{short_uid()}"
        create_network(network_name)
        docker_client.start_container(dummy_container.container_id)
        result_bridge_network = docker_client.get_container_ipv4_for_network(
            container_name_or_id=dummy_container.container_id,
            container_network=_get_default_network(),
        ).strip()
        assert is_ipv4_address(result_bridge_network)

        with pytest.raises(ContainerException):
            docker_client.get_container_ipv4_for_network(
                container_name_or_id=dummy_container.container_id, container_network=network_name
            )

    # TODO: currently failing under Podman in CI (works locally under MacOS)
    @pytest.mark.skipif(
        condition=_is_podman_test(),
        reason="Podman get_networks(..) does not return list of networks in CI",
    )
    def test_get_container_ip_for_host_network(
        self, docker_client: ContainerClient, create_container
    ):
        container = create_container(
            "alpine", command=["sh", "-c", "while true; do sleep 1; done"], network="host"
        )
        assert "host" == docker_client.get_networks(container.container_name)[0]
        # host network containers have no dedicated IP, so it will throw an exception here
        with pytest.raises(ContainerException):
            docker_client.get_container_ipv4_for_network(
                container_name_or_id=container.container_name, container_network="host"
            )

    def test_get_container_ip_for_network_non_existent_network(
        self, docker_client: ContainerClient, dummy_container, create_network
    ):
        network_name = f"invalid-test-network-{short_uid()}"
        docker_client.start_container(dummy_container.container_id)
        with pytest.raises(NoSuchNetwork):
            docker_client.get_container_ipv4_for_network(
                container_name_or_id=dummy_container.container_id, container_network=network_name
            )

    # TODO: currently failing under Podman in CI (works locally under MacOS)
    @pytest.mark.skipif(
        condition=_is_podman_test(),
        reason="Podman get_networks(..) does not return list of networks in CI",
    )
    def test_create_with_host_network(self, docker_client: ContainerClient, create_container):
        info = create_container("alpine", network="host")
        network = docker_client.get_networks(info.container_name)
        assert ["host"] == network

    def test_create_with_port_mapping(self, docker_client: ContainerClient, create_container):
        ports = PortMappings()
        ports.add(45122, 22)
        ports.add(45180, 80)
        create_container("alpine", ports=ports)

    def test_create_with_exposed_ports(self, docker_client: ContainerClient, create_container):
        exposed_ports = ["45000", "45001/udp"]
        container = create_container(
            "alpine",
            command=["sh", "-c", "while true; do sleep 1; done"],
            exposed_ports=exposed_ports,
        )
        docker_client.start_container(container.container_id)
        inspection_result = docker_client.inspect_container(container.container_id)
        assert inspection_result["Config"]["ExposedPorts"] == {
            f"{port}/tcp" if "/" not in port else port: {} for port in exposed_ports
        }
        assert inspection_result["NetworkSettings"]["Ports"] == {
            f"{port}/tcp" if "/" not in port else port: None for port in exposed_ports
        }

    @pytest.mark.skipif(
        condition=in_docker(), reason="cannot test volume mounts from host when in docker"
    )
    def test_create_with_volume(self, tmpdir, docker_client: ContainerClient, create_container):
        mount_volumes = [(tmpdir.realpath(), "/tmp/mypath")]

        c = create_container(
            "alpine",
            command=["sh", "-c", "echo 'foobar' > /tmp/mypath/foo.log"],
            mount_volumes=mount_volumes,
        )
        docker_client.start_container(c.container_id)
        assert tmpdir.join("foo.log").isfile(), "foo.log was not created in mounted dir"

    @pytest.mark.skipif(
        condition=in_docker(), reason="cannot test volume mounts from host when in docker"
    )
    @skip_for_podman  # TODO: Volume mounting test currently not working against Podman
    def test_inspect_container_volumes(
        self, tmpdir, docker_client: ContainerClient, create_container
    ):
        mount_volumes = [
            (tmpdir.realpath() / "foo", "/tmp/mypath/foo"),
            ("some_named_volume", "/tmp/mypath/volume"),
        ]

        c = create_container(
            "alpine",
            command=["sh", "-c", "while true; do sleep 1; done"],
            mount_volumes=mount_volumes,
        )
        docker_client.start_container(c.container_id)

        vols = docker_client.inspect_container_volumes(c.container_id)

        # FIXME cmd docker client creates different default permission mode flags
        if isinstance(docker_client, CmdDockerClient):
            vol1 = VolumeInfo(
                type="bind",
                source=f"{tmpdir}/foo",
                destination="/tmp/mypath/foo",
                mode="",
                rw=True,
                propagation="rprivate",
                name=None,
                driver=None,
            )
            vol2 = VolumeInfo(
                type="volume",
                source="/var/lib/docker/volumes/some_named_volume/_data",
                destination="/tmp/mypath/volume",
                mode="z",
                rw=True,
                propagation="",
                name="some_named_volume",
                driver="local",
            )
        else:
            vol1 = VolumeInfo(
                type="bind",
                source=f"{tmpdir}/foo",
                destination="/tmp/mypath/foo",
                mode="rw",
                rw=True,
                propagation="rprivate",
                name=None,
                driver=None,
            )
            vol2 = VolumeInfo(
                type="volume",
                source="/var/lib/docker/volumes/some_named_volume/_data",
                destination="/tmp/mypath/volume",
                mode="rw",
                rw=True,
                propagation="",
                name="some_named_volume",
                driver="local",
            )

        assert vol1 in vols
        assert vol2 in vols

    def test_inspect_container_volumes_with_no_volumes(
        self, docker_client: ContainerClient, dummy_container
    ):
        docker_client.start_container(dummy_container.container_id)
        assert len(docker_client.inspect_container_volumes(dummy_container.container_id)) == 0

    def test_copy_into_container(self, tmpdir, docker_client: ContainerClient, create_container):
        local_path = tmpdir.join("myfile.txt")
        container_path = "/tmp/myfile_differentpath.txt"

        self._test_copy_into_container(
            docker_client,
            create_container,
            ["cat", container_path],
            local_path,
            local_path,
            container_path,
        )

    def test_copy_into_non_existent_container(self, tmpdir, docker_client: ContainerClient):
        local_path = tmpdir.mkdir("test_dir")
        file_path = local_path.join("test_file")
        with file_path.open(mode="w") as fd:
            fd.write("foobared\n")
        with pytest.raises(NoSuchContainer):
            docker_client.copy_into_container(
                f"hopefully_non_existent_container_{short_uid()}", str(file_path), "test_file"
            )

    def test_copy_into_container_without_target_filename(
        self, tmpdir, docker_client: ContainerClient, create_container
    ):
        local_path = tmpdir.join("myfile.txt")
        container_path = "/tmp"

        self._test_copy_into_container(
            docker_client,
            create_container,
            ["cat", "/tmp/myfile.txt"],
            local_path,
            local_path,
            container_path,
        )

    def test_copy_directory_into_container(
        self, tmpdir, docker_client: ContainerClient, create_container
    ):
        local_path = tmpdir.join("fancy_folder")
        local_path.mkdir()

        file_path = local_path.join("myfile.txt")
        container_path = "/tmp/fancy_other_folder"

        self._test_copy_into_container(
            docker_client,
            create_container,
            ["cat", "/tmp/fancy_other_folder/myfile.txt"],
            file_path,
            local_path,
            container_path,
        )

    def _test_copy_into_container(
        self, docker_client, create_container, command, file_path, local_path, container_path
    ):
        c = create_container("alpine", command=command)

        with file_path.open(mode="w") as fd:
            fd.write("foobared\n")

        docker_client.copy_into_container(c.container_name, str(local_path), container_path)

        output, _ = docker_client.start_container(c.container_id, attach=True)
        output = output.decode(config.DEFAULT_ENCODING)

        assert "foobared" in output

    def test_copy_into_container_with_existing_target(
        self, tmpdir, docker_client: ContainerClient, dummy_container
    ):
        local_path = tmpdir.join("myfile.txt")
        container_path = "/tmp/myfile.txt"

        with local_path.open(mode="w") as fd:
            fd.write("foo\n")

        docker_client.start_container(dummy_container.container_id)
        docker_client.exec_in_container(
            dummy_container.container_id, command=["sh", "-c", f"echo bar > {container_path}"]
        )

        out, _ = docker_client.exec_in_container(
            dummy_container.container_id,
            command=[
                "cat",
                "/tmp/myfile.txt",
            ],
        )
        assert "bar" in out.decode(config.DEFAULT_ENCODING)
        docker_client.copy_into_container(
            dummy_container.container_id, str(local_path), container_path
        )
        out, _ = docker_client.exec_in_container(
            dummy_container.container_id,
            command=[
                "cat",
                "/tmp/myfile.txt",
            ],
        )
        assert "foo" in out.decode(config.DEFAULT_ENCODING)

    def test_copy_directory_content_into_container(
        self, tmpdir, docker_client: ContainerClient, dummy_container
    ):
        local_path = tmpdir.join("fancy_folder")
        local_path.mkdir()

        file_path = local_path.join("myfile.txt")
        with file_path.open(mode="w") as fd:
            fd.write("foo\n")
        file_path = local_path.join("myfile2.txt")
        with file_path.open(mode="w") as fd:
            fd.write("bar\n")
        container_path = "/tmp/fancy_other_folder"
        docker_client.start_container(dummy_container.container_id)
        docker_client.exec_in_container(
            dummy_container.container_id, command=["mkdir", "-p", container_path]
        )
        docker_client.copy_into_container(
            dummy_container.container_id, f"{str(local_path)}/.", container_path
        )
        out, _ = docker_client.exec_in_container(
            dummy_container.container_id,
            command=[
                "cat",
                "/tmp/fancy_other_folder/myfile.txt",
                "/tmp/fancy_other_folder/myfile2.txt",
            ],
        )
        assert "foo" in out.decode(config.DEFAULT_ENCODING)
        assert "bar" in out.decode(config.DEFAULT_ENCODING)

    def test_copy_directory_structure_into_container(
        self, tmpdir, docker_client: ContainerClient, create_container
    ):
        container = create_container(
            image_name="public.ecr.aws/lambda/python:3.9",
            entrypoint="",
            command=["sh", "-c", "while true; do sleep 1; done"],
        )
        local_path = tmpdir.join("fancy_folder")
        local_path.mkdir()
        sub_path = local_path.join("inner_folder")
        sub_path.mkdir()
        sub_sub_path = sub_path.join("innerinner_folder")
        sub_sub_path.mkdir()

        file_path = sub_sub_path.join("myfile.txt")
        with file_path.open(mode="w") as fd:
            fd.write("foo\n")
        container_path = "/"
        docker_client.copy_into_container(container.container_id, str(local_path), container_path)
        docker_client.start_container(container.container_id)
        out, _ = docker_client.exec_in_container(
            container.container_id,
            command=[
                "cat",
                "/fancy_folder/inner_folder/innerinner_folder/myfile.txt",
            ],
        )
        assert "foo" in out.decode(config.DEFAULT_ENCODING)

    def test_get_network_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(ContainerException):
            docker_client.get_networks("this_container_does_not_exist")

    def test_list_containers(self, docker_client: ContainerClient, create_container):
        c1 = create_container("alpine", command=["echo", "1"])
        c2 = create_container("alpine", command=["echo", "2"])
        c3 = create_container("alpine", command=["echo", "3"])

        container_list = docker_client.list_containers()

        assert len(container_list) >= 3

        image_names = [info["name"] for info in container_list]

        assert c1.container_name in image_names
        assert c2.container_name in image_names
        assert c3.container_name in image_names

    def test_list_containers_filter_non_existing(self, docker_client: ContainerClient):
        container_list = docker_client.list_containers(filter="id=DOES_NOT_EXST")
        assert 0 == len(container_list)

    def test_list_containers_filter_illegal_filter(self, docker_client: ContainerClient):
        with pytest.raises(ContainerException):
            docker_client.list_containers(filter="illegalfilter=foobar")

    def test_list_containers_filter(self, docker_client: ContainerClient, create_container):
        name_prefix = "filter_tests_"
        cn1 = name_prefix + _random_container_name()
        cn2 = name_prefix + _random_container_name()
        cn3 = name_prefix + _random_container_name()

        c1 = create_container("alpine", name=cn1, command=["echo", "1"])
        c2 = create_container("alpine", name=cn2, command=["echo", "2"])
        c3 = create_container("alpine", name=cn3, command=["echo", "3"])

        # per id
        container_list = docker_client.list_containers(filter=f"id={c2.container_id}")
        assert 1 == len(container_list)
        assert c2.container_id.startswith(container_list[0]["id"])
        assert c2.container_name == container_list[0]["name"]
        # note: Docker returns "created", Podman returns "configured"
        assert container_list[0]["status"] in ["created", "configured"]

        # per name pattern
        container_list = docker_client.list_containers(filter=f"name={name_prefix}")
        assert 3 == len(container_list)
        image_names = [info["name"] for info in container_list]
        assert c1.container_name in image_names
        assert c2.container_name in image_names
        assert c3.container_name in image_names

        # multiple patterns
        container_list = docker_client.list_containers(
            filter=[
                f"id={c1.container_id}",
                f"name={container_name_prefix}",
            ]
        )
        assert 1 == len(container_list)
        assert c1.container_name == container_list[0]["name"]

    def test_list_containers_with_podman_image_ref_format(
        self, docker_client: ContainerClient, create_container, cleanups, monkeypatch
    ):
        # create custom image tag
        image_name = f"alpine:tag-{short_uid()}"
        _pull_image_if_not_exists(docker_client, "alpine")
        docker_client.tag_image("alpine", image_name)
        cleanups.append(lambda: docker_client.remove_image(image_name))

        # apply patch to simulate podman behavior
        container_init_orig = Container.__init__

        def container_init(self, attrs=None, *args, **kwargs):
            # Simulate podman API response, Docker returns "sha:..." for Image, podman returns "<image-name>:<tag>".
            #  See https://github.com/containers/podman/issues/8329
            attrs["Image"] = image_name
            container_init_orig(self, *args, attrs=attrs, **kwargs)

        monkeypatch.setattr(Container, "__init__", container_init)

        # start a container from the custom image tag
        c1 = create_container(image_name, command=["sleep", "3"])
        docker_client.start_container(c1.container_id, attach=False)

        # list containers, assert that container is contained in the list
        container_list = docker_client.list_containers()
        running_containers = [cnt for cnt in container_list if cnt["status"] == "running"]
        assert running_containers
        container_names = [info["name"] for info in container_list]
        assert c1.container_name in container_names

        # assert that get_running_container_names(..) call is successful as well
        container_names = docker_client.get_running_container_names()
        assert len(running_containers) == len(container_names)
        assert c1.container_name in container_names

    def test_get_container_entrypoint(self, docker_client: ContainerClient):
        entrypoint = docker_client.get_image_entrypoint("alpine")
        assert "" == entrypoint

    def test_get_container_entrypoint_non_existing_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.get_image_entrypoint("thisdoesnotexist")

    def test_get_container_entrypoint_not_pulled_image(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            docker_client.remove_image("alpine")
        except ContainerException:
            pass
        entrypoint = docker_client.get_image_entrypoint("alpine")
        assert "" == entrypoint

    def test_get_container_command(self, docker_client: ContainerClient):
        command = docker_client.get_image_cmd("alpine")
        assert ["/bin/sh"] == command

    def test_get_container_command_not_pulled_image(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            docker_client.remove_image("alpine")
        except ContainerException:
            pass
        command = docker_client.get_image_cmd("alpine")
        assert ["/bin/sh"] == command

    def test_get_container_command_non_existing_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("thisdoesnotexist")

    @pytest.mark.parametrize("attach", [True, False])
    def test_create_start_container_with_stdin_to_stdout(
        self, attach: bool, docker_client: ContainerClient
    ):
        if isinstance(docker_client, CmdDockerClient) and _is_podman_test() and not attach:
            # TODO: Podman behavior deviates from Docker if attach=False (prints container ID instead of stdin)
            pytest.skip("Podman output deviates from Docker if attach=False")
        container_name = _random_container_name()
        message = "test_message_stdin"
        try:
            docker_client.create_container(
                "alpine",
                name=container_name,
                interactive=True,
                command=["cat"],
            )

            output, _ = docker_client.start_container(
                container_name, interactive=True, stdin=to_bytes(message), attach=attach
            )
            output = to_str(output)

            assert message == output.strip()
        finally:
            docker_client.remove_container(container_name)

    @pytest.mark.parametrize("attach", [True, False])
    def test_create_start_container_with_stdin_to_file(
        self, tmpdir, attach, docker_client: ContainerClient
    ):
        if isinstance(docker_client, CmdDockerClient) and _is_podman_test() and not attach:
            # TODO: Podman behavior deviates from Docker if attach=False (prints container ID instead of stdin)
            pytest.skip("Podman output deviates from Docker if attach=False")

        container_name = _random_container_name()
        message = "test_message_stdin"
        try:
            docker_client.create_container(
                "alpine",
                name=container_name,
                interactive=True,
                command=["sh", "-c", "cat > test_file"],
            )

            output, _ = docker_client.start_container(
                container_name,
                interactive=True,
                stdin=message.encode(config.DEFAULT_ENCODING),
                attach=attach,
            )
            target_path = tmpdir.join("test_file")
            docker_client.copy_from_container(container_name, str(target_path), "test_file")

            assert message == target_path.read().strip()
        finally:
            docker_client.remove_container(container_name)

    def test_run_container_with_stdin(self, docker_client: ContainerClient):
        container_name = _random_container_name()
        message = "test_message_stdin"
        try:
            output, _ = docker_client.run_container(
                "alpine",
                name=container_name,
                interactive=True,
                stdin=message.encode(config.DEFAULT_ENCODING),
                command=["cat"],
            )

            assert message == output.decode(config.DEFAULT_ENCODING).strip()
        finally:
            docker_client.remove_container(container_name)

    def test_exec_in_container_with_stdin(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        message = "test_message_stdin"
        output, _ = docker_client.exec_in_container(
            dummy_container.container_id,
            interactive=True,
            stdin=message.encode(config.DEFAULT_ENCODING),
            command=["cat"],
        )

        assert message == output.decode(config.DEFAULT_ENCODING).strip()

    def test_exec_in_container_with_stdin_stdout_stderr(
        self, docker_client: ContainerClient, dummy_container
    ):
        docker_client.start_container(dummy_container.container_id)
        message = "test_message_stdin"
        output, stderr = docker_client.exec_in_container(
            dummy_container.container_id,
            interactive=True,
            stdin=message.encode(config.DEFAULT_ENCODING),
            command=["sh", "-c", "cat; >&2 echo stderrtest"],
        )

        assert message == output.decode(config.DEFAULT_ENCODING).strip()
        assert "stderrtest" == stderr.decode(config.DEFAULT_ENCODING).strip()

    def test_run_detached_with_logs(self, docker_client: ContainerClient):
        container_name = _random_container_name()
        message = "test_message"
        try:
            output, _ = docker_client.run_container(
                "alpine",
                name=container_name,
                detach=True,
                command=["echo", message],
            )
            container_id = output.decode(config.DEFAULT_ENCODING).strip()
            logs = docker_client.get_container_logs(container_id)

            assert message == logs.strip()
        finally:
            docker_client.remove_container(container_name)

    def test_get_logs_non_existent_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.get_container_logs("container_hopefully_does_not_exist", safe=False)

        assert "" == docker_client.get_container_logs(
            "container_hopefully_does_not_exist", safe=True
        )

    def test_get_logs(self, docker_client: ContainerClient):
        container_name = _random_container_name()
        try:
            docker_client.run_container(
                "alpine",
                name=container_name,
                detach=True,
                command=["env"],
            )

            logs = docker_client.get_container_logs(container_name)
            assert "PATH=" in logs
            assert "HOSTNAME=" in logs
            assert "HOME=/root" in logs

        finally:
            docker_client.remove_container(container_name)

    def test_stream_logs_non_existent_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.stream_container_logs("container_hopefully_does_not_exist")

    def test_stream_logs(self, docker_client: ContainerClient):
        container_name = _random_container_name()
        try:
            docker_client.run_container(
                "alpine",
                name=container_name,
                detach=True,
                command=["env"],
            )

            stream = docker_client.stream_container_logs(container_name)
            for line in stream:
                line = line.decode("utf-8")
                assert line.split("=")[0] in ["HOME", "PATH", "HOSTNAME"]

            stream.close()

        finally:
            docker_client.remove_container(container_name)

    @markers.skip_offline
    def test_pull_docker_image(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            docker_client.remove_image("alpine")
        except ContainerException:
            pass
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("alpine", pull=False)
        docker_client.pull_image("alpine")
        assert ["/bin/sh"] == docker_client.get_image_cmd("alpine", pull=False)

    @markers.skip_offline
    def test_pull_non_existent_docker_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.pull_image("localstack_non_existing_image_for_tests")

    @markers.skip_offline
    def test_pull_docker_image_with_tag(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            docker_client.remove_image("alpine")
        except ContainerException:
            pass
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("alpine", pull=False)
        docker_client.pull_image("alpine:3.13")
        assert ["/bin/sh"] == docker_client.get_image_cmd("alpine:3.13", pull=False)
        assert "alpine:3.13" in docker_client.inspect_image("alpine:3.13", pull=False)["RepoTags"]

    @markers.skip_offline
    def test_pull_docker_image_with_hash(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            docker_client.remove_image("alpine")
        except ContainerException:
            pass
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("alpine", pull=False)
        docker_client.pull_image(
            "alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a"
        )
        assert ["/bin/sh"] == docker_client.get_image_cmd(
            "alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
            pull=False,
        )
        assert (
            "alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a"
            in docker_client.inspect_image(
                "alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
                pull=False,
            )["RepoDigests"]
        )

    @markers.skip_offline
    def test_run_container_automatic_pull(self, docker_client: ContainerClient):
        try:
            docker_client.remove_image("alpine")
        except ContainerException:
            pass
        message = "test message"
        stdout, _ = docker_client.run_container("alpine", command=["echo", message], remove=True)
        assert message == stdout.decode(config.DEFAULT_ENCODING).strip()

    @markers.skip_offline
    def test_push_non_existent_docker_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.push_image("localstack_non_existing_image_for_tests")

    @markers.skip_offline
    def test_push_access_denied(self, docker_client: ContainerClient):
        with pytest.raises(AccessDenied):
            docker_client.push_image("alpine")
        with pytest.raises(AccessDenied):
            docker_client.push_image("alpine:latest")

    @markers.skip_offline
    def test_push_invalid_registry(self, docker_client: ContainerClient):
        image_name = f"localhost:{get_free_tcp_port()}/localstack_dummy_image"
        try:
            docker_client.tag_image("alpine", image_name)
            with pytest.raises(RegistryConnectionError):
                docker_client.push_image(image_name)
        finally:
            docker_client.remove_image(image_name)

    @markers.skip_offline
    def test_tag_image(self, docker_client: ContainerClient):
        if _is_podman_test() and isinstance(docker_client, SdkDockerClient):
            # TODO: Podman raises "normalizing image: normalizing name for compat API: invalid reference format"
            pytest.skip("Image tagging not fully supported using SDK client against Podman API")

        _pull_image_if_not_exists(docker_client, "alpine")
        img_refs = [
            "localstack_dummy_image",
            "localstack_dummy_image:latest",
            "localstack_dummy_image:test",
            "docker.io/localstack_dummy_image:test2",
            "example.com:4510/localstack_dummy_image:test3",
        ]
        try:
            for img_ref in img_refs:
                docker_client.tag_image("alpine", img_ref)
                images = docker_client.get_docker_image_names(strip_latest=":latest" not in img_ref)
                expected = img_ref.split("/")[-1] if len(img_ref.split(":")) < 3 else img_ref
                assert expected in images
        finally:
            for img_ref in img_refs:
                try:
                    docker_client.remove_image(img_ref)
                except Exception as e:
                    LOG.info("Unable to remove image '%s': %s", img_ref, e)

    @markers.skip_offline
    def test_tag_non_existing_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.tag_image(
                "localstack_non_existing_image_for_tests", "localstack_dummy_image"
            )

    @markers.skip_offline
    @pytest.mark.parametrize("custom_context", [True, False])
    @pytest.mark.parametrize("dockerfile_as_dir", [True, False])
    def test_build_image(
        self, docker_client: ContainerClient, custom_context, dockerfile_as_dir, tmp_path, cleanups
    ):
        if custom_context and is_podman_test():
            # TODO: custom context currently failing with Podman
            pytest.skip("Test not applicable when run against Podman (only Docker)")

        dockerfile_dir = tmp_path / "dockerfile"
        tmp_file = short_uid()
        ctx_dir = tmp_path / "context" if custom_context else dockerfile_dir
        dockerfile_path = os.path.join(dockerfile_dir, "Dockerfile")
        dockerfile = f"""
        FROM alpine
        ADD {tmp_file} .
        ENV foo=bar
        EXPOSE 45329
        """
        save_file(dockerfile_path, dockerfile)
        save_file(os.path.join(ctx_dir, tmp_file), "test content 123")

        kwargs = {"context_path": str(ctx_dir)} if custom_context else {}
        dockerfile_ref = str(dockerfile_dir) if dockerfile_as_dir else dockerfile_path

        image_name = f"img-{short_uid()}"
        docker_client.build_image(dockerfile_path=dockerfile_ref, image_name=image_name, **kwargs)
        cleanups.append(lambda: docker_client.remove_image(image_name, force=True))

        assert image_name in docker_client.get_docker_image_names()
        result = docker_client.inspect_image(image_name, pull=False)
        assert "foo=bar" in result["Config"]["Env"]
        assert "45329/tcp" in result["Config"]["ExposedPorts"]

    @markers.skip_offline
    def test_run_container_non_existent_image(self, docker_client: ContainerClient):
        try:
            docker_client.remove_image("alpine")
        except ContainerException:
            pass
        with pytest.raises(NoSuchImage):
            stdout, _ = docker_client.run_container(
                "localstack_non_existing_image_for_tests", command=["echo", "test"], remove=True
            )

    def test_running_container_names(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        name = dummy_container.container_name
        assert name in docker_client.get_running_container_names()
        docker_client.stop_container(name)
        assert name not in docker_client.get_running_container_names()

    def test_is_container_running(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        name = dummy_container.container_name
        assert docker_client.is_container_running(name)
        docker_client.restart_container(name)
        assert docker_client.is_container_running(name)
        docker_client.stop_container(name)
        assert not docker_client.is_container_running(name)

    @markers.skip_offline
    def test_docker_image_names(self, docker_client: ContainerClient):
        try:
            docker_client.remove_image("alpine")
        except ContainerException:
            pass
        assert "alpine:latest" not in docker_client.get_docker_image_names()
        assert "alpine" not in docker_client.get_docker_image_names()
        docker_client.pull_image("alpine")
        assert "alpine:latest" in docker_client.get_docker_image_names()
        assert "alpine:latest" not in docker_client.get_docker_image_names(include_tags=False)
        assert "alpine" in docker_client.get_docker_image_names(include_tags=False)
        assert "alpine" in docker_client.get_docker_image_names()
        assert "alpine" not in docker_client.get_docker_image_names(strip_latest=False)

    def test_get_container_name(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        assert dummy_container.container_name == docker_client.get_container_name(
            dummy_container.container_id
        )

    def test_get_container_name_not_existing(self, docker_client: ContainerClient):
        not_existent_container = "not_existing_container"
        with pytest.raises(NoSuchContainer):
            docker_client.get_container_name(not_existent_container)

    def test_get_container_id(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        assert dummy_container.container_id == docker_client.get_container_id(
            dummy_container.container_name
        )

    def test_get_container_id_not_existing(self, docker_client: ContainerClient):
        not_existent_container = "not_existing_container"
        with pytest.raises(NoSuchContainer):
            docker_client.get_container_id(not_existent_container)

    def test_inspect_container(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        for identifier in [dummy_container.container_id, dummy_container.container_name]:
            assert dummy_container.container_id == docker_client.inspect_container(identifier)["Id"]
            # considering container names with (Docker) and without (Podman) leading slashes
            candidates = (f"/{dummy_container.container_name}", dummy_container.container_name)
            assert docker_client.inspect_container(identifier)["Name"] in candidates

    @markers.skip_offline
    def test_inspect_image(self, docker_client: ContainerClient):
        _pull_image_if_not_exists(docker_client, "alpine")
        assert "alpine" in docker_client.inspect_image("alpine")["RepoTags"][0]

    # TODO: currently failing under Podman
    @pytest.mark.skipif(
        condition=_is_podman_test(), reason="Podman inspect_network does not return `Id` attribute"
    )
    def test_inspect_network(self, docker_client: ContainerClient, create_network):
        network_name = f"ls_test_network_{short_uid()}"
        network_id = create_network(network_name)
        result = docker_client.inspect_network(network_name)
        assert network_name == result["Name"]
        assert network_id == result["Id"]

    def test_inspect_network_non_existent_network(self, docker_client: ContainerClient):
        network_name = "ls_test_network_non_existent"
        with pytest.raises(NoSuchNetwork):
            docker_client.inspect_network(network_name)

    def test_copy_from_container(self, tmpdir, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        local_path = tmpdir.join("test_file")
        self._test_copy_from_container(
            local_path, local_path, "test_file", docker_client, dummy_container
        )

    def test_copy_from_container_to_different_file(
        self, tmpdir, docker_client: ContainerClient, dummy_container
    ):
        docker_client.start_container(dummy_container.container_id)
        local_path = tmpdir.join("test_file_2")
        self._test_copy_from_container(
            local_path, local_path, "test_file", docker_client, dummy_container
        )

    def test_copy_from_container_into_directory(
        self, tmpdir, docker_client: ContainerClient, dummy_container
    ):
        docker_client.start_container(dummy_container.container_id)
        local_path = tmpdir.mkdir("test_dir")
        file_path = local_path.join("test_file")
        self._test_copy_from_container(
            local_path, file_path, "test_file", docker_client, dummy_container
        )

    def test_copy_from_non_existent_container(self, tmpdir, docker_client: ContainerClient):
        local_path = tmpdir.mkdir("test_dir")
        with pytest.raises(NoSuchContainer):
            docker_client.copy_from_container(
                f"hopefully_non_existent_container_{short_uid()}", str(local_path), "test_file"
            )

    def _test_copy_from_container(
        self,
        local_path,
        file_path,
        container_file_name,
        docker_client: ContainerClient,
        dummy_container,
    ):
        docker_client.exec_in_container(
            dummy_container.container_id,
            command=["sh", "-c", f"echo TEST_CONTENT > {container_file_name}"],
        )
        docker_client.copy_from_container(
            dummy_container.container_id,
            local_path=str(local_path),
            container_path=container_file_name,
        )
        assert "TEST_CONTENT" == file_path.read().strip()

    def test_get_container_ip_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.get_container_ip(f"hopefully_non_existent_container_{short_uid()}")

    # TODO: getting container IP not yet working against Podman
    @skip_for_podman
    def test_get_container_ip(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        ip = docker_client.get_container_ip(dummy_container.container_id)
        assert is_ipv4_address(ip)
        assert "127.0.0.1" != ip


class TestRunWithAdditionalArgs:
    def test_run_with_additional_arguments(self, docker_client: ContainerClient):
        env_variable = "TEST_FLAG=test_str"
        stdout, _ = docker_client.run_container(
            "alpine", remove=True, command=["env"], additional_flags=f"-e {env_variable}"
        )
        assert env_variable in stdout.decode(config.DEFAULT_ENCODING)
        stdout, _ = docker_client.run_container(
            "alpine",
            remove=True,
            command=["env"],
            additional_flags=f"-e {env_variable}",
            env_vars={"EXISTING_VAR": "test_var"},
        )
        stdout = stdout.decode(config.DEFAULT_ENCODING)
        assert env_variable in stdout
        assert "EXISTING_VAR=test_var" in stdout

    def test_run_with_additional_arguments_add_host(self, docker_client: ContainerClient):
        additional_flags = "--add-host sometest.localstack.cloud:127.0.0.1"
        stdout, _ = docker_client.run_container(
            "alpine",
            remove=True,
            command=["getent", "hosts", "sometest.localstack.cloud"],
            additional_flags=additional_flags,
        )
        stdout = to_str(stdout)
        assert "127.0.0.1" in stdout
        assert "sometest.localstack.cloud" in stdout

    @pytest.mark.parametrize("pass_dns_in_run_container", [True, False])
    def test_run_with_additional_arguments_add_dns(
        self, docker_client: ContainerClient, pass_dns_in_run_container
    ):
        kwargs = {}
        additional_flags = "--dns 1.2.3.4"
        if pass_dns_in_run_container:
            kwargs["dns"] = "5.6.7.8"
        else:
            additional_flags += " --dns 5.6.7.8"

        container_name = f"c-{short_uid()}"
        stdout, _ = docker_client.run_container(
            "alpine",
            name=container_name,
            remove=True,
            command=["sleep", "3"],
            additional_flags=additional_flags,
            detach=True,
            **kwargs,
        )
        result = docker_client.inspect_container(container_name)
        assert set(result["HostConfig"]["Dns"]) == {"1.2.3.4", "5.6.7.8"}

    def test_run_with_additional_arguments_random_port(
        self, docker_client: ContainerClient, create_container
    ):
        container = create_container(
            "alpine",
            command=["sh", "-c", "while true; do sleep 1; done"],
            additional_flags="-p 0:80",
        )
        docker_client.start_container(container.container_id)
        inspect_result = docker_client.inspect_container(
            container_name_or_id=container.container_id
        )
        automatic_host_port = int(
            inspect_result["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"]
        )
        assert automatic_host_port > 0

    def test_run_with_ulimit(self, docker_client: ContainerClient):
        container_name = f"c-{short_uid()}"
        stdout, _ = docker_client.run_container(
            "alpine",
            name=container_name,
            remove=True,
            command=["sh", "-c", "ulimit -n"],
            ulimits=[Ulimit(name="nofile", soft_limit=1024, hard_limit=1024)],
        )
        assert stdout.decode(config.DEFAULT_ENCODING).strip() == "1024"

    def test_run_with_additional_arguments_env_files(
        self, docker_client: ContainerClient, tmp_path, monkeypatch
    ):
        env_variable = "TEST1=VAL1"
        env_file = tmp_path / "env1"
        env_vars = textwrap.dedent("""
            # Some comment
            TEST1=OVERRIDDEN
            TEST2=VAL2
            TEST3=${TEST2}
            TEST4=VAL # end comment
            TEST5="VAL"
            """)
        env_file.write_text(env_vars)

        stdout, _ = docker_client.run_container(
            "alpine",
            remove=True,
            command=["env"],
            additional_flags=f"-e {env_variable} --env-file {env_file}",
        )
        env_output = stdout.decode(config.DEFAULT_ENCODING)
        # behavior differs here from more advanced env file parsers
        assert env_variable in env_output
        assert "TEST1=VAL1" in env_output
        assert "TEST2=VAL2" in env_output
        assert "TEST3=${TEST2}" in env_output
        assert "TEST4=VAL # end comment" in env_output
        assert 'TEST5="VAL"' in env_output

        env_vars = textwrap.dedent("""
            # Some comment
            TEST1
            """)
        env_file.write_text(env_vars)

        stdout, _ = docker_client.run_container(
            "alpine",
            remove=True,
            command=["env"],
            additional_flags=f"--env-file {env_file}",
        )
        env_output = stdout.decode(config.DEFAULT_ENCODING)
        assert "TEST1" not in env_output

        monkeypatch.setenv("TEST1", "VAL1")
        stdout, _ = docker_client.run_container(
            "alpine",
            remove=True,
            command=["env"],
            additional_flags=f"--env-file {env_file}",
        )
        env_output = stdout.decode(config.DEFAULT_ENCODING)
        assert "TEST1=VAL1" in env_output

        env_vars = textwrap.dedent("""
            # Some comment
            TEST1=
            """)
        env_file.write_text(env_vars)

        stdout, _ = docker_client.run_container(
            "alpine",
            remove=True,
            command=["env"],
            additional_flags=f"--env-file {env_file}",
        )
        env_output = stdout.decode(config.DEFAULT_ENCODING)
        assert "TEST1=" in env_output.splitlines()


class TestDockerImages:
    def test_commit_creates_image_from_running_container(self, docker_client: ContainerClient):
        image_name = "lorem"
        image_tag = "ipsum"
        image = f"{image_name}:{image_tag}"
        container_name = _random_container_name()

        try:
            docker_client.run_container(
                "alpine",
                name=container_name,
                command=["sleep", "60"],
                detach=True,
            )
            docker_client.commit(container_name, image_name, image_tag)
            assert image in docker_client.get_docker_image_names()
        finally:
            docker_client.remove_container(container_name)
            docker_client.remove_image(image, force=True)

    def test_commit_image_raises_for_nonexistent_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.commit("nonexistent_container", "image_name", "should_not_matter")

    def test_remove_image_raises_for_nonexistent_image(self, docker_client: ContainerClient):
        image_name = "this_image"
        image_tag = "does_not_exist"
        image = f"{image_name}:{image_tag}"

        with pytest.raises(NoSuchImage):
            docker_client.remove_image(image, force=False)


# TODO: most of these tests currently failing under Podman in our CI pipeline, due
#  to "Error: "slirp4netns" is not supported: invalid network mode" in CI
@skip_for_podman
class TestDockerNetworking:
    def test_network_lifecycle(self, docker_client: ContainerClient):
        network_name = f"test-network-{short_uid()}"
        network_id = docker_client.create_network(network_name=network_name)
        assert network_name == docker_client.inspect_network(network_name=network_name)["Name"]
        assert network_id == docker_client.inspect_network(network_name=network_name)["Id"]
        docker_client.delete_network(network_name=network_name)
        with pytest.raises(NoSuchNetwork):
            docker_client.inspect_network(network_name=network_name)

    def test_get_container_ip_with_network(
        self, docker_client: ContainerClient, create_container, create_network
    ):
        network_name = f"ls_test_network_{short_uid()}"
        create_network(network_name)
        container = create_container(
            "alpine", network=network_name, command=["sh", "-c", "while true; do sleep 1; done"]
        )
        docker_client.start_container(container.container_id)
        ip = docker_client.get_container_ip(container.container_id)
        assert re.match(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            ip,
        )
        assert "127.0.0.1" != ip

    def test_set_container_workdir(self, docker_client: ContainerClient):
        result = docker_client.run_container("alpine", command=["pwd"], workdir="/tmp", remove=True)
        assert "/tmp" == to_str(result[0]).strip()

    def test_connect_container_to_network(
        self, docker_client: ContainerClient, create_network, create_container
    ):
        network_name = f"ls_test_network_{short_uid()}"
        create_network(network_name)
        container = create_container("alpine", command=["sh", "-c", "while true; do sleep 1; done"])
        docker_client.start_container(container.container_id)
        docker_client.connect_container_to_network(
            network_name, container_name_or_id=container.container_id
        )
        # TODO: podman CmdDockerClient currently not returning `Containers` list
        assert (
            container.container_id
            in docker_client.inspect_network(network_name).get("Containers").keys()
        )

    def test_connect_container_to_network_with_link_local_address(
        self, docker_client, create_network, create_container
    ):
        network_name = f"ls_test_network_{short_uid()}"
        create_network(network_name)
        container = create_container("alpine", command=["sh", "-c", "sleep infinity"])
        docker_client.connect_container_to_network(
            network_name,
            container_name_or_id=container.container_id,
            link_local_ips=["169.254.169.10"],
        )
        assert docker_client.inspect_container(container.container_id)["NetworkSettings"][
            "Networks"
        ][network_name]["IPAMConfig"]["LinkLocalIPs"] == ["169.254.169.10"]

    def test_connect_container_to_nonexistent_network(
        self, docker_client: ContainerClient, create_container
    ):
        container = create_container("alpine", command=["sh", "-c", "while true; do sleep 1; done"])
        docker_client.start_container(container.container_id)
        with pytest.raises(NoSuchNetwork):
            docker_client.connect_container_to_network(
                f"invalid_network_{short_uid()}", container_name_or_id=container.container_id
            )

    def test_disconnect_container_from_nonexistent_network(
        self, docker_client: ContainerClient, create_container
    ):
        container = create_container("alpine", command=["sh", "-c", "while true; do sleep 1; done"])
        docker_client.start_container(container.container_id)
        with pytest.raises(NoSuchNetwork):
            docker_client.disconnect_container_from_network(
                f"invalid_network_{short_uid()}", container_name_or_id=container.container_id
            )

    def test_connect_nonexistent_container_to_network(
        self, docker_client: ContainerClient, create_network, create_container
    ):
        network_name = f"ls_test_network_{short_uid()}"
        create_network(network_name)
        with pytest.raises(NoSuchContainer):
            docker_client.connect_container_to_network(
                network_name, container_name_or_id=f"some-invalid-container-{short_uid()}"
            )

    def test_disconnect_nonexistent_container_from_network(
        self, docker_client: ContainerClient, create_network, create_container
    ):
        network_name = f"ls_test_network_{short_uid()}"
        create_network(network_name)
        with pytest.raises(NoSuchContainer):
            docker_client.disconnect_container_from_network(
                network_name, container_name_or_id=f"some-invalid-container-{short_uid()}"
            )

    def test_connect_container_to_network_with_alias_and_disconnect(
        self, docker_client: ContainerClient, create_network, create_container
    ):
        network_name = f"ls_test_network_{short_uid()}"
        container_alias = f"test-container-{short_uid()}.localstack.cloud"
        create_network(network_name)
        container = create_container("alpine", command=["sh", "-c", "while true; do sleep 1; done"])
        docker_client.start_container(container.container_id)
        docker_client.connect_container_to_network(
            network_name, container_name_or_id=container.container_id, aliases=[container_alias]
        )
        container_2 = create_container(
            "alpine", command=["ping", "-c", "1", container_alias], network=network_name
        )
        docker_client.start_container(container_name_or_id=container_2.container_id, attach=True)
        docker_client.disconnect_container_from_network(network_name, container.container_id)
        with pytest.raises(ContainerException):
            docker_client.start_container(
                container_name_or_id=container_2.container_id, attach=True
            )

    @skip_for_podman  # note: manually creating SdkDockerClient can fail for clients
    def test_docker_sdk_timeout_seconds(self, monkeypatch):
        # check that the timeout seconds are defined by the config variable
        monkeypatch.setattr(config, "DOCKER_SDK_DEFAULT_TIMEOUT_SECONDS", 1337)
        sdk_client = SdkDockerClient()
        assert sdk_client.docker_client.api.timeout == 1337
        # check that the config variable is reloaded when the client is recreated
        monkeypatch.setattr(config, "DOCKER_SDK_DEFAULT_TIMEOUT_SECONDS", 987)
        sdk_client = SdkDockerClient()
        assert sdk_client.docker_client.api.timeout == 987

    def test_docker_sdk_no_retries(self, monkeypatch):
        monkeypatch.setattr(config, "DOCKER_SDK_DEFAULT_RETRIES", 0)
        # change the env for the docker socket (such that it cannot be initialized)
        monkeypatch.setenv("DOCKER_HOST", "tcp://non_existing_docker_client:2375/")
        sdk_client = SdkDockerClient()
        assert sdk_client.docker_client is None

    def test_docker_sdk_retries_on_init(self, monkeypatch):
        # increase the number of retries
        monkeypatch.setattr(config, "DOCKER_SDK_DEFAULT_RETRIES", 10)
        # change the env for the docker socket (such that it cannot be initialized)
        monkeypatch.setenv("DOCKER_HOST", "tcp://non_existing_docker_client:2375/")
        global sdk_client

        def on_demand_init(*args):
            global sdk_client
            sdk_client = SdkDockerClient()
            assert sdk_client.docker_client is not None

        # start initializing the client in another thread (with 10 retries)
        init_thread = FuncThread(func=on_demand_init)
        init_thread.start()
        # reset / fix the DOCKER_HOST config
        monkeypatch.delenv("DOCKER_HOST")
        # wait for the init thread to finish
        init_thread.join()
        # verify that the client is available
        assert sdk_client.docker_client is not None

    def test_docker_sdk_retries_after_init(self, monkeypatch):
        # increase the number of retries
        monkeypatch.setattr(config, "DOCKER_SDK_DEFAULT_RETRIES", 0)
        # change the env for the docker socket (such that it cannot be initialized)
        monkeypatch.setenv("DOCKER_HOST", "tcp://non_existing_docker_client:2375/")
        sdk_client = SdkDockerClient()
        assert sdk_client.docker_client is None
        monkeypatch.setattr(config, "DOCKER_SDK_DEFAULT_RETRIES", 10)

        def on_demand_init(*args):
            internal_sdk_client = sdk_client.client()
            assert internal_sdk_client is not None

        # start initializing the client in another thread (with 10 retries)
        init_thread = FuncThread(func=on_demand_init)
        init_thread.start()
        # reset / fix the DOCKER_HOST config
        monkeypatch.delenv("DOCKER_HOST")
        # wait for the init thread to finish
        init_thread.join()
        # verify that the client is available
        assert sdk_client.docker_client is not None


class TestDockerLogging:
    def test_docker_logging_none_disables_logs(
        self, docker_client: ContainerClient, create_container
    ):
        container = create_container(
            "alpine", command=["sh", "-c", "echo test"], log_config=LogConfig("none")
        )
        docker_client.start_container(container.container_id, attach=True)
        with pytest.raises(ContainerException):
            docker_client.get_container_logs(container_name_or_id=container.container_id)

    def test_docker_logging_fluentbit(self, docker_client: ContainerClient, create_container):
        ports = PortMappings(bind_host="0.0.0.0")
        ports.add(24224, 24224)
        fluentd_container = create_container(
            "fluent/fluent-bit",
            command=["-i", "forward", "-o", "stdout", "-p", "format=json_lines", "-f", "1", "-q"],
            ports=ports,
        )
        docker_client.start_container(fluentd_container.container_id)

        container = create_container(
            "alpine",
            command=["sh", "-c", "echo test"],
            log_config=LogConfig(
                "fluentd", config={"fluentd-address": "127.0.0.1:24224", "fluentd-async": "true"}
            ),
        )
        docker_client.start_container(container.container_id, attach=True)

        def _get_logs():
            logs = docker_client.get_container_logs(
                container_name_or_id=fluentd_container.container_id
            )
            message = None
            for log in logs.splitlines():
                if log.strip():
                    message = json.loads(log.strip())
            assert message
            return message

        log = retry(_get_logs, retries=10, sleep=1)
        assert log["log"] == "test"
        assert log["source"] == "stdout"
        assert log["container_id"] == container.container_id
        assert log["container_name"] == f"/{container.container_name}"


class TestDockerPermissions:
    def test_container_with_cap_add(self, docker_client: ContainerClient, create_container):
        container = create_container(
            "alpine",
            cap_add=["NET_ADMIN"],
            command=[
                "sh",
                "-c",
                "ip link add dummy0 type dummy && ip link delete dummy0 && echo test",
            ],
        )
        stdout, _ = docker_client.start_container(
            container_name_or_id=container.container_id, attach=True
        )
        assert "test" in to_str(stdout)
        container = create_container(
            "alpine",
            command=[
                "sh",
                "-c",
                "ip link add dummy0 type dummy && ip link delete dummy0 && echo test",
            ],
        )
        with pytest.raises(ContainerException):
            stdout, _ = docker_client.start_container(
                container_name_or_id=container.container_id, attach=True
            )

    def test_container_with_cap_drop(self, docker_client: ContainerClient, create_container):
        container = create_container("alpine", command=["sh", "-c", "chown nobody / && echo test"])
        stdout, _ = docker_client.start_container(
            container_name_or_id=container.container_id, attach=True
        )
        assert "test" in to_str(stdout)
        container = create_container(
            "alpine", cap_drop=["CHOWN"], command=["sh", "-c", "chown nobody / && echo test"]
        )
        with pytest.raises(ContainerException):
            stdout, _ = docker_client.start_container(
                container_name_or_id=container.container_id, attach=True
            )

    # TODO: currently fails in Podman with "Apparmor is not enabled on this system"
    @skip_for_podman
    def test_container_with_sec_opt(self, docker_client: ContainerClient, create_container):
        security_opt = ["apparmor=unrestricted"]
        container = create_container(
            "alpine",
            security_opt=security_opt,
            command=["sh", "-c", "while true; do sleep 1; done"],
        )
        inspect_result = docker_client.inspect_container(
            container_name_or_id=container.container_id
        )
        assert security_opt == inspect_result["HostConfig"]["SecurityOpt"]


@pytest.fixture
def set_ports_check_image_alpine(monkeypatch):
    """Set the ports check Docker image to 'alpine', to avoid pulling the larger localstack image in the tests"""

    def _get_ports_check_docker_image():
        return "alpine"

    monkeypatch.setattr(
        docker_utils, "_get_ports_check_docker_image", _get_ports_check_docker_image
    )


@pytest.mark.parametrize("protocol", [None, "tcp", "udp"])
class TestDockerPorts:
    def test_reserve_container_port(self, docker_client, set_ports_check_image_alpine, protocol):
        if isinstance(docker_client, CmdDockerClient):
            pytest.skip("Running test only for one Docker executor")

        # reserve available container port
        port = reserve_available_container_port(duration=1, protocol=protocol)
        port = Port(port, protocol or "tcp")
        assert is_container_port_reserved(port)
        assert container_ports_can_be_bound(port)
        assert not is_port_available_for_containers(port)

        # reservation should fail immediately after
        with pytest.raises(PortNotAvailableException):
            reserve_container_port(port)

        # reservation should work after expiry time
        time.sleep(1)
        assert not is_container_port_reserved(port)
        assert is_port_available_for_containers(port)
        reserve_container_port(port, duration=1)
        assert is_container_port_reserved(port)
        assert container_ports_can_be_bound(port)

        # reservation should work on privileged port
        port = reserve_available_container_port(duration=1, port_start=1, port_end=1024)
        assert is_container_port_reserved(port)
        assert container_ports_can_be_bound(port)
        assert not is_port_available_for_containers(port)

    def test_container_port_can_be_bound(
        self, docker_client, set_ports_check_image_alpine, protocol
    ):
        if isinstance(docker_client, CmdDockerClient):
            pytest.skip("Running test only for one Docker executor")

        # reserve available container port
        port = reserve_available_container_port(duration=1)
        start_time = datetime.datetime.now()
        assert container_ports_can_be_bound(port)
        assert not is_port_available_for_containers(port)

        # run test container with port exposed
        ports = PortMappings()
        ports.add(port, port)
        name = f"c-{short_uid()}"
        docker_client.run_container(
            "alpine",
            name=name,
            command=["sleep", "5"],
            entrypoint="",
            ports=ports,
            detach=True,
        )
        # assert that port can no longer be bound by new containers
        assert not container_ports_can_be_bound(port)

        # remove container, assert that port can be bound again
        docker_client.remove_container(name, force=True)
        assert container_ports_can_be_bound(port)
        delta = (datetime.datetime.now() - start_time).total_seconds()
        if delta <= 1:
            time.sleep(1.01 - delta)
        assert is_port_available_for_containers(port)


class TestDockerLabels:
    def test_create_container_with_labels(self, docker_client, create_container):
        labels = {"foo": "bar", short_uid(): short_uid()}
        container = create_container("alpine", command=["dummy"], labels=labels)
        result = docker_client.inspect_container(container.container_id)
        result_labels = result.get("Config", {}).get("Labels")
        assert result_labels == labels

    def test_run_container_with_labels(self, docker_client):
        labels = {"foo": "bar", short_uid(): short_uid()}
        container_name = _random_container_name()
        try:
            docker_client.run_container(
                image_name="alpine",
                command=["sh", "-c", "while true; do sleep 1; done"],
                labels=labels,
                name=container_name,
                detach=True,
            )
            result = docker_client.inspect_container(container_name_or_id=container_name)
            result_labels = result.get("Config", {}).get("Labels")
            assert result_labels == labels
        finally:
            docker_client.remove_container(container_name=container_name, force=True)

    def test_list_containers_with_labels(self, docker_client, create_container):
        labels = {"foo": "bar", short_uid(): short_uid()}
        container = create_container(
            "alpine", command=["sh", "-c", "while true; do sleep 1; done"], labels=labels
        )
        docker_client.start_container(container.container_id)

        containers = docker_client.list_containers(filter=f"id={container.container_id}")
        assert len(containers) == 1
        container = containers[0]
        assert container["labels"] == labels


def _pull_image_if_not_exists(docker_client: ContainerClient, image_name: str):
    if image_name not in docker_client.get_docker_image_names():
        docker_client.pull_image(image_name)


def _get_default_network() -> str:
    """Return the default container network name - `bridge` for Docker, `podman` for Podman."""
    return "podman" if _is_podman_test() else "bridge"
