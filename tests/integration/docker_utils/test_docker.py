import ipaddress
import logging
import os
import re
import time
from subprocess import CalledProcessError
from typing import NamedTuple

import pytest

from localstack import config
from localstack.config import in_docker
from localstack.utils.common import is_ipv4_address, safe_run, save_file, short_uid, to_str
from localstack.utils.container_utils.container_client import (
    AccessDenied,
    ContainerClient,
    ContainerException,
    DockerContainerStatus,
    NoSuchContainer,
    NoSuchImage,
    NoSuchNetwork,
    PortMappings,
    RegistryConnectionError,
    Util,
)
from localstack.utils.net_utils import get_free_tcp_port

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
def create_network():
    """
    Uses the factory as fixture pattern to wrap the creation of networks as a factory that
    removes the networks after the fixture is cleaned up.
    """
    networks = []

    def _create_network(network_name: str):
        network_id = safe_run([config.DOCKER_CMD, "network", "create", network_name]).strip()
        networks.append(network_id)
        return network_id

    yield _create_network

    for network in networks:
        try:
            LOG.debug("Removing network %s", network)
            safe_run([config.DOCKER_CMD, "network", "remove", network])
        except CalledProcessError:
            pass


class TestDockerClient:
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

            docker_client.pause_container(container_id)
            assert DockerContainerStatus.PAUSED == docker_client.get_container_status(
                container_name
            )

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
        output = output.decode(config.DEFAULT_ENCODING)
        time.sleep(1)  # give the docker daemon some time to remove the container after execution

        assert 0 == len(docker_client.list_containers(f"id={info.container_id}"))

        # it takes a while for it to be removed
        assert "foobar" in output

    @pytest.mark.skip_offline
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
        output = output.decode(config.DEFAULT_ENCODING)
        assert "foobar" == output.strip()

    def test_exec_in_container_not_running_raises_exception(
        self, docker_client: ContainerClient, dummy_container
    ):
        with pytest.raises(ContainerException):
            # can't exec into a non-running container
            docker_client.exec_in_container(
                dummy_container.container_id, command=["echo", "foobar"]
            )

    def test_exec_in_container_with_env(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)

        env = {"MYVAR": "foo_var"}

        output, _ = docker_client.exec_in_container(
            dummy_container.container_id, env_vars=env, command=["env"]
        )
        output = output.decode(config.DEFAULT_ENCODING)
        assert "MYVAR=foo_var" in output

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

        env = {"MYVAR": None}

        output, _ = docker_client.exec_in_container(
            container_info.container_id, env_vars=env, command=["env"]
        )
        output = output.decode(config.DEFAULT_ENCODING)
        assert "MYVAR" not in output

    def test_exec_error_in_container(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)

        with pytest.raises(ContainerException) as ex:
            docker_client.exec_in_container(
                dummy_container.container_id, command=["./doesnotexist"]
            )

        assert ex.match("doesnotexist: no such file or directory")

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

    def test_pause_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.pause_container("this_container_does_not_exist")

    def test_remove_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.remove_container("this_container_does_not_exist", force=False)

    def test_start_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.start_container("this_container_does_not_exist")

    def test_get_network(self, docker_client: ContainerClient, dummy_container):
        n = docker_client.get_networks(dummy_container.container_name)
        assert ["bridge"] == n

    def test_get_network_multiple_networks(
        self, docker_client: ContainerClient, dummy_container, create_network
    ):
        network_name = f"test-network-{short_uid()}"
        network_id = create_network(network_name)
        safe_run(["docker", "network", "connect", network_id, dummy_container.container_id])
        docker_client.start_container(dummy_container.container_id)
        networks = docker_client.get_networks(dummy_container.container_id)
        assert network_name in networks
        assert "bridge" in networks
        assert len(networks) == 2

    def test_get_container_ip_for_network(
        self, docker_client: ContainerClient, dummy_container, create_network
    ):
        network_name = f"test-network-{short_uid()}"
        network_id = create_network(network_name)
        safe_run(["docker", "network", "connect", network_id, dummy_container.container_id])
        docker_client.start_container(dummy_container.container_id)
        result_bridge_network = docker_client.get_container_ipv4_for_network(
            container_name_or_id=dummy_container.container_id, container_network="bridge"
        ).strip()
        assert is_ipv4_address(result_bridge_network)
        bridge_network = docker_client.inspect_network("bridge")["IPAM"]["Config"][0]["Subnet"]
        assert ipaddress.IPv4Address(result_bridge_network) in ipaddress.IPv4Network(bridge_network)
        result_custom_network = docker_client.get_container_ipv4_for_network(
            container_name_or_id=dummy_container.container_id, container_network=network_name
        ).strip()
        assert is_ipv4_address(result_custom_network)
        assert result_custom_network != result_bridge_network
        custom_network = docker_client.inspect_network(network_name)["IPAM"]["Config"][0]["Subnet"]
        assert ipaddress.IPv4Address(result_custom_network) in ipaddress.IPv4Network(custom_network)

    def test_get_container_ip_for_network_wrong_network(
        self, docker_client: ContainerClient, dummy_container, create_network
    ):
        network_name = f"test-network-{short_uid()}"
        create_network(network_name)
        docker_client.start_container(dummy_container.container_id)
        result_bridge_network = docker_client.get_container_ipv4_for_network(
            container_name_or_id=dummy_container.container_id, container_network="bridge"
        ).strip()
        assert is_ipv4_address(result_bridge_network)

        with pytest.raises(ContainerException):
            docker_client.get_container_ipv4_for_network(
                container_name_or_id=dummy_container.container_id, container_network=network_name
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

    def test_create_with_host_network(self, docker_client: ContainerClient, create_container):
        info = create_container("alpine", network="host")
        network = docker_client.get_networks(info.container_name)
        assert ["host"] == network

    def test_create_with_port_mapping(self, docker_client: ContainerClient, create_container):
        ports = PortMappings()
        ports.add(45122, 22)
        ports.add(45180, 80)
        create_container("alpine", ports=ports)

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
                "hopefully_non_existent_container_%s" % short_uid(), str(file_path), "test_file"
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
        assert "created" == container_list[0]["status"]

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

    def test_get_container_entrypoint(self, docker_client: ContainerClient):
        entrypoint = docker_client.get_image_entrypoint("alpine")
        assert "" == entrypoint

    def test_get_container_entrypoint_non_existing_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.get_image_entrypoint("thisdoesnotexist")

    def test_get_container_entrypoint_not_pulled_image(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
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
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
        except ContainerException:
            pass
        command = docker_client.get_image_cmd("alpine")
        assert ["/bin/sh"] == command

    def test_get_container_command_non_existing_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("thisdoesnotexist")

    def test_create_start_container_with_stdin_to_stdout(self, docker_client: ContainerClient):
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
                container_name, interactive=True, stdin=message.encode(config.DEFAULT_ENCODING)
            )

            assert message == output.decode(config.DEFAULT_ENCODING).strip()
        finally:
            docker_client.remove_container(container_name)
            pass

    def test_create_start_container_with_stdin_to_file(
        self, tmpdir, docker_client: ContainerClient
    ):
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
                container_name, interactive=True, stdin=message.encode(config.DEFAULT_ENCODING)
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

    @pytest.mark.skip_offline
    def test_pull_docker_image(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
        except ContainerException:
            pass
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("alpine", pull=False)
        docker_client.pull_image("alpine")
        assert ["/bin/sh"] == docker_client.get_image_cmd("alpine", pull=False)

    @pytest.mark.skip_offline
    def test_pull_non_existent_docker_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.pull_image("localstack_non_existing_image_for_tests")

    @pytest.mark.skip_offline
    def test_pull_docker_image_with_tag(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
        except ContainerException:
            pass
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("alpine", pull=False)
        docker_client.pull_image("alpine:3.13")
        assert ["/bin/sh"] == docker_client.get_image_cmd("alpine:3.13", pull=False)
        assert "alpine:3.13" in docker_client.inspect_image("alpine:3.13", pull=False)["RepoTags"]

    @pytest.mark.skip_offline
    def test_pull_docker_image_with_hash(self, docker_client: ContainerClient):
        try:
            docker_client.get_image_cmd("alpine", pull=False)
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
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

    @pytest.mark.skip_offline
    def test_run_container_automatic_pull(self, docker_client: ContainerClient):
        try:
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
        except CalledProcessError:
            pass
        message = "test message"
        stdout, _ = docker_client.run_container("alpine", command=["echo", message], remove=True)
        assert message == stdout.decode(config.DEFAULT_ENCODING).strip()

    @pytest.mark.skip_offline
    def test_push_non_existent_docker_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.push_image("localstack_non_existing_image_for_tests")

    @pytest.mark.skip_offline
    def test_push_access_denied(self, docker_client: ContainerClient):
        with pytest.raises(AccessDenied):
            docker_client.push_image("alpine")
        with pytest.raises(AccessDenied):
            docker_client.push_image("alpine:latest")

    @pytest.mark.skip_offline
    def test_push_invalid_registry(self, docker_client: ContainerClient):
        image_name = f"localhost:{get_free_tcp_port()}/localstack_dummy_image"
        try:
            docker_client.tag_image("alpine", image_name)
            with pytest.raises(RegistryConnectionError):
                docker_client.push_image(image_name)
        finally:
            docker_client.remove_image(image_name)

    @pytest.mark.skip_offline
    def test_tag_image(self, docker_client: ContainerClient):
        docker_client.pull_image("alpine")
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
                docker_client.remove_image(img_ref)

    @pytest.mark.skip_offline
    def test_tag_non_existing_image(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchImage):
            docker_client.tag_image(
                "localstack_non_existing_image_for_tests", "localstack_dummy_image"
            )

    @pytest.mark.skip_offline
    @pytest.mark.parametrize("custom_context", [True, False])
    @pytest.mark.parametrize("dockerfile_as_dir", [True, False])
    def test_build_image(
        self, docker_client: ContainerClient, custom_context, dockerfile_as_dir, tmp_path
    ):
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
        assert image_name in docker_client.get_docker_image_names()
        result = docker_client.inspect_image(image_name, pull=False)
        assert "foo=bar" in result["Config"]["Env"]
        assert "45329/tcp" in result["Config"]["ExposedPorts"]

        docker_client.remove_image(image_name, force=True)

    @pytest.mark.skip_offline
    def test_run_container_non_existent_image(self, docker_client: ContainerClient):
        try:
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
        except CalledProcessError:
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
        docker_client.stop_container(name)
        assert not docker_client.is_container_running(name)

    @pytest.mark.skip_offline
    def test_docker_image_names(self, docker_client: ContainerClient):
        try:
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
        except CalledProcessError:
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
            assert (
                f"/{dummy_container.container_name}"
                == docker_client.inspect_container(identifier)["Name"]
            )

    @pytest.mark.skip_offline
    def test_inspect_image(self, docker_client: ContainerClient):
        docker_client.pull_image("alpine")
        assert "alpine" in docker_client.inspect_image("alpine")["RepoTags"][0]

    def test_inspect_network(self, docker_client: ContainerClient, create_network):
        network_name = "ls_test_network_%s" % short_uid()
        network_id = create_network(network_name)
        assert network_name == docker_client.inspect_network(network_name)["Name"]
        assert network_id == docker_client.inspect_network(network_name)["Id"]

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
                "hopefully_non_existent_container_%s" % short_uid(), str(local_path), "test_file"
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
        stdout = stdout.decode(config.DEFAULT_ENCODING)
        assert "127.0.0.1" in stdout
        assert "sometest.localstack.cloud" in stdout

    def test_get_container_ip_non_existing_container(self, docker_client: ContainerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.get_container_ip("hopefully_non_existent_container_%s" % short_uid())

    def test_get_container_ip(self, docker_client: ContainerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        ip = docker_client.get_container_ip(dummy_container.container_id)
        assert is_ipv4_address(ip)
        assert "127.0.0.1" != ip

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

    def test_get_container_ip_with_network(
        self, docker_client: ContainerClient, create_container, create_network
    ):
        network_name = "ls_test_network_%s" % short_uid()
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
        network_name = "ls_test_network_%s" % short_uid()
        create_network(network_name)
        container = create_container("alpine", command=["sh", "-c", "while true; do sleep 1; done"])
        docker_client.start_container(container.container_id)
        docker_client.connect_container_to_network(
            network_name, container_name_or_id=container.container_id
        )
        assert (
            container.container_id
            in docker_client.inspect_network(network_name).get("Containers").keys()
        )

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
        network_name = "ls_test_network_%s" % short_uid()
        create_network(network_name)
        with pytest.raises(NoSuchContainer):
            docker_client.connect_container_to_network(
                network_name, container_name_or_id=f"some-invalid-container-{short_uid()}"
            )

    def test_disconnect_nonexistent_container_from_network(
        self, docker_client: ContainerClient, create_network, create_container
    ):
        network_name = "ls_test_network_%s" % short_uid()
        create_network(network_name)
        with pytest.raises(NoSuchContainer):
            docker_client.disconnect_container_from_network(
                network_name, container_name_or_id=f"some-invalid-container-{short_uid()}"
            )

    def test_connect_container_to_network_with_alias_and_disconnect(
        self, docker_client: ContainerClient, create_network, create_container
    ):
        network_name = "ls_test_network_%s" % short_uid()
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
