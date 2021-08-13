import logging
from subprocess import CalledProcessError
from typing import NamedTuple

import pytest

from localstack import config
from localstack.utils.common import safe_run, short_uid
from localstack.utils.docker import CmdDockerClient as DockerClient
from localstack.utils.docker import (
    ContainerException,
    DockerContainerStatus,
    NoSuchContainer,
    NoSuchImage,
    PortMappings,
    Util,
)

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
def create_container(docker_client: DockerClient):
    """
    Uses the factory as fixture pattern to wrap DockerClient.create_container as a factory that
    removes the containers after the fixture is cleaned up.
    """
    containers = list()

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


class TestDockerClient:
    def test_container_lifecycle_commands(self, docker_client: DockerClient):
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
            docker_client.stop_container(container_id)
            assert DockerContainerStatus.DOWN == docker_client.get_container_status(container_name)
        finally:
            docker_client.remove_container(container_id)

        assert DockerContainerStatus.NON_EXISTENT == docker_client.get_container_status(
            container_name
        )

    def test_create_container_remove_removes_container(
        self, docker_client: DockerClient, create_container
    ):
        info = create_container("alpine", remove=True, command=["echo", "foobar"])
        # make sure it was correctly created
        assert 1 == len(docker_client.list_containers(f"id={info.container_id}"))

        # start the container
        output, _ = docker_client.start_container(info.container_id, attach=True)
        output = output.decode(config.DEFAULT_ENCODING)

        assert 0 == len(docker_client.list_containers(f"id={info.container_id}"))

        # it takes a while for it to be removed
        assert "foobar" in output

    def test_create_container_non_existing_image(self, docker_client: DockerClient):
        with pytest.raises(NoSuchImage):
            docker_client.create_container("this_image_does_hopefully_not_exist_42069")

    def test_exec_in_container(self, docker_client: DockerClient, dummy_container: ContainerInfo):
        docker_client.start_container(dummy_container.container_id)

        output, _ = docker_client.exec_in_container(
            dummy_container.container_id, command=["echo", "foobar"]
        )
        output = output.decode(config.DEFAULT_ENCODING)
        assert "foobar" == output.strip()

    def test_exec_in_container_not_running_raises_exception(
        self, docker_client: DockerClient, dummy_container
    ):
        with pytest.raises(ContainerException):
            # can't exec into a non-running container
            docker_client.exec_in_container(
                dummy_container.container_id, command=["echo", "foobar"]
            )

    def test_exec_in_container_with_env(self, docker_client: DockerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)

        env = {"MYVAR": "foo_var"}

        output, _ = docker_client.exec_in_container(
            dummy_container.container_id, env_vars=env, command=["env"]
        )
        output = output.decode(config.DEFAULT_ENCODING)
        assert "MYVAR=foo_var" in output

    def test_exec_error_in_container(self, docker_client: DockerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)

        with pytest.raises(ContainerException) as ex:
            docker_client.exec_in_container(
                dummy_container.container_id, command=["./doesnotexist"]
            )

        assert ex.match("doesnotexist: no such file or directory")

    def test_create_container_with_max_env_vars(
        self, docker_client: DockerClient, create_container
    ):
        # default ARG_MAX=131072 in Docker
        env = dict([(f"IVAR_{i:05d}", f"VAL_{i:05d}") for i in range(2000)])

        # make sure we're really triggering the relevant code
        assert len(str(dict(env))) >= Util.MAX_ENV_ARGS_LENGTH

        info = create_container("alpine", env_vars=env, command=["env"])
        output, _ = docker_client.start_container(info.container_id, attach=True)
        output = output.decode(config.DEFAULT_ENCODING)

        assert "IVAR_00001=VAL_00001" in output
        assert "IVAR_01000=VAL_01000" in output
        assert "IVAR_01999=VAL_01999" in output

    def test_run_container(self, docker_client: DockerClient):
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

    def test_run_container_error(self, docker_client: DockerClient):
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

    def test_stop_non_existing_container(self, docker_client: DockerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.stop_container("this_container_does_not_exist")

    def test_remove_non_existing_container(self, docker_client: DockerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.remove_container("this_container_does_not_exist", force=False)

    def test_start_non_existing_container(self, docker_client: DockerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.start_container("this_container_does_not_exist")

    def test_get_network(self, docker_client: DockerClient, dummy_container):
        n = docker_client.get_network(dummy_container.container_name)
        assert "default" == n

    def test_create_with_host_network(self, docker_client: DockerClient, create_container):
        info = create_container("alpine", network="host")
        network = docker_client.get_network(info.container_name)
        assert "host" == network

    def test_create_with_port_mapping(self, docker_client: DockerClient, create_container):
        ports = PortMappings()
        ports.add(45122, 22)
        ports.add(45180, 80)
        create_container("alpine", ports=ports)

    def test_create_with_volume(self, tmpdir, docker_client: DockerClient, create_container):
        mount_volumes = [(tmpdir.realpath(), "/tmp/mypath")]

        c = create_container(
            "alpine",
            command=["sh", "-c", "echo 'foobar' > /tmp/mypath/foo.log"],
            mount_volumes=mount_volumes,
        )
        docker_client.start_container(c.container_id)

        assert tmpdir.join("foo.log").isfile(), "foo.log was not created in mounted dir"

    def test_copy_into_container(self, tmpdir, docker_client: DockerClient, create_container):
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

    def test_copy_into_container_without_target_filename(
        self, tmpdir, docker_client: DockerClient, create_container
    ):
        local_path = tmpdir.join("myfile.txt")
        container_path = "/tmp/"

        self._test_copy_into_container(
            docker_client,
            create_container,
            ["cat", "/tmp/myfile.txt"],
            local_path,
            local_path,
            container_path,
        )

    def test_copy_directory_into_container(
        self, tmpdir, docker_client: DockerClient, create_container
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

    def test_get_network_non_existing_container(self, docker_client: DockerClient):
        with pytest.raises(ContainerException):
            docker_client.get_network("this_container_does_not_exist")

    def test_list_containers(self, docker_client: DockerClient, create_container):
        c1 = create_container("alpine", command=["echo", "1"])
        c2 = create_container("alpine", command=["echo", "2"])
        c3 = create_container("alpine", command=["echo", "3"])

        container_list = docker_client.list_containers()

        assert len(container_list) >= 3

        image_names = [info["name"] for info in container_list]

        assert c1.container_name in image_names
        assert c2.container_name in image_names
        assert c3.container_name in image_names

    def test_list_containers_filter_non_existing(self, docker_client: DockerClient):
        container_list = docker_client.list_containers(filter="id=DOES_NOT_EXST")
        assert 0 == len(container_list)

    def test_list_containers_filter_illegal_filter(self, docker_client: DockerClient):
        with pytest.raises(ContainerException):
            docker_client.list_containers(filter="illegalfilter=foobar")

    def test_list_containers_filter(self, docker_client: DockerClient, create_container):
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

    def test_get_container_entrypoint(self, docker_client: DockerClient):
        entrypoint = docker_client.get_image_entrypoint("alpine")
        assert "" == entrypoint

    def test_get_container_entrypoint_non_existing_image(self, docker_client: DockerClient):
        with pytest.raises(NoSuchImage):
            docker_client.get_image_entrypoint("thisdoesnotexist")

    def test_get_container_command(self, docker_client: DockerClient):
        command = docker_client.get_image_cmd("alpine")
        assert "/bin/sh" == command

    def test_get_container_command_non_existing_image(self, docker_client: DockerClient):
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("thisdoesnotexist")

    def test_create_start_container_with_stdin_to_stdout(self, docker_client: DockerClient):
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

    def test_create_start_container_with_stdin_to_file(self, tmpdir, docker_client: DockerClient):
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

    @pytest.mark.timeout(10)
    def test_run_container_with_stdin(self, docker_client: DockerClient):
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

    def test_exec_in_container_with_stdin(self, docker_client: DockerClient, dummy_container):
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
        self, docker_client: DockerClient, dummy_container
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

    def test_run_detached_with_logs(self, docker_client: DockerClient):
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

    def test_get_logs_non_existent_container(self, docker_client: DockerClient):
        with pytest.raises(NoSuchContainer):
            docker_client.get_container_logs("container_hopefully_does_not_exist", safe=False)

        assert "" == docker_client.get_container_logs(
            "container_hopefully_does_not_exist", safe=True
        )

    def test_pull_docker_image(self, docker_client: DockerClient):
        try:
            docker_client.get_image_cmd("alpine")
            safe_run([config.DOCKER_CMD, "rmi", "alpine"])
        except ContainerException:
            pass
        with pytest.raises(NoSuchImage):
            docker_client.get_image_cmd("alpine")
        docker_client.pull_image("alpine")
        assert "/bin/sh" == docker_client.get_image_cmd("alpine").strip()

    def test_running_container_names(self, docker_client: DockerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        name = dummy_container.container_name
        assert name in docker_client.get_running_container_names()
        docker_client.stop_container(name)
        assert name not in docker_client.get_running_container_names()

    def test_is_container_running(self, docker_client: DockerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        name = dummy_container.container_name
        assert docker_client.is_container_running(name)
        docker_client.stop_container(name)
        assert not docker_client.is_container_running(name)

    def test_docker_image_names(self, docker_client: DockerClient):
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

    def test_get_container_name(self, docker_client: DockerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        assert dummy_container.container_name == docker_client.get_container_name(
            dummy_container.container_id
        )

    def test_get_container_name_not_existing(self, docker_client: DockerClient):
        not_existent_container = "not_existing_container"
        with pytest.raises(NoSuchContainer):
            docker_client.get_container_name(not_existent_container)

    def test_get_container_id(self, docker_client: DockerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        assert dummy_container.container_id == docker_client.get_container_id(
            dummy_container.container_name
        )

    def test_get_container_id_not_existing(self, docker_client: DockerClient):
        not_existent_container = "not_existing_container"
        with pytest.raises(NoSuchContainer):
            docker_client.get_container_id(not_existent_container)

    def test_inspect_container(self, docker_client: DockerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        for identifier in [dummy_container.container_id, dummy_container.container_name]:
            assert dummy_container.container_id == docker_client.inspect_container(identifier)["Id"]
            assert (
                f"/{dummy_container.container_name}"
                == docker_client.inspect_container(identifier)["Name"]
            )

    def test_inspect_image(self, docker_client: DockerClient):
        docker_client.pull_image("alpine")
        assert "alpine:latest" == docker_client.inspect_image("alpine")["RepoTags"][0]

    def test_copy_from_container(self, tmpdir, docker_client: DockerClient, dummy_container):
        docker_client.start_container(dummy_container.container_id)
        local_path = tmpdir.join("test_file")
        self._test_copy_from_container(
            local_path, local_path, "test_file", docker_client, dummy_container
        )

    def test_copy_from_container_into_directory(
        self, tmpdir, docker_client: DockerClient, dummy_container
    ):
        docker_client.start_container(dummy_container.container_id)
        local_path = tmpdir.mkdir("test_dir")
        file_path = local_path.join("test_file")
        self._test_copy_from_container(
            local_path, file_path, "test_file", docker_client, dummy_container
        )

    def _test_copy_from_container(
        self,
        local_path,
        file_path,
        container_file_name,
        docker_client: DockerClient,
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
