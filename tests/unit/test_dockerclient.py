import json
import logging
import unittest
from typing import List
from unittest.mock import patch

import pytest

from localstack import config
from localstack.utils.docker_utils import CmdDockerClient, DockerContainerStatus, PortMappings, Util

LOG = logging.getLogger(__name__)


class TestDockerClient(unittest.TestCase):
    def _docker_cmd(self) -> List[str]:
        """Return the string to be used for running Docker commands."""
        return config.DOCKER_CMD.split()

    @patch("localstack.utils.docker_utils.safe_run")
    def test_list_containers(self, run_mock):
        test_container = {
            "id": "00000000a1",
            "image": "localstack/localstack",
            "name": "localstack_main",
            "labels": "authors=LocalStack Contributors",
            "status": "running",
        }
        run_mock.return_value = json.dumps(test_container)
        docker_client = CmdDockerClient()
        container_list = docker_client.list_containers()
        call_arguments = run_mock.call_args[0][0]
        LOG.info("Intercepted call arguments: %s", call_arguments)
        self.assertEqual(test_container, container_list[0])
        self.assertTrue(list_in(self._docker_cmd() + ["ps"], call_arguments))
        self.assertIn("-a", call_arguments)
        self.assertIn("--format", call_arguments)

    @patch("localstack.utils.docker_utils.safe_run")
    def test_container_status(self, run_mock):
        test_output = "Up 2 minutes - localstack_main"
        run_mock.return_value = test_output
        docker_client = CmdDockerClient()
        status = docker_client.get_container_status("localstack_main")
        self.assertEqual(DockerContainerStatus.UP, status)
        run_mock.return_value = "Exited (0) 1 minute ago - localstack_main"
        status = docker_client.get_container_status("localstack_main")
        self.assertEqual(DockerContainerStatus.DOWN, status)
        run_mock.return_value = "STATUS    NAME"
        status = docker_client.get_container_status("localstack_main")
        self.assertEqual(DockerContainerStatus.NON_EXISTENT, status)


def test_argument_parsing():
    test_port_string = "-p 80:8080/udp"
    test_port_string_with_host = "-p 127.0.0.1:6000:7000/tcp"
    test_env_string = "-e TEST_ENV_VAR=test_string=123"
    test_mount_string = "-v /var/test:/opt/test"
    argument_string = (
        f"{test_port_string} {test_env_string} {test_mount_string} {test_port_string_with_host}"
    )
    env_vars = {}
    ports = PortMappings()
    mounts = []
    Util.parse_additional_flags(argument_string, env_vars, ports, mounts)
    assert env_vars == {"TEST_ENV_VAR": "test_string=123"}
    assert ports.to_str() == "-p 80:8080/udp -p 6000:7000"
    assert mounts == [("/var/test", "/opt/test")]
    argument_string = (
        "--add-host host.docker.internal:host-gateway --add-host arbitrary.host:127.0.0.1"
    )
    _, _, _, extra_hosts, _ = Util.parse_additional_flags(argument_string, env_vars, ports, mounts)
    assert {"host.docker.internal": "host-gateway", "arbitrary.host": "127.0.0.1"} == extra_hosts

    with pytest.raises(NotImplementedError):
        argument_string = "--somerandomargument"
        Util.parse_additional_flags(argument_string, env_vars, ports, mounts)
    with pytest.raises(ValueError):
        argument_string = "--publish 80:80:80:80"
        Util.parse_additional_flags(argument_string, env_vars, ports, mounts)

    # Test windows paths
    argument_string = r'-v "C:\Users\SomeUser\SomePath:/var/task"'
    _, _, mounts, _, _ = Util.parse_additional_flags(argument_string)
    assert mounts == [(r"C:\Users\SomeUser\SomePath", "/var/task")]
    argument_string = r'-v "C:\Users\SomeUser\SomePath:/var/task:ro"'
    _, _, mounts, _, _ = Util.parse_additional_flags(argument_string)
    assert mounts == [(r"C:\Users\SomeUser\SomePath", "/var/task")]
    argument_string = r'-v "C:\Users\Some User\Some Path:/var/task:ro"'
    _, _, mounts, _, _ = Util.parse_additional_flags(argument_string)
    assert mounts == [(r"C:\Users\Some User\Some Path", "/var/task")]
    argument_string = r'-v "/var/test:/var/task:ro"'
    _, _, mounts, _, _ = Util.parse_additional_flags(argument_string)
    assert mounts == [("/var/test", "/var/task")]

    # Test file paths
    argument_string = r'-v "/tmp/test.jar:/tmp/foo bar/test.jar"'
    _, _, mounts, _, _ = Util.parse_additional_flags(argument_string)
    assert mounts == [(r"/tmp/test.jar", "/tmp/foo bar/test.jar")]
    argument_string = r'-v "/tmp/test-foo_bar.jar:/tmp/test-foo_bar2.jar"'
    _, _, mounts, _, _ = Util.parse_additional_flags(argument_string)
    assert mounts == [(r"/tmp/test-foo_bar.jar", "/tmp/test-foo_bar2.jar")]

    # Test file paths
    argument_string = r'-v "/tmp/test.jar:/tmp/foo bar/test.jar" --network mynet123'
    _, _, _, _, network = Util.parse_additional_flags(argument_string)
    assert network == "mynet123"


def list_in(a, b):
    return len(a) <= len(b) and any(
        map(lambda x: b[x : x + len(a)] == a, range(len(b) - len(a) + 1))
    )
