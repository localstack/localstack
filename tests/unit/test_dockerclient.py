import json
import logging
from typing import List
from unittest.mock import patch

import pytest

from localstack import config
from localstack.utils.bootstrap import extract_port_flags
from localstack.utils.container_utils.container_client import (
    DockerContainerStatus,
    PortMappings,
    Util,
)
from localstack.utils.container_utils.docker_cmd_client import CmdDockerClient

LOG = logging.getLogger(__name__)


class TestDockerClient:
    def _docker_cmd(self) -> List[str]:
        """Return the string to be used for running Docker commands."""
        return config.DOCKER_CMD.split()

    @patch("localstack.utils.container_utils.docker_cmd_client.run")
    def test_list_containers(self, run_mock):
        mock_container = {
            "ID": "00000000a1",
            "Image": "localstack/localstack",
            "Names": "localstack_main",
            "Labels": "authors=LocalStack Contributors",
            "State": "running",
        }
        return_container = {
            "id": mock_container["ID"],
            "image": mock_container["Image"],
            "name": mock_container["Names"],
            "labels": mock_container["Labels"],
            "status": mock_container["State"],
        }
        run_mock.return_value = json.dumps(mock_container)
        docker_client = CmdDockerClient()
        container_list = docker_client.list_containers()
        call_arguments = run_mock.call_args[0][0]
        LOG.info("Intercepted call arguments: %s", call_arguments)
        assert container_list[0] == return_container
        assert list_in(self._docker_cmd() + ["ps"], call_arguments)
        assert "-a" in call_arguments
        assert "--format" in call_arguments

    @patch("localstack.utils.container_utils.docker_cmd_client.run")
    def test_container_status(self, run_mock):
        test_output = "Up 2 minutes - localstack_main"
        run_mock.return_value = test_output
        docker_client = CmdDockerClient()
        status = docker_client.get_container_status("localstack_main")
        assert status == DockerContainerStatus.UP
        run_mock.return_value = "Exited (0) 1 minute ago - localstack_main"
        status = docker_client.get_container_status("localstack_main")
        assert status == DockerContainerStatus.DOWN
        run_mock.return_value = "STATUS    NAME"
        status = docker_client.get_container_status("localstack_main")
        assert status == DockerContainerStatus.NON_EXISTENT


def test_argument_parsing():
    test_port_string = "-p 80:8080/udp"
    test_port_string_with_host = "-p 127.0.0.1:6000:7000/tcp"
    test_port_string_many_to_one = "-p 9230-9231:9230"
    test_env_string = "-e TEST_ENV_VAR=test_string=123"
    test_mount_string = "-v /var/test:/opt/test"
    argument_string = f"{test_port_string} {test_env_string} {test_mount_string} {test_port_string_with_host} {test_port_string_many_to_one}"
    env_vars = {}
    ports = PortMappings()
    mounts = []
    Util.parse_additional_flags(argument_string, env_vars, ports, mounts)
    assert env_vars == {"TEST_ENV_VAR": "test_string=123"}
    assert ports.to_str() == "-p 80:8080/udp -p 6000:7000 -p 9230-9231:9230"
    assert mounts == [("/var/test", "/opt/test")]
    argument_string = (
        "--add-host host.docker.internal:host-gateway --add-host arbitrary.host:127.0.0.1"
    )
    flags = Util.parse_additional_flags(argument_string, env_vars, ports, mounts)
    assert {
        "host.docker.internal": "host-gateway",
        "arbitrary.host": "127.0.0.1",
    } == flags.extra_hosts

    with pytest.raises(NotImplementedError):
        argument_string = "--somerandomargument"
        Util.parse_additional_flags(argument_string, env_vars, ports, mounts)
    with pytest.raises(ValueError):
        argument_string = "--publish 80:80:80:80"
        Util.parse_additional_flags(argument_string, env_vars, ports, mounts)

    # Test windows paths
    argument_string = r'-v "C:\Users\SomeUser\SomePath:/var/task"'
    flags = Util.parse_additional_flags(argument_string)
    assert flags.mounts == [(r"C:\Users\SomeUser\SomePath", "/var/task")]
    argument_string = r'-v "C:\Users\SomeUser\SomePath:/var/task:ro"'
    flags = Util.parse_additional_flags(argument_string)
    assert flags.mounts == [(r"C:\Users\SomeUser\SomePath", "/var/task")]
    argument_string = r'-v "C:\Users\Some User\Some Path:/var/task:ro"'
    flags = Util.parse_additional_flags(argument_string)
    assert flags.mounts == [(r"C:\Users\Some User\Some Path", "/var/task")]
    argument_string = r'-v "/var/test:/var/task:ro"'
    flags = Util.parse_additional_flags(argument_string)
    assert flags.mounts == [("/var/test", "/var/task")]

    # Test file paths
    argument_string = r'-v "/tmp/test.jar:/tmp/foo bar/test.jar"'
    flags = Util.parse_additional_flags(argument_string)
    assert flags.mounts == [(r"/tmp/test.jar", "/tmp/foo bar/test.jar")]
    argument_string = r'-v "/tmp/test-foo_bar.jar:/tmp/test-foo_bar2.jar"'
    flags = Util.parse_additional_flags(argument_string)
    assert flags.mounts == [(r"/tmp/test-foo_bar.jar", "/tmp/test-foo_bar2.jar")]

    # Test file paths
    argument_string = r'-v "/tmp/test.jar:/tmp/foo bar/test.jar" --network mynet123'
    flags = Util.parse_additional_flags(argument_string)
    assert flags.network == "mynet123"

    # Test labels
    argument_string = r"--label foo=bar.123"
    flags = Util.parse_additional_flags(argument_string)
    assert flags.labels == {"foo": "bar.123"}
    argument_string = r'--label foo="bar 123"'  # test with whitespaces
    flags = Util.parse_additional_flags(argument_string)
    assert flags.labels == {"foo": "bar 123"}
    argument_string = r'--label foo1="bar" --label foo2="baz"'  # test with multiple labels
    flags = Util.parse_additional_flags(argument_string)
    assert flags.labels == {"foo1": "bar", "foo2": "baz"}
    argument_string = r"--label foo=bar=baz"  # assert label values that contain equal signs
    flags = Util.parse_additional_flags(argument_string)
    assert flags.labels == {"foo": "bar=baz"}
    argument_string = r'--label ""'  # assert that we gracefully handle invalid labels
    flags = Util.parse_additional_flags(argument_string)
    assert flags.labels == {}


def list_in(a, b):
    return len(a) <= len(b) and any(
        map(lambda x: b[x : x + len(a)] == a, range(len(b) - len(a) + 1))
    )


class TestPortMappings:
    def test_extract_port_flags(self):
        port_mappings = PortMappings()
        flags = extract_port_flags("foo -p 1234:1234 bar", port_mappings=port_mappings)
        assert flags == "foo  bar"
        mapping_str = port_mappings.to_str()
        assert mapping_str == "-p 1234:1234"

        port_mappings = PortMappings()
        flags = extract_port_flags(
            "foo -p 1234:1234 bar -p 80-90:81-91 baz", port_mappings=port_mappings
        )
        assert flags == "foo  bar  baz"
        mapping_str = port_mappings.to_str()
        assert "-p 1234:1234" in mapping_str
        assert "-p 80-90:81-91" in mapping_str

    def test_overlapping_port_ranges(self):
        port_mappings = PortMappings()
        port_mappings.add(4590)
        port_mappings.add(4591)
        port_mappings.add(4593)
        port_mappings.add(4592)
        port_mappings.add(4593)
        result = port_mappings.to_str()
        # assert that ranges are non-overlapping, i.e., no duplicate ports
        assert "-p 4593:4593" in result
        assert "-p 4590-4592:4590-4592" in result

    def test_port_ranges_with_bind_host(self):
        port_mappings = PortMappings(bind_host="0.0.0.0")
        port_mappings.add(5000)
        port_mappings.add(5001)
        port_mappings.add(5003)
        port_mappings.add([5004, 5006], 9000)
        result = port_mappings.to_str()
        assert (
            result
            == "-p 0.0.0.0:5000-5001:5000-5001 -p 0.0.0.0:5003:5003 -p 0.0.0.0:5004-5006:9000"
        )

    def test_port_ranges_with_bind_host_to_dict(self):
        port_mappings = PortMappings(bind_host="0.0.0.0")
        port_mappings.add(5000, 6000)
        port_mappings.add(5001, 7000)
        port_mappings.add(5003, 8000)
        port_mappings.add([5004, 5006], 9000)
        result = port_mappings.to_dict()
        expected_result = {
            "6000/tcp": ("0.0.0.0", 5000),
            "7000/tcp": ("0.0.0.0", 5001),
            "8000/tcp": ("0.0.0.0", 5003),
            "9000/tcp": ("0.0.0.0", [5004, 5005, 5006]),
        }
        assert result == expected_result

    def test_many_to_one_adjacent_to_uniform(self):
        port_mappings = PortMappings()
        port_mappings.add(5002)
        port_mappings.add(5003)
        port_mappings.add([5004, 5006], 5004)
        expected_result = {
            "5002/tcp": 5002,
            "5003/tcp": 5003,
            "5004/tcp": [5004, 5005, 5006],
        }
        result = port_mappings.to_dict()
        assert result == expected_result

    def test_adjacent_port_to_many_to_one(self):
        port_mappings = PortMappings()
        port_mappings.add([7000, 7002], 7000)
        port_mappings.add(6999)
        expected_result = {
            "6999/tcp": 6999,
            "7000/tcp": [7000, 7001, 7002],
        }
        result = port_mappings.to_dict()
        assert result == expected_result
