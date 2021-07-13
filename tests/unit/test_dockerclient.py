import json
import logging
import unittest
from typing import List
from unittest.mock import patch

from localstack import config
from localstack.utils.docker import CmdDockerClient, DockerContainerStatus

LOG = logging.getLogger(__name__)


class TestDockerClient(unittest.TestCase):
    def _docker_cmd(self) -> List[str]:
        """Return the string to be used for running Docker commands."""
        return config.DOCKER_CMD.split()

    @patch("localstack.utils.docker.safe_run")
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

    @patch("localstack.utils.docker.safe_run")
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


def list_in(a, b):
    return len(a) <= len(b) and any(
        map(lambda x: b[x : x + len(a)] == a, range(len(b) - len(a) + 1))
    )
