import json
import logging
import unittest
from unittest.mock import call, patch

from localstack.utils.docker import CmdDockerClient, DockerContainerStatus

LOG = logging.getLogger(__name__)


class TestDockerClient(unittest.TestCase):
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
        self.assertEqual(test_container, container_list[0])
        call_arguments = run_mock.mock_calls[0].args[0]
        self.assertTrue(list_in(["docker", "ps"], call_arguments))
        self.assertIn("-a", call_arguments)
        self.assertIn("--format", call_arguments)

    @patch("localstack.utils.docker.safe_run")
    def test_container_status(self, run_mock):
        test_output = 'Up 2 minutes - localstack_main'
        run_mock.return_value = test_output
        docker_client = CmdDockerClient()
        status = docker_client.get_container_status('localstack_main')
        self.assertEqual(DockerContainerStatus.UP, status)
        run_mock.return_value = 'Exited (0) 1 minute ago - localstack_main'
        status = docker_client.get_container_status('localstack_main')
        self.assertEqual(DockerContainerStatus.DOWN, status)
        run_mock.return_value = 'STATUS    NAME'
        status = docker_client.get_container_status('localstack_main')
        self.assertEqual(DockerContainerStatus.NOT_EXISTANT, status)



def list_in(a, b):
    return len(a) <= len(b) and any(
        map(lambda x: b[x : x + len(a)] == a, range(len(b) - len(a) + 1))
    )
