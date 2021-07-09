import unittest
import uuid

from localstack.utils.bootstrap import run
from localstack.utils.docker import DOCKER_CLIENT, DockerContainerStatus


class TestContainerClient(unittest.TestCase):
    def test_start_container(self):
        container_name = f"test_{uuid.uuid4()}"
        output = DOCKER_CLIENT.create_container(
            "alpine", name=container_name, command=["sh", "-c", "while true; do sleep 1; done"]
        )
        container_id = output.strip()
        DOCKER_CLIENT.start_container(container_id)
        self.assertEqual(
            DockerContainerStatus.UP, DOCKER_CLIENT.get_container_status(container_name)
        )

        run(f"docker kill {container_id}")
        self.assertEqual(
            DockerContainerStatus.DOWN, DOCKER_CLIENT.get_container_status(container_name)
        )
        run(f"docker rm {container_id}")
        self.assertEqual(
            DockerContainerStatus.NOT_EXISTANT, DOCKER_CLIENT.get_container_status(container_name)
        )
