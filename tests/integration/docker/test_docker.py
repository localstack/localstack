import uuid

from localstack.utils.bootstrap import run
from localstack.utils.docker import DockerContainerStatus


def test_start_and_stop_container(docker_client):
    container_name = f"test_{uuid.uuid4()}"
    output = docker_client.create_container(
        "alpine", name=container_name, command=["sh", "-c", "while true; do sleep 1; done"]
    )
    container_id = output.strip()
    docker_client.start_container(container_id)

    assert DockerContainerStatus.UP == docker_client.get_container_status(container_name)
    run(f"docker kill {container_id}")
    assert DockerContainerStatus.DOWN == docker_client.get_container_status(container_name)
    run(f"docker rm {container_id}")
    assert DockerContainerStatus.NOT_EXISTANT == docker_client.get_container_status(container_name)
