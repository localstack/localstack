import os
import subprocess
import time
from typing import Dict

import pytest

LOCALSTACK_TEST_PORT = 7777
WELL_KNOWN_LOCALSTACK_DOCKER_IMAGES = [
    "localstack/localstack-pro:latest",
    "localstack/localstack-pro:2.0",
    "localstack/localstack:1.4",
    # "localstack/localstack:1.3",
    # "localstack/localstack:1.2",
    # "localstack/localstack:1.1",
    # "localstack/localstack:1.0",
    # "localstack/localstack:0.14"
    # "localstack/localstack:0.13",
    # "localstack/localstack:0.11",
    # "localstack/localstack:0.10",
]


def configure_string(input: str, **kwargs: Dict[str, str]) -> str:
    output = input
    for key, value in kwargs.items():
        output = output.replace("{{" + key + "}}", str(value))
    return output


def wait_for_startup(timeoutSeconds: float, port: int = 4566) -> bool:
    print(f"waiting for localstack to be up, timeout: {timeoutSeconds}seconds")
    command = f"curl --fail --silent http://localhost:{port}/_localstack/health"
    start_time = time.monotonic()
    last_return_code = -1

    while last_return_code != 0:
        curl_process = subprocess.run(command, shell=True, check=False, timeout=2)
        last_return_code = curl_process.returncode

        if time.monotonic() - start_time > timeoutSeconds:
            return False

        time.sleep(0.5)

    print(f"waited on localstack for {time.monotonic() - start_time} seconds")
    return True


class LocalStackDocker:
    def __init__(self, image: str, port: int, api_key: str) -> None:
        self.port = port
        compose_template = """
version: "3.9"
services:
  localstack:
    image: {{image}}
    ports:
    - "{{port}}:4566"
    environment:
      - LOCALSTACK_API_KEY={{api_key}}
    volumes:
      - ./.test-tmp:/var/lib/localstack/cache
    """
        self.compose_yml = configure_string(
            compose_template, image=image, port=port, api_key=api_key
        )

    def __enter__(self) -> None:
        command = "docker-compose -f - up -d"
        try:
            subprocess.run(
                command,
                input=self.compose_yml.encode(),
                shell=True,
                check=True,
                capture_output=True,
                timeout=60,
            )
            assert wait_for_startup(30, port=self.port)
        except subprocess.CalledProcessError as e:
            pytest.fail(f"Error starting Localstack: {e} \n {e.stdout} \n {e.stderr}")

    def __exit__(self, exctype, excinst, exctb):
        command = "docker-compose -f - down"
        try:
            subprocess.run(
                command,
                input=self.compose_yml.encode(),
                shell=True,
                check=True,
                capture_output=True,
                timeout=60,
            )
        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"Error shutting down localstack: {e}  \nstdout:\n{e.stdout} \nstderr:\n{e.stderr}"
            )


@pytest.fixture
def localstack_docker(request):
    docker_image = getattr(request, "param", "localstack/localstack-pro:latest")
    api_key = (
        os.getenv("LOCALSTACK_API_KEY") or os.getenv("PRO_ACTIVATION_KEY") or "no-api-key-given"
    )

    with LocalStackDocker(docker_image, LOCALSTACK_TEST_PORT, api_key):
        yield
