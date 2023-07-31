from __future__ import annotations

import logging
import time
from typing import Generator

import pytest

from localstack import config
from localstack import constants
from localstack.utils.container_utils.container_client import (
    ContainerClient,
    ContainerConfiguration,
    ContainerException,
    PortMappings,
)
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def _setup_cli_environment(monkeypatch):
    # normally we are setting LOCALSTACK_CLI in localstack/cli/main.py, which is not actually run in the tests
    monkeypatch.setenv("LOCALSTACK_CLI", "1")
    monkeypatch.setattr(config, "dirs", config.Directories.for_cli())


class LocalStackContainer:
    def __init__(self, client: ContainerClient, config: ContainerConfiguration):
        self.client = client
        self.config = config
        self.container_id: str | None = None

    def start(self) -> "LocalStackContainer":
        self.container_id = self.client.create_container_from_config(self.config)
        try:
            self.client.start_container(self.container_id)
        except ContainerException as e:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.exception("Error while starting LocalStack container")
            else:
                LOG.error(
                    "Error while starting LocalStack container: %s\n%s", e.message, to_str(e.stderr)
                )
            raise
        return self

    def run(self) -> "LocalStackContainer":
        self.start()
        return self.wait_until_ready()

    def is_up(self):
        if self.container_id is None:
            return False

        logs = self.client.get_container_logs(self.container_id)
        return constants.READY_MARKER_OUTPUT in logs.splitlines()

    def wait_until_ready(
        self, max_retries: int = 30, sleep_time: float = 0.2
    ) -> "LocalStackContainer":
        for _ in range(max_retries):
            if self.is_up():
                return self

            time.sleep(sleep_time)

        # TODO: bad error message
        raise RuntimeError("Container did not start")

    def remove(self):
        self.client.stop_container(self.container_id, timeout=10)
        self.client.remove_container(self.container_id, force=True, check_existence=False)


class ContainerFactory:
    def __init__(self):
        self.client = DOCKER_CLIENT
        self._containers: list[LocalStackContainer] = []

    def __call__(
        self, pro: bool = False, publish: list[int] | None = None, /, **kwargs
    ) -> LocalStackContainer:
        config = ContainerConfiguration(**kwargs)
        if pro:
            config.env_vars["GATEWAY_LISTEN"] = "0.0.0.0:4566,0.0.0.0:443"
            config.env_vars["LOCALSTACK_API_KEY"] = "test"

        port_mappings = PortMappings()
        if publish:
            for port in publish:
                port_mappings.add(port)
        else:
            port_mappings.add(4566)

        config.ports = port_mappings
        container = LocalStackContainer(self.client, config)
        self._containers.append(container)
        return container

    def remove_all_containers(self):
        failures = []
        for container in self._containers:
            try:
                container.remove()
            except Exception as e:
                failures.append((container, e))

        if failures:
            for container, ex in failures:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.error(f"Failed to remove container {container.container_id}", exc_info=ex)
                else:
                    LOG.error(f"Failed to remove container {container.container_id}")


@pytest.fixture(scope="session")
def container_factory() -> Generator[ContainerFactory, None, None]:
    factory = ContainerFactory()
    yield factory
    factory.remove_all_containers()
