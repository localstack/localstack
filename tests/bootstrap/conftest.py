from __future__ import annotations

import logging
from typing import Generator

import pytest

from localstack import config
from localstack.utils.container_utils.container_client import (
    PortMappings,
)
from localstack.utils.bootstrap import LocalstackContainer
from localstack.utils.container_utils.container_client import PortMappings

LOG = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def _setup_cli_environment(monkeypatch):
    # normally we are setting LOCALSTACK_CLI in localstack/cli/main.py, which is not actually run in the tests
    monkeypatch.setenv("LOCALSTACK_CLI", "1")
    monkeypatch.setattr(config, "dirs", config.Directories.for_cli())


class ContainerFactory:
    def __init__(self):
        self._containers: list[LocalstackContainer] = []

    def __call__(
        self,
        # convenience properties
        pro: bool = False,
        publish: list[int] | None = None,
        # ContainerConfig properties
        **kwargs,
    ) -> LocalstackContainer:
        container = LocalstackContainer()

        # override some default configuration
        container.config.ports = PortMappings()

        # allow for randomised container names
        container.config.name = None

        for key, value in kwargs.items():
            setattr(container.config, key, value)

        # handle the convenience options
        if pro:
            container.config.env_vars["GATEWAY_LISTEN"] = "0.0.0.0:4566,0.0.0.0:443"
            container.config.env_vars["LOCALSTACK_API_KEY"] = "test"

        port_mappings = PortMappings()
        if publish:
            for port in publish:
                port_mappings.add(port)
        container.config.ports = port_mappings

        # track the container so we can remove it later
        self._containers.append(container)
        return container

    def remove_all_containers(self):
        failures = []
        for container in self._containers:
            if not container.running_container:
                # container is not running
                continue

            try:
                container.running_container.shutdown()
            except Exception as e:
                failures.append((container, e))

        if failures:
            for container, ex in failures:
                LOG.error(
                    f"Failed to remove container {container.running_container.id}",
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )


@pytest.fixture(scope="session")
def container_factory() -> Generator[ContainerFactory, None, None]:
    factory = ContainerFactory()
    yield factory
    factory.remove_all_containers()
