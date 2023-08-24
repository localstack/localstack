from __future__ import annotations

import logging
import os
import shlex
from typing import Generator

import pytest

from localstack import config
from localstack.utils.bootstrap import Container, get_docker_image_to_start
from localstack.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def _setup_cli_environment(monkeypatch):
    # normally we are setting LOCALSTACK_CLI in localstack/cli/main.py, which is not actually run
    # in the tests
    monkeypatch.setenv("LOCALSTACK_CLI", "1")
    monkeypatch.setattr(config, "dirs", config.Directories.for_cli())


# TODO: for now we duplicate this fixture since we can't enable the fixture plugin, and can't
#  move the fixture to tests/conftest.py because some unit tests are dependent on its current path
@pytest.fixture
def cleanups():
    cleanup_fns = []

    yield cleanup_fns

    for cleanup_callback in cleanup_fns[::-1]:
        try:
            cleanup_callback()
        except Exception as e:
            LOG.warning("Failed to execute cleanup", exc_info=e)


class ContainerFactory:
    def __init__(self):
        self._containers: list[Container] = []

    def __call__(
        self,
        # convenience properties
        pro: bool = False,
        publish: list[int] | None = None,
        # ContainerConfig properties
        **kwargs,
    ) -> Container:
        port_configuration = PortMappings()
        if publish:
            for port in publish:
                port_configuration.add(port)

        container_configuration = ContainerConfiguration(
            image_name=get_docker_image_to_start(),
            name=config.MAIN_CONTAINER_NAME,
            volumes=VolumeMappings(),
            remove=True,
            ports=port_configuration,
            entrypoint=os.environ.get("ENTRYPOINT"),
            command=shlex.split(os.environ.get("CMD", "")) or None,
            env_vars={},
        )

        # allow for randomised container names
        container_configuration.name = None

        # handle the convenience options
        if pro:
            container_configuration.env_vars["GATEWAY_LISTEN"] = "0.0.0.0:4566,0.0.0.0:443"
            container_configuration.env_vars["LOCALSTACK_API_KEY"] = "test"

        # override values from kwargs
        for key, value in kwargs.items():
            setattr(container_configuration, key, value)

        container = Container(container_configuration)

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
