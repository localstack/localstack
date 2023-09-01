from __future__ import annotations

import logging
import os
import shlex
from typing import Generator

import pytest

from localstack import config, constants
from localstack.utils.bootstrap import Container, RunningContainer, get_docker_image_to_start
from localstack.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)


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


@pytest.fixture(scope="session", autouse=True)
def setup_host_config_dirs():
    config.dirs.mkdirs()


@pytest.fixture
def wait_for_localstack_ready():
    def _wait_for(container: RunningContainer, timeout: float | None = None):
        container.wait_until_ready(timeout)

        poll_condition(
            lambda: constants.READY_MARKER_OUTPUT in container.get_logs().splitlines(),
            timeout=timeout,
        )

    return _wait_for
