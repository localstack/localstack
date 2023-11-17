import logging
import os
import shlex
import threading
from typing import Callable, Generator, List, Optional

import pytest

from localstack import constants
from localstack.utils.bootstrap import Container, RunningContainer, get_docker_image_to_start
from localstack.utils.container_utils.container_client import (
    CancellableStream,
    ContainerConfiguration,
    ContainerConfigurator,
    NoSuchNetwork,
    PortMappings,
    VolumeMappings,
)
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)

ENV_TEST_CONTAINER_MOUNT_SOURCES = "TEST_CONTAINER_MOUNT_SOURCES"
"""Environment variable used to indicate that we should mount localstack source files into the container."""


class ContainerFactory:
    def __init__(self):
        self._containers: List[Container] = []

    def __call__(
        self,
        # convenience properties
        pro: bool = False,
        publish: Optional[List[int]] = None,
        configurators: Optional[List[ContainerConfigurator]] = None,
        # ContainerConfig properties
        **kwargs,
    ) -> Container:
        port_configuration = PortMappings()
        if publish:
            for port in publish:
                port_configuration.add(port)

        container_configuration = ContainerConfiguration(
            image_name=get_docker_image_to_start(),
            name=None,
            volumes=VolumeMappings(),
            remove=True,
            ports=port_configuration,
            entrypoint=os.environ.get("ENTRYPOINT"),
            command=shlex.split(os.environ.get("CMD", "")) or None,
            env_vars={},
        )

        # handle the convenience options
        if pro:
            container_configuration.env_vars["GATEWAY_LISTEN"] = "0.0.0.0:4566,0.0.0.0:443"
            container_configuration.env_vars["LOCALSTACK_API_KEY"] = os.environ.get(
                "LOCALSTACK_API_KEY", "test"
            )

        # override values from kwargs
        for key, value in kwargs.items():
            setattr(container_configuration, key, value)

        container = Container(container_configuration)

        if configurators:
            container.configure(configurators)

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


class LogStreamFactory:
    def __init__(self):
        self.streams: list[CancellableStream] = []
        self.stop_events: list[threading.Event] = []
        self.mutex = threading.RLock()

    def __call__(self, container: Container, callback: Callable[[str], None] = None) -> None:
        """
        Create and start a new log stream thread. The thread starts immediately and waits for the container
        to move into a running state. Once it's running, it will attempt to stream the container logs. If
        the container is already closed by then, an exception will be raised in the thread and it will
        terminate.

        :param container: the container to stream the logs from
        :param callback: an optional callback called on each log line.
        """
        stop = threading.Event()
        self.stop_events.append(stop)

        def _can_continue():
            if stop.is_set():
                return True
            if not container.running_container:
                return False
            return container.running_container.is_running()

        def _run_stream_container_logs():
            # wait until either the container is running or the test was terminated
            poll_condition(_can_continue)
            with self.mutex:
                if stop.is_set():
                    return

                stream = container.running_container.stream_logs()
                self.streams.append(stream)

            # create a default logger
            if callback is None:
                log = logging.getLogger(f"container.{container.running_container.name}")
                log.setLevel(level=logging.DEBUG)
                _callback = log.debug
            else:
                _callback = callback

            for line in stream:
                _callback(line.decode("utf-8").rstrip(os.linesep))

        t = threading.Thread(
            target=_run_stream_container_logs,
            name=threading._newname("log-stream-%d"),
            daemon=True,
        )
        t.start()

    def close(self):
        with self.mutex:
            for _event in self.stop_events:
                _event.set()

        for _stream in self.streams:
            _stream.close()


@pytest.fixture
def container_factory() -> Generator[ContainerFactory, None, None]:
    factory = ContainerFactory()
    yield factory
    factory.remove_all_containers()


@pytest.fixture(scope="session")
def wait_for_localstack_ready():
    def _wait_for(container: RunningContainer, timeout: Optional[float] = None):
        container.wait_until_ready(timeout)

        poll_condition(
            lambda: constants.READY_MARKER_OUTPUT in container.get_logs().splitlines(),
            timeout=timeout,
        )

    return _wait_for


@pytest.fixture
def ensure_network():
    networks = []

    def _ensure_network(name: str):
        try:
            DOCKER_CLIENT.inspect_network(name)
        except NoSuchNetwork:
            DOCKER_CLIENT.create_network(name)
            networks.append(name)

    yield _ensure_network

    for network_name in networks:
        # detach attached containers
        details = DOCKER_CLIENT.inspect_network(network_name)
        for container_id in details.get("Containers", []):
            DOCKER_CLIENT.disconnect_container_from_network(
                network_name=network_name, container_name_or_id=container_id
            )
        DOCKER_CLIENT.delete_network(network_name)


@pytest.fixture
def docker_network(ensure_network):
    network_name = f"net-{short_uid()}"
    ensure_network(network_name)
    return network_name


@pytest.fixture
def dns_query_from_container(container_factory: ContainerFactory, monkeypatch):
    """
    Run the LocalStack container after installing dig
    """
    containers: list[RunningContainer] = []

    def query(name: str, ip_address: str, port: int = 53, **kwargs) -> tuple[bytes, bytes]:
        container = container_factory(
            image_name="localstack/localstack",
            command=["infinity"],
            entrypoint="sleep",
            **kwargs,
        )
        running_container = container.start()
        containers.append(running_container)

        command = [
            "bash",
            "-c",
            f"apt-get install -y --no-install-recommends dnsutils >/dev/null && dig +short @{ip_address} -p {port} {name}",
        ]
        # The CmdDockerClient has its output set to a logfile. We must patch
        # the client to ensure the output of the command goes to stdout. We use
        # a monkeypatch.context here to make sure the scope of the patching is
        # minimal.
        with monkeypatch.context() as m:
            m.setattr(running_container.container_client, "default_run_outfile", None)
            stdout, stderr = running_container.exec_in_container(command=command)
        return stdout, stderr

    yield query

    for container in containers:
        container.shutdown()


@pytest.fixture
def stream_container_logs() -> Generator[LogStreamFactory, None, None]:
    """
    Factory fixture for streaming logs of containers in the background. Invoke as follows::

        def test_container(container_factory, stream_container_logs):
            container: Container = container_factory(...)

            with container.start() as running_container:
                stream_container_logs(container)

    This will start a background thread that streams the container logs to a python logger
    ``containers.<container-name>``. You can find it in the logs as::

        2023-09-03T18:49:06.236 DEBUG --- [log-stream-1] container.localstack-5a4c3678 : foobar
        2023-09-03T18:49:06.236 DEBUG --- [log-stream-1] container.localstack-5a4c3678 : hello world

    The function ``stream_container_logs`` also accepts a ``callback`` argument that can be used to
    overwrite the default logging mechanism. For example, to print every log line directly to stdout, call::

        stream_container_logs(container, callback=print)

    :return: a factory to start log streams
    """
    factory = LogStreamFactory()
    yield factory
    factory.close()
