import textwrap

import pytest
import requests

from localstack import config
from localstack.config import in_docker
from localstack.utils.bootstrap import (
    Container,
    ContainerConfigurators,
    LocalstackContainerServer,
    get_gateway_url,
)
from localstack.utils.container_utils.container_client import VolumeBind


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestLocalstackContainerServer:
    def test_lifecycle(self):
        server = LocalstackContainerServer()
        server.container.config.ports.add(config.EDGE_PORT)

        assert not server.is_up()
        try:
            server.start()
            assert server.wait_is_up(60)

            response = requests.get("http://localhost:4566/_localstack/health")
            assert response.ok, "expected health check to return OK: %s" % response.text
        finally:
            server.shutdown()

        server.join(30)
        assert not server.is_up()


def test_common_container_fixture_configurators(
    container_factory, wait_for_localstack_ready, tmp_path
):
    volume = tmp_path / "localstack-volume"
    volume.mkdir(parents=True)

    container: Container = container_factory(
        configurators=[
            ContainerConfigurators.random_container_name,
            ContainerConfigurators.random_gateway_port,
            ContainerConfigurators.random_service_port_range(20),
            ContainerConfigurators.debug,
            ContainerConfigurators.mount_localstack_volume(volume),
        ]
    )

    with container.start() as running_container:
        wait_for_localstack_ready(running_container)

        url = get_gateway_url(container)

        # port was exposed correctly
        response = requests.get(f"{url}/_localstack/health")
        assert response.ok

        # volume was mounted correctly
        assert (volume / "cache" / "machine.json").exists()

        inspect = running_container.inspect()
        # volume was mounted correctly
        assert inspect["Mounts"] == [
            {
                "Type": "bind",
                "Source": str(volume),
                "Destination": "/var/lib/localstack",
                "Mode": "",
                "RW": True,
                "Propagation": "rprivate",
            }
        ]
        # debug was set
        assert "DEBUG=1" in inspect["Config"]["Env"]
        # container name was set
        assert f"MAIN_CONTAINER_NAME={container.config.name}" in inspect["Config"]["Env"]


def test_custom_command_configurator(container_factory, tmp_path):
    tmp_dir = tmp_path

    script = tmp_dir / "my-command.sh"
    script.write_text(
        textwrap.dedent(
            """
            #!/bin/bash
            echo "foobar"
            echo "$@"
            """
        ).strip()
    )
    script.chmod(0o777)

    container: Container = container_factory(
        configurators=[
            ContainerConfigurators.random_container_name,
            ContainerConfigurators.custom_command(
                ["/tmp/pytest-tmp-path/my-command.sh", "hello", "world"]
            ),
            ContainerConfigurators.volume(VolumeBind(str(tmp_path), "/tmp/pytest-tmp-path")),
        ],
        remove=False,
    )

    with container.start() as running_container:
        assert running_container.wait_until_ready(timeout=5)
        assert running_container.get_logs().strip() == "foobar\nhello world"
