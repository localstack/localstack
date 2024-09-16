import json

import pytest
import requests

from localstack.config import in_docker
from localstack.testing.pytest.container import ContainerFactory
from localstack.utils.bootstrap import ContainerConfigurators
from localstack.utils.container_utils.container_client import VolumeBind

pytestmarks = pytest.mark.skipif(
    condition=in_docker(), reason="cannot run bootstrap tests in docker"
)


class TestInitHooks:
    def test_shutdown_hooks(
        self,
        container_factory: ContainerFactory,
        stream_container_logs,
        wait_for_localstack_ready,
        tmp_path,
    ):
        volume = tmp_path / "volume"

        # prepare shutdown hook scripts
        shutdown_hooks = tmp_path / "shutdown.d"
        shutdown_hooks.mkdir()
        shutdown_00 = shutdown_hooks / "on_shutdown_00.sh"
        shutdown_01 = shutdown_hooks / "on_shutdown_01.sh"
        shutdown_00.touch(mode=0o777)
        shutdown_01.touch(mode=0o777)
        shutdown_00.write_text("#!/bin/bash\necho 'foobar' > /var/lib/localstack/shutdown_00.log")
        shutdown_01.write_text(
            "#!/bin/bash\ncurl -s localhost:4566/_localstack/init &> /var/lib/localstack/shutdown_01.log"
        )

        # set up container
        container = container_factory(
            configurators=[
                ContainerConfigurators.debug,
                ContainerConfigurators.mount_docker_socket,
                ContainerConfigurators.default_gateway_port,
                ContainerConfigurators.mount_localstack_volume(volume),
                ContainerConfigurators.volume(
                    VolumeBind(str(shutdown_hooks), "/etc/localstack/init/shutdown.d")
                ),
            ]
        )
        running_container = container.start(attach=False)
        stream_container_logs(container)
        wait_for_localstack_ready(running_container)

        # check that the init scripts are registered correctly
        r = requests.get("http://127.0.0.1:4566/_localstack/init")
        assert r.status_code == 200
        assert r.json() == {
            "completed": {
                "BOOT": True,
                "READY": True,
                "SHUTDOWN": False,
                "START": True,
            },
            "scripts": [
                {
                    "name": "on_shutdown_00.sh",
                    "stage": "SHUTDOWN",
                    "state": "UNKNOWN",
                },
                {
                    "name": "on_shutdown_01.sh",
                    "stage": "SHUTDOWN",
                    "state": "UNKNOWN",
                },
            ],
        }

        # programmatically shut down the container to trigger the shutdown hooks
        running_container.shutdown()

        # verify that they were executed correctly by checking their logs
        shutdown_00_log = volume / "shutdown_00.log"
        shutdown_01_log = volume / "shutdown_01.log"

        assert shutdown_00_log.is_file()
        assert shutdown_00_log.read_text() == "foobar\n"

        assert shutdown_01_log.is_file()
        # check the state of hook scripts
        assert json.loads(shutdown_01_log.read_text()) == {
            "completed": {
                "BOOT": True,
                "READY": True,
                "SHUTDOWN": False,
                "START": True,
            },
            "scripts": [
                {
                    "name": "on_shutdown_00.sh",
                    "stage": "SHUTDOWN",
                    "state": "SUCCESSFUL",
                },
                {
                    "name": "on_shutdown_01.sh",
                    "stage": "SHUTDOWN",
                    "state": "RUNNING",
                },
            ],
        }
