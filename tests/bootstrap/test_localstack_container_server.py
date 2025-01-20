import pytest
import requests

from localstack import config
from localstack.config import in_docker
from localstack.utils.bootstrap import LocalstackContainerServer
from localstack.utils.sync import poll_condition


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestLocalstackContainerServer:
    def test_lifecycle(self):
        server = LocalstackContainerServer()
        server.container.config.ports.add(config.GATEWAY_LISTEN[0].port)

        assert not server.is_up()
        try:
            server.start()
            assert server.wait_is_up(60)

            health_response = requests.get("http://localhost:4566/_localstack/health")
            assert health_response.ok, (
                "expected health check to return OK: %s" % health_response.text
            )

            restart_response = requests.post(
                "http://localhost:4566/_localstack/health", json={"action": "restart"}
            )
            assert restart_response.ok, (
                "expected restart command via health endpoint to return OK: %s"
                % restart_response.text
            )

            def check_restart_successful():
                logs = server.container.get_logs()
                if logs.count("Ready.") < 2:
                    # second ready marker still missing
                    return False

                health_response_after_retry = requests.get(
                    "http://localhost:4566/_localstack/health"
                )
                if not health_response_after_retry.ok:
                    # health endpoint not yet ready again
                    return False

                # second restart marker found and health endpoint returned with 200!
                return True

            assert poll_condition(
                check_restart_successful, 45, 1
            ), "expected two Ready markers in the logs after triggering restart via health endpoint"
        finally:
            server.shutdown()

        server.join(30)
        assert not server.is_up()
