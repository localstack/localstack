import threading

import pytest
import requests
from botocore.config import Config

from localstack.config import in_docker
from localstack.testing.pytest import markers
from localstack.testing.pytest.container import ContainerFactory
from localstack.utils.bootstrap import (
    ContainerConfigurators,
    get_gateway_url,
)
from localstack.utils.strings import short_uid

pytestmarks = [
    pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker"),
    markers.aws.only_localstack,
]


class TestBlockingServiceShutdown:
    def test_shutdown_during_sqs_long_poll(
        self,
        container_factory: ContainerFactory,
        wait_for_localstack_ready,
        aws_client_factory,
    ):
        # This will test whether SQS long-polling calls can be gracefully terminated
        # and respond without error when LocalStack is signalled for shutdown.

        ## SETUP LOCALSTACK CONTAINER

        ls_container = container_factory(
            configurators=[
                ContainerConfigurators.random_container_name,
                ContainerConfigurators.random_gateway_port,
                ContainerConfigurators.random_service_port_range(20),
                ContainerConfigurators.env_vars(
                    {"SERVICES": "sqs", "SQS_DISABLE_CLOUDWATCH_METRICS": "1"}
                ),
            ]
        )
        running_container = ls_container.start()
        wait_for_localstack_ready(running_container)
        url = get_gateway_url(ls_container)

        response = requests.get(f"{url}/_localstack/health")
        assert response.ok

        # activate sqs service
        client = aws_client_factory(endpoint_url=url)
        result = client.sqs.list_queues()
        assert result

        ## SETUP TEST VARIABLES

        # 5 polling threads + 1 main thread
        sqs_poller_count = 5
        completed_barrier = threading.Barrier(
            sqs_poller_count + 1
        )  # blocks until all threads have completed

        errored_event = threading.Event()  # flag to ensure no errors were encounterd in threads

        boto_config = Config(retries={"total_max_attempts": 1})  # disable retries
        aws_client = aws_client_factory(config=boto_config, endpoint_url=url)

        def long_poll_queue(queue_url: str):
            def _receive_messages():
                try:
                    _ = aws_client.sqs.receive_message(
                        QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=20
                    )
                except Exception:
                    # We expect all ReceiveMessage calls to end gracefully with a 200 response
                    errored_event.set()
                finally:
                    completed_barrier.wait()

            return _receive_messages

        for _ in range(sqs_poller_count):
            queue_name = f"queue-{short_uid()}"
            # Do not use fixtures since the queues will be torn down when LS restarts
            queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
            threading.Thread(target=long_poll_queue(queue_url), daemon=False).start()

        # Restart LocalStack
        _ = requests.post(f"{url}/_localstack/health", json={"action": "restart"})
        wait_for_localstack_ready(running_container)

        # Wait for 5 seconds for all threads to finish
        completed_barrier.wait(5)

        assert not errored_event.is_set(), (
            "Expected all ReceiveMessage calls to shutdown gracefully"
        )
