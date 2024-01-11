import logging
import threading
from datetime import datetime

import pytest
from botocore.config import Config

from localstack.config import is_env_true
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

# reusing the same ENV as for test_lambda_performance
if not is_env_true("TEST_PERFORMANCE"):
    pytest.skip("Skip slow and resource-intensive tests", allow_module_level=True)


LOG = logging.getLogger(__name__)

CUSTOM_CLIENT_CONFIG_RETRY = Config(
    connect_timeout=60,
    read_timeout=60,
    retries={"max_attempts": 3},  # increase retries in case LS cannot accept connections anymore
    max_pool_connections=3000,
)


class TestCloudWatchPerformance:
    @markers.aws.only_localstack
    def test_parallel_put_metric_data_list_metrics(self, aws_client, aws_client_factory):
        num_threads = 1200
        create_barrier = threading.Barrier(num_threads)
        error_counter = Counter()
        namespace = f"namespace-{short_uid()}"

        def _put_metric_list_metrics(runner: int):
            nonlocal error_counter
            nonlocal create_barrier
            nonlocal namespace
            create_barrier.wait()
            try:
                cw_client = aws_client_factory(config=CUSTOM_CLIENT_CONFIG_RETRY).cloudwatch
                if runner % 2:
                    cw_client.put_metric_data(
                        Namespace=namespace,
                        MetricData=[
                            {
                                "MetricName": f"metric-{runner}-1",
                                "Value": 25,
                                "Unit": "Seconds",
                            },
                            {
                                "MetricName": f"metric-{runner}-2",
                                "Value": runner + 1,
                                "Unit": "Seconds",
                            },
                        ],
                    )
                else:
                    cw_client.list_metrics()
            except Exception as e:
                LOG.exception(f"runner {runner} failed: {e}")
                error_counter.increment()

        start_time = datetime.utcnow()
        thread_list = []
        for i in range(1, num_threads + 1):
            thread = threading.Thread(target=_put_metric_list_metrics, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        end_time = datetime.utcnow()
        diff = end_time - start_time
        LOG.info(f"N={num_threads} took {diff.total_seconds()} seconds")

        assert error_counter.get_value() == 0
        metrics = []
        result = aws_client.cloudwatch.list_metrics(Namespace=namespace)
        metrics += result["Metrics"]

        while next_token := result.get("NextToken"):
            result = aws_client.cloudwatch.list_metrics(NextToken=next_token, Namespace=namespace)
            metrics += result["Metrics"]

        assert 1200 == len(metrics)  # every second thread inserted two metrics

    @markers.aws.only_localstack
    def test_run_100_alarms(self, aws_client, aws_client_factory):
        pass

    @markers.aws.only_localstack
    def test_sqs_queue_integration(self, aws_client, aws_client_factory):
        pass


class Counter:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def increment(self):
        with self.lock:
            self.value += 1

    def get_value(self):
        with self.lock:
            return self.value
