import logging
import threading

from localstack.testing import pytest
from localstack.testing.pytest import markers

LOG = logging.getLogger(__name__)


class TestCloudWatchPerformance:
    @markers.aws.only_localstack
    @pytest.mark.skip
    def test_parallel_write_read_access(self, aws_client):
        num_threads = 150
        create_barrier = threading.Barrier(num_threads)
        errored = False

        def _put_metric_list_metrics(runner: int):
            nonlocal errored
            create_barrier.wait()
            try:
                if runner % 2:
                    namespace = f"namespace-{runner}"
                    aws_client.cloudwatch.put_metric_data(
                        Namespace=namespace,
                        MetricData=[
                            {
                                "MetricName": "metric2",
                                "Value": 25,
                                "Unit": "Seconds",
                            },
                            {
                                "MetricName": "metric1",
                                "Value": runner + 1,
                                "Unit": "Seconds",
                            },
                        ],
                    )
                else:
                    aws_client.cloudwatch.list_metrics()
            except Exception:
                LOG.exception("failed")
                errored = True

        thread_list = []
        for i in range(1, num_threads + 1):
            thread = threading.Thread(target=_put_metric_list_metrics, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        assert not errored
