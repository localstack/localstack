from localstack.utils.analytics.metrics.counter_metric import _CounterMetric, _LabeledCounterMetric
from localstack.utils.analytics.metrics.interfaces import CounterMetric, LabeledCounterMetric


class Counter:
    """
    A factory class for counter metrics.
    Use `Counter.base(...)` for base counters, or `Counter.with_labels(...)` for labeled counters.
    """

    @staticmethod
    def base(namespace: str, name: str) -> CounterMetric:
        return _CounterMetric(namespace=namespace, name=name)

    @staticmethod
    def with_labels(
        namespace: str, name: str, schema_version: int, labels: list[str]
    ) -> LabeledCounterMetric:
        return _LabeledCounterMetric(
            namespace=namespace, name=name, schema_version=schema_version, labels=labels
        )
