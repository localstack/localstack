import datetime
import math
import threading
from collections import defaultdict
from itertools import count
from typing import Any

from localstack import config
from localstack.runtime import hooks
from localstack.utils.analytics import get_session_id
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.publisher import AnalyticsClientPublisher

# Counters have to register with the registry
collector_registry: dict[str, Any] = dict()

# TODO: introduce some base abstraction for the counters after gather some initial experience working with it
#  we could probably do intermediate aggregations over time to avoid unbounded counters for very long LS sessions
#  for now, we can recommend to use config.DISABLE_EVENTS=1


class UsageSetCounter:
    """
    Use this counter to count occurrences of unique values

    Example:
        my_feature_counter = UsageSetCounter("lambda:runtime")
        my_feature_counter.record("python3.7")
        my_feature_counter.record("nodejs16.x")
        my_feature_counter.record("nodejs16.x")
        my_feature_counter.aggregate() # returns {"python3.7": 1, "nodejs16.x": 2}
    """

    state: dict[str, int]
    _counter: dict[str, count]
    namespace: str

    def __init__(self, namespace: str):
        self.enabled = not config.DISABLE_EVENTS
        self.state = {}
        self._counter = defaultdict(lambda: count(1))
        self.namespace = namespace
        collector_registry[namespace] = self

    def record(self, value: str):
        if self.enabled:
            self.state[value] = next(self._counter[value])

    def aggregate(self) -> dict:
        return self.state


class UsageMultiSetCounter:
    """
    Use this counter to count occurrences of unique values for multiple dimensions.
    This dynamically creates UsageSetCounters and should be used with care (i.e., with limited keys).

    Example:

    my_feature_counter = UsageMultiSetCounter("pipes:invocation")
    my_feature_counter.record("aws:sqs", "aws:lambda")
    my_feature_counter.record("aws:sqs", "aws:lambda")
    my_feature_counter.record("aws:sqs", "aws:stepfunctions")
    my_feature_counter.record("aws:kinesis", "aws:lambda")
    aggregate is implemented for each counter individually

    my_feature_counter.aggregate() is available for testing purposes:
    {
       "aws:sqs": {
         "aws:lambda": 2,
         "aws:stepfunctions": 1,
       },
       "aws:kinesis": {
         "aws:lambda": 1
       }
    }
    """

    namespace: str
    _counters: dict[str, UsageSetCounter]
    lock = threading.Lock()

    def __init__(self, namespace: str):
        self._counters = {}
        self.namespace = namespace

    def record(self, key: str, value: str):
        namespace = f"{self.namespace}:{key}"

        if namespace in self._counters:
            set_counter = self._counters[namespace]
        else:
            with self.lock:
                # We cannot use setdefault here because Python always instantiates a new UsageSetCounter,
                # which overwrites the collector_registry
                set_counter = UsageSetCounter(namespace)
                self._counters[namespace] = set_counter
        set_counter.record(value)

    def aggregate(self) -> dict:
        """aggregate is invoked on a per UsageSetCounter level because each counter is registered individually.
        This utility is only for testing!"""
        merged_dict = {}
        for namespace, counter in self._counters.items():
            merged_dict[namespace] = counter.aggregate()
        return merged_dict


class UsageCounter:
    """
    Use this counter to count numeric values

    Example:
        my__counter = UsageCounter("lambda:somefeature")
        my_counter.increment()
        my_counter.increment()
        my_counter.aggregate()  # returns {"count": 2}
    """

    state: int
    namespace: str

    def __init__(self, namespace: str):
        self.enabled = not config.DISABLE_EVENTS
        self.state = 0
        self._counter = count(1)
        self.namespace = namespace
        collector_registry[namespace] = self

    def increment(self):
        # TODO: we should instead have different underlying datastructures to store the state, and have no-op operations
        #  when config.DISABLE_EVENTS is set
        if self.enabled:
            self.state = next(self._counter)

    def aggregate(self) -> dict:
        # TODO: should we just keep `count`? "sum" might need to be kept for historical data?
        return {"count": self.state, "sum": self.state}


class TimingStats:
    """
    Use this counter to measure numeric values and perform aggregations

    Available aggregations: min, max, sum, mean, median, count

    Example:
        my_feature_counter = TimingStats("lambda:somefeature", aggregations=["min", "max", "sum", "count"])
        my_feature_counter.record_value(512)
        my_feature_counter.record_value(256)
        my_feature_counter.aggregate()  # returns {"min": 256, "max": 512, "sum": 768, "count": 2}
    """

    state: list[int | float]
    namespace: str
    aggregations: list[str]

    def __init__(self, namespace: str, aggregations: list[str]):
        self.enabled = not config.DISABLE_EVENTS
        self.state = []
        self.namespace = namespace
        self.aggregations = aggregations
        collector_registry[namespace] = self

    def record_value(self, value: int | float):
        if self.enabled:
            self.state.append(value)

    def aggregate(self) -> dict:
        result = {}
        if self.state:
            for aggregation in self.aggregations:
                match aggregation:
                    case "sum":
                        result[aggregation] = sum(self.state)
                    case "min":
                        result[aggregation] = min(self.state)
                    case "max":
                        result[aggregation] = max(self.state)
                    case "mean":
                        result[aggregation] = sum(self.state) / len(self.state)
                    case "median":
                        median_index = math.floor(len(self.state) / 2)
                        result[aggregation] = sorted(self.state)[median_index]
                    case "count":
                        result[aggregation] = len(self.state)
                    case _:
                        raise Exception(f"Unsupported aggregation: {aggregation}")
        return result


def aggregate() -> dict:
    aggregated_payload = {}
    for ns, collector in collector_registry.items():
        agg = collector.aggregate()
        if agg:
            aggregated_payload[ns] = agg
    return aggregated_payload


@hooks.on_infra_shutdown()
def aggregate_and_send():
    """
    Aggregates data from all registered usage trackers and immediately sends the aggregated result to the analytics service.
    """
    if config.DISABLE_EVENTS:
        return

    metadata = EventMetadata(
        session_id=get_session_id(),
        client_time=str(datetime.datetime.now()),
    )

    aggregated_payload = aggregate()

    if aggregated_payload:
        publisher = AnalyticsClientPublisher()
        publisher.publish(
            [Event(name="ls:usage_analytics", metadata=metadata, payload=aggregated_payload)]
        )
