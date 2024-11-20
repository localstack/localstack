import datetime
import math
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


class UsageCounter:
    """
    Use this counter to count numeric values and perform aggregations

    Available aggregations: min, max, sum, mean, median

    Example:
        my_feature_counter = UsageCounter("lambda:somefeature", aggregations=["min", "max", "sum"])
        my_feature_counter.increment()  # equivalent to my_feature_counter.record_value(1)
        my_feature_counter.record_value(3)
        my_feature_counter.aggregate()  # returns {"min": 1, "max": 3, "sum": 4}
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

    def increment(self):
        # TODO: we should instead have different underlying datastructures to store the state, and have no-op operations
        #  when config.DISABLE_EVENTS is set
        if self.enabled:
            self.state.append(1)

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
