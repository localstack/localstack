import datetime
import math
from typing import Any

from localstack.utils.analytics import get_session_id
from localstack.utils.analytics.events import Event, EventHandler, EventMetadata
from localstack.utils.analytics.publisher import AnalyticsClientPublisher

collector_registry: dict[str, Any] = dict()


class UsageSetCounter:

    state: list[str]
    namespace: str

    def __init__(self, namespace: str):
        self.state = list()
        self.namespace = namespace
        collector_registry[namespace] = self

    def record(self, value: str):
        self.state.append(value)

    def aggregate(self) -> dict:
        result = {}
        for a in self.state:
            result.setdefault(a, 0)
            result[a] = result[a] + 1
        return result


class UsageCounter:
    state: list[int | float]
    namespace: str
    aggregations: list[str]

    def __init__(self, namespace: str, aggregations: list[str]):
        self.state = list()
        self.namespace = namespace
        self.aggregations = aggregations
        collector_registry[namespace] = self

    def increment(self):
        self.state.append(1)

    def record_value(self, value: int | float):
        self.state.append(value)

    def aggregate(self) -> dict:
        result = {}
        for a in self.aggregations:
            if self.state:
                match a:
                    case "sum":
                        result[a] = sum(self.state)
                    case "min":
                        result[a] = min(self.state)
                    case "max":
                        result[a] = max(self.state)
                    case "mean":
                        result[a] = sum(self.state) / len(self.state)
                    case "median":
                        median_index = math.floor(len(self.state) / 2)
                        result[a] = self.state[median_index]
                    case _:
                        raise Exception("unknown")
        return result


class UsageLogger:
    handler: EventHandler
    usage_events: dict[str, dict[str, list]]

    def __init__(self, handler: EventHandler):
        self.handler = handler
        self.session_id = get_session_id()
        self.usage_events = dict()

    def usage(self, partition_name: str, usage_type: str, processing_fn: list, value: object):
        self.usage_events.setdefault(partition_name)

    def _metadata(self) -> EventMetadata:
        return EventMetadata(
            session_id=self.session_id,
            client_time=str(datetime.datetime.now()),
        )

    def aggregate(self) -> dict:
        aggregated_payload = {}
        for ns, collector in collector_registry.items():
            aggregated_payload[ns] = collector.aggregate()
        return aggregated_payload

    def flush(self):
        self.handler.handle(
            Event(name="hackystacky:usage", metadata=self._metadata(), payload=self.aggregate())
        )


class UsageEventHandler(EventHandler):

    events: list[Event]

    def __init__(self):
        self.publisher = AnalyticsClientPublisher()
        self.events = list()

    def handle(self, event: Event):
        self.events.append(event)
        self.publisher.publish(self.events)
