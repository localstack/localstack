from localstack.aws.api.events import Arn, EventBusList
from localstack.aws.api.events import EventBus as ApiTypeEventBus
from localstack.services.events.rule import RuleDict


class EventBus:
    def __init__(self, name: str, arn: Arn, policy: str | None = None):
        self.name = name
        self.arn = arn
        self.policy = policy
        self._rules: RuleDict = {}

    def delete(self):
        self._rules.clear()


EventBusDict = dict[str, EventBus]


def event_bus_to_api_type_event_bus(event_bus: EventBus) -> ApiTypeEventBus:
    if event_bus.policy:
        event_bus = {
            "Name": event_bus.name,
            "Arn": event_bus.arn,
            "Policy": event_bus.policy,
        }
    else:
        event_bus = {
            "Name": event_bus.name,
            "Arn": event_bus.arn,
        }
    return event_bus


def event_bust_dict_to_list(event_buses: EventBusDict) -> EventBusList:
    event_bus_list = [
        event_bus_to_api_type_event_bus(event_bus) for event_bus in event_buses.values()
    ]
    return event_bus_list
