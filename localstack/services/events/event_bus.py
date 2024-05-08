from typing import Optional

from localstack.aws.api.events import Arn, EventBusName, TagList
from localstack.services.events.models import EventBus, RuleDict


class EventBusService:
    def __init__(
        self,
        name: EventBusName,
        region: str,
        account_id: str,
        event_source_name: Optional[str] = None,
        tags: Optional[TagList] = None,
        policy: Optional[str] = None,
        rules: Optional[RuleDict] = None,
    ):
        self.event_bus = EventBus(
            name,
            region,
            account_id,
            event_source_name,
            tags,
            policy,
            rules,
        )

    @property
    def arn(self):
        return self.event_bus.arn


EventBusServiceDict = dict[Arn, EventBusService]
