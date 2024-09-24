from datetime import datetime, timezone

from localstack.aws.api.events import (
    Arn,
    PutEventsRequestEntry,
    ReplayDescription,
    ReplayDestination,
    ReplayName,
    ReplayState,
    Timestamp,
)
from localstack.services.events.models import FormattedEventList, Replay
from localstack.services.events.utils import (
    convert_to_timezone_aware_datetime,
    extract_event_bus_name,
    re_format_event,
)


class ReplayService:
    name: ReplayName
    region: str
    account_id: str
    event_source_arn: Arn
    destination: ReplayDestination
    event_start_time: Timestamp
    event_end_time: Timestamp
    description: ReplayDescription
    replay: Replay

    def __init__(
        self,
        name: ReplayName,
        region: str,
        account_id: str,
        event_source_arn: Arn,
        destination: ReplayDestination,
        event_start_time: Timestamp,
        event_end_time: Timestamp,
        description: ReplayDescription,
    ):
        event_start_time = convert_to_timezone_aware_datetime(event_start_time)
        event_end_time = convert_to_timezone_aware_datetime(event_end_time)
        self.replay = Replay(
            name,
            region,
            account_id,
            event_source_arn,
            destination,
            event_start_time,
            event_end_time,
            description,
        )
        self.set_state(ReplayState.STARTING)

    def __getattr__(self, name):
        return getattr(self.replay, name)

    def set_state(self, state: ReplayState) -> None:
        self.replay.state = state

    def start(self, events: FormattedEventList | None) -> None:
        self.set_state(ReplayState.RUNNING)
        self.replay.replay_start_time = datetime.now(timezone.utc)
        if events:
            self._set_event_last_replayed_time(events)

    def finish(self) -> None:
        self.set_state(ReplayState.COMPLETED)
        self.replay.replay_end_time = datetime.now(timezone.utc)

    def stop(self) -> None:
        self.set_state(ReplayState.CANCELLING)
        self.replay.event_last_replayed_time = None
        self.replay.replay_end_time = None

    def re_format_events_from_archive(
        self, events: FormattedEventList, replay_name: ReplayName
    ) -> PutEventsRequestEntry:
        event_bus_name = extract_event_bus_name(
            self.destination["Arn"]
        )  # TODO deal with filter arn -> defining rules to replay to
        re_formatted_events = [re_format_event(event, event_bus_name) for event in events]
        re_formatted_events_from_archive = [
            {**event, "ReplayName": replay_name} for event in re_formatted_events
        ]
        return re_formatted_events_from_archive

    def _set_event_last_replayed_time(self, events: FormattedEventList) -> None:
        latest_event_time = max(event["time"] for event in events)
        self.replay.event_last_replayed_time = latest_event_time


ReplayServiceDict = dict[ReplayName, ReplayService]
