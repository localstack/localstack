import json
import logging
from datetime import datetime, timezone

from botocore.client import BaseClient

from localstack.aws.api.events import (
    ArchiveState,
    Arn,
    EventBusName,
    TargetId,
    Timestamp,
)
from localstack.aws.connect import connect_to
from localstack.services.events.models import (
    Archive,
    ArchiveDescription,
    ArchiveName,
    EventPattern,
    FormattedEvent,
    FormattedEventList,
    RetentionDays,
    RuleName,
)
from localstack.services.events.utils import extract_event_bus_name
from localstack.utils.aws.client_types import ServicePrincipal

LOG = logging.getLogger(__name__)


class ArchiveService:
    archive_name: ArchiveName
    region: str
    account_id: str
    event_source_arn: Arn
    description: ArchiveDescription
    event_pattern: EventPattern
    retention_days: RetentionDays
    archive: Archive
    client: BaseClient
    event_bus_name: EventBusName
    rule_name: RuleName
    target_id: TargetId

    def __init__(
        self,
        archive_name: ArchiveName,
        region: str,
        account_id: str,
        event_source_arn: Arn,
        description: ArchiveDescription,
        event_pattern: EventPattern,
        retention_days: RetentionDays,
    ):
        self.archive = Archive(
            archive_name,
            region,
            account_id,
            event_source_arn,
            description,
            event_pattern,
            retention_days,
        )
        self.set_state(ArchiveState.CREATING)
        self.set_creation_time()
        self.client: BaseClient = self._initialize_client()
        self.event_bus_name: EventBusName = extract_event_bus_name(event_source_arn)

        self.rule_name: RuleName = self._create_archive_rule()
        self.target_id: TargetId = self._create_archive_target()
        self.set_state(ArchiveState.ENABLED)

    def __getattr__(self, name):
        return getattr(self.archive, name)

    @property
    def archive_name(self) -> ArchiveName:
        return self.archive.name

    @property
    def archive_arn(self) -> Arn:
        return self.archive.arn

    def set_state(self, state: ArchiveState) -> None:
        self.archive.state = state

    def set_creation_time(self) -> None:
        self.archive.creation_time = datetime.now(timezone.utc)

    def update(
        self,
        description: ArchiveDescription,
        event_pattern: EventPattern,
        retention_days: RetentionDays,
    ) -> None:
        self.set_state(ArchiveState.UPDATING)
        if description is not None:
            self.archive.description = description
        if event_pattern is not None:
            self.archive.event_pattern = event_pattern
        if retention_days is not None:
            self.archive.retention_days = retention_days
        self.set_state(ArchiveState.ENABLED)

    def delete(self) -> None:
        self.set_state(ArchiveState.DISABLED)
        try:
            self.client.remove_targets(
                Rule=self.rule_name, EventBusName=self.event_bus_name, Ids=[self.target_id]
            )
        except Exception as e:
            LOG.debug(f"Target {self.target_id} could not be removed, {e}")
        try:
            self.client.delete_rule(Name=self.rule_name, EventBusName=self.event_bus_name)
        except Exception as e:
            LOG.debug(f"Rule {self.rule_name} could not be deleted, {e}")

    def put_events(self, events: FormattedEventList) -> None:
        for event in events:
            self.archive.events[event["id"]] = event

    def get_events(self, start_time: Timestamp, end_time: Timestamp) -> FormattedEventList:
        events_to_replay = self._filter_events_start_end_time(start_time, end_time)
        return events_to_replay

    def _initialize_client(self) -> BaseClient:
        client_factory = connect_to(aws_access_key_id=self.account_id, region_name=self.region)
        client = client_factory.get_client("events")

        service_principal = ServicePrincipal.events
        client = client.request_metadata(service_principal=service_principal, source_arn=self.arn)
        return client

    def _create_archive_rule(
        self,
    ) -> RuleName:
        rule_name = f"Events-Archive-{self.name}"
        default_event_pattern = {
            "replay-name": [{"exists": False}],
        }
        if self.event_pattern:
            updated_event_pattern = json.loads(self.event_pattern)
            updated_event_pattern.update(default_event_pattern)
        else:
            updated_event_pattern = default_event_pattern
        self.client.put_rule(
            Name=rule_name,
            EventBusName=self.event_bus_name,
            EventPattern=json.dumps(updated_event_pattern),
        )
        return rule_name

    def _create_archive_target(
        self,
    ) -> TargetId:
        """Creates a target for the archive rule. The target is required for accessing parameters
        from the provider during sending of events to the target but it is not invoked
        because events are put to the archive directly to not overload the gateway"""
        target_id = f"Events-Archive-{self.name}"
        self.client.put_targets(
            Rule=self.rule_name,
            EventBusName=self.event_bus_name,
            Targets=[{"Id": target_id, "Arn": self.arn}],
        )
        return target_id

    def _normalize_datetime(self, dt: datetime) -> datetime:
        return dt.replace(second=0, microsecond=0)

    def _filter_events_start_end_time(
        self, event_start_time: Timestamp, event_end_time: Timestamp
    ) -> list[FormattedEvent]:
        events = self.archive.events
        event_start_time = self._normalize_datetime(event_start_time)
        event_end_time = self._normalize_datetime(event_end_time)
        return [
            event
            for event in events.values()
            if event_start_time <= self._normalize_datetime(event["time"]) <= event_end_time
        ]


ArchiveServiceDict = dict[Arn, ArchiveService]
