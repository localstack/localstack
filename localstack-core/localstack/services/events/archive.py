from localstack.aws.api.events import ArchiveState, Arn
from localstack.services.events.models import (
    Archive,
    ArchiveDescription,
    ArchiveName,
    EventPattern,
    RetentionDays,
    RuleName,
)


class ArchiveService:
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
        self.set_state(ArchiveState.ENABLED)
        self.rule_name: RuleName = None

    @property
    def arn(self):
        return self.archive.arn

    @property
    def state(self):
        return self.archive.state

    def set_state(self, state: ArchiveState):
        self.archive.state = state


ArchiveServiceDict = dict[Arn, ArchiveService]
