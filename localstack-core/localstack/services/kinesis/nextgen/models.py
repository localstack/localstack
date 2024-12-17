from datetime import datetime, timezone
from typing import Dict

from localstack.aws.api.kinesis import StreamName
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.aws.arns import kinesis_stream_arn
from localstack.utils.tagging import TaggingService


class Stream:
    def __init__(self, account_id: str, region_name: str, name: str, mode: str, shard_count: int):
        self.account_id = account_id
        self.region_name = region_name

        self.name = name
        self.mode = mode
        self.shard_count = shard_count
        self.retention_period = 24  # hours

        self.created_timestamp = datetime.now(timezone.utc)

    @property
    def arn(self) -> str:
        return kinesis_stream_arn(self.name, self.account_id, self.region_name)


# Shards have:
# - ID
# Records have:
# - sequence number
# - partition key
# - data


class KinesisStore(BaseStore):
    streams: Dict[StreamName, Stream] = LocalAttribute(default=dict)

    TAGS: TaggingService = CrossRegionAttribute(default=TaggingService)


kinesis_stores = AccountRegionBundle("kinesis", KinesisStore)
