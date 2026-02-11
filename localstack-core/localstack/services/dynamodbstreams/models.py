import dataclasses

from localstack.aws.api.dynamodbstreams import StreamDescription
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


@dataclasses.dataclass
class Stream:
    """Wrapper for the API stub and additional information about a store"""

    StreamDescription: StreamDescription
    shards_id_map: dict[str, str] = dataclasses.field(default_factory=dict)


class DynamoDbStreamsStore(BaseStore):
    ddb_streams: dict[str, Stream] = LocalAttribute(default=dict)


dynamodbstreams_stores = AccountRegionBundle("dynamodbstreams", DynamoDbStreamsStore)
