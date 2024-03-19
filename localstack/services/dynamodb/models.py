import dataclasses
from typing import TypedDict

from localstack.aws.api.dynamodb import (
    AttributeMap,
    Key,
    RegionName,
    ReplicaDescription,
    StreamViewType,
    TableName,
    TimeToLiveSpecification,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)


@dataclasses.dataclass
class TableStreamType:
    """
    When an item in the table is modified, StreamViewType determines what information is written to the stream for this table.
    - KEYS_ONLY - Only the key attributes of the modified item are written to the stream.
    - NEW_IMAGE - The entire item, as it appears after it was modified, is written to the stream.
    - OLD_IMAGE - The entire item, as it appeared before it was modified, is written to the stream.
    - NEW_AND_OLD_IMAGES - Both the new and the old item images of the item are written to the stream.
    Special case:
    is_kinesis: equivalent to NEW_AND_OLD_IMAGES, can be set at the same time as StreamViewType
    """

    stream_view_type: StreamViewType | None
    is_kinesis: bool

    @property
    def needs_old_image(self):
        return self.is_kinesis or self.stream_view_type in (
            StreamViewType.OLD_IMAGE,
            StreamViewType.NEW_AND_OLD_IMAGES,
        )

    @property
    def needs_new_image(self):
        return self.is_kinesis or self.stream_view_type in (
            StreamViewType.NEW_IMAGE,
            StreamViewType.NEW_AND_OLD_IMAGES,
        )


class DynamoDbStreamRecord(TypedDict, total=False):
    ApproximateCreationDateTime: int
    SizeBytes: int
    Keys: Key
    StreamViewType: StreamViewType | None
    OldImage: AttributeMap | None
    NewImage: AttributeMap | None
    SequenceNumber: int | None


class StreamRecord(TypedDict, total=False):
    """
    Related to DynamoDB Streams and Kinesis Destinations
    This class contains data necessary for both KinesisRecord and DynamoDBStreams record
    """

    eventName: str
    eventID: str
    eventVersion: str
    dynamodb: DynamoDbStreamRecord
    awsRegion: str
    eventSource: str


StreamRecords = list[StreamRecord]


class TableRecords(TypedDict):
    """
    Container class used to forward events from DynamoDB to DDB Streams and Kinesis destinations.
    It contains the records to be forwarded and data about the streams to be forwarded to.
    """

    table_stream_type: TableStreamType
    records: StreamRecords


# the RecordsMap maps the TableName to TableRecords, allowing forwarding to the destinations
# some DynamoDB calls can modify several tables at once, which is why we need to group those events per table, as each
# table can have different destinations
RecordsMap = dict[TableName, TableRecords]


class DynamoDBStore(BaseStore):
    # maps global table names to configurations (for the legacy v.2017 tables)
    GLOBAL_TABLES: dict[str, dict] = CrossRegionAttribute(default=dict)

    # Maps table name to the region they exist in on DDBLocal (for v.2019 global tables)
    TABLE_REGION: dict[TableName, RegionName] = CrossRegionAttribute(default=dict)

    # Maps the table replicas (for v.2019 global tables)
    REPLICAS: dict[TableName, dict[RegionName, ReplicaDescription]] = CrossRegionAttribute(
        default=dict
    )

    # cache table taggings - maps table ARN to tags dict
    TABLE_TAGS: dict[str, dict] = CrossRegionAttribute(default=dict)

    # maps table names to cached table definitions
    table_definitions: dict[str, dict] = LocalAttribute(default=dict)

    # maps table names to additional table properties that are not stored upstream (e.g., ReplicaUpdates)
    table_properties: dict[str, dict] = LocalAttribute(default=dict)

    # maps table names to TTL specifications
    ttl_specifications: dict[str, TimeToLiveSpecification] = LocalAttribute(default=dict)

    # maps backups
    backups: dict[str, dict] = LocalAttribute(default=dict)


dynamodb_stores = AccountRegionBundle("dynamodb", DynamoDBStore)
