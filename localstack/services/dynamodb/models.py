from localstack.aws.api.dynamodb import RegionName, ReplicaDescription, TableName
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)


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
    ttl_specifications: dict[str, dict] = LocalAttribute(default=dict)

    # maps backups
    backups: dict[str, dict] = LocalAttribute(default=dict)


dynamodb_stores = AccountRegionBundle("dynamodb", DynamoDBStore)
