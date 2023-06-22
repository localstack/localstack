from typing import Dict

from localstack.aws.api.dynamodb import RegionName, ReplicaDescription, TableName
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)


class DynamoDBStore(BaseStore):
    # maps global table names to configurations (for the legacy v.2017 tables)
    GLOBAL_TABLES: Dict[str, Dict] = CrossRegionAttribute(default=dict)

    # Maps table name to the region they exist in on DDBLocal (for v.2019 global tables)
    TABLE_REGION: Dict[TableName, RegionName] = CrossRegionAttribute(default=dict)

    # Maps the table replicas (for v.2019 global tables)
    REPLICAS: Dict[TableName, Dict[RegionName, ReplicaDescription]] = CrossRegionAttribute(
        default=dict
    )

    # cache table taggings - maps table ARN to tags dict
    TABLE_TAGS: Dict[str, Dict] = CrossRegionAttribute(default=dict)

    # maps table names to cached table definitions
    table_definitions: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps table names to additional table properties that are not stored upstream (e.g., ReplicaUpdates)
    table_properties: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps table names to TTL specifications
    ttl_specifications: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps backups
    backups: Dict[str, Dict] = LocalAttribute(default=dict)


dynamodb_stores = AccountRegionBundle("dynamodb", DynamoDBStore)
