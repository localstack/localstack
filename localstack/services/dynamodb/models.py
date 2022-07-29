from typing import Dict

from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)


class DynamoDBStore(BaseStore):
    # maps global table names to configurations
    GLOBAL_TABLES: Dict[str, Dict] = CrossRegionAttribute(default=dict)
    # cache table taggings - maps table ARN to tags dict
    TABLE_TAGS: Dict[str, Dict] = CrossRegionAttribute(default=dict)
    # maps table names to cached table definitions
    table_definitions: Dict[str, Dict] = LocalAttribute(default=dict)
    # maps table names to additional table properties that are not stored upstream (e.g., ReplicaUpdates)
    table_properties: Dict[str, Dict] = LocalAttribute(default=dict)
    # maps table names to TTL specifications
    ttl_specifications: Dict[str, Dict] = LocalAttribute(default=dict)


dynamodb_stores = AccountRegionBundle("dynamodb", DynamoDBStore)
