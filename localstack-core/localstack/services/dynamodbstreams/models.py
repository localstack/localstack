from typing import Dict

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class DynamoDbStreamsStore(BaseStore):
    # maps table names to DynamoDB stream descriptions
    ddb_streams: Dict[str, dict] = LocalAttribute(default=dict)


dynamodbstreams_stores = AccountRegionBundle("dynamodbstreams", DynamoDbStreamsStore)
