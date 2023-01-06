from unittest.mock import patch

from localstack.aws.accounts import get_aws_account_id
from localstack.services.dynamodb.provider import DynamoDBProvider, get_store
from localstack.services.dynamodb.utils import ItemSet, SchemaExtractor
from localstack.utils.aws import aws_stack


def test_fix_region_in_headers():
    # the NoSQL Workbench sends "localhost" or "local" as the region name
    # TODO: this may need to be updated once we migrate DynamoDB to ASF

    for region_name in ["local", "localhost"]:
        headers = aws_stack.mock_aws_request_headers("dynamodb", region_name=region_name)
        assert aws_stack.get_region() not in headers.get("Authorization")

        # Ensure that the correct namespacing key is passed as Access Key ID to DynamoDB Local
        DynamoDBProvider.prepare_request_headers(
            headers, account_id="000011112222", region_name="ap-south-1"
        )
        assert "000011112222apsouth1" in headers.get("Authorization")


def test_lookup_via_item_set():
    items1 = [
        {"id": {"S": "n1"}, "attr1": {"N": "1"}},
        {"id": {"S": "n2"}},
        {"id": {"S": "n3"}},
    ]
    key_schema1 = [{"AttributeName": "id", "KeyType": "HASH"}]

    items2 = [
        {"id": {"S": "id1"}, "num": {"N": "1"}},
        {"id": {"S": "id2"}, "num": {"N": "2"}},
        {"id": {"S": "id3"}, "num": {"N": "2"}},
    ]
    key_schema2 = [
        {"AttributeName": "id", "KeyType": "HASH"},
        {"AttributeName": "num", "KeyType": "RANGE"},
    ]

    samples = ((items1, key_schema1), (items2, key_schema2))

    for items, key_schema in samples:
        item_set = ItemSet(items, key_schema=key_schema)
        for item in items:
            assert item_set.find_item(item) == item
        for item in items:
            assert not item_set.find_item({**item, "id": {"S": item["id"]["S"] + "-new"}})


@patch("localstack.services.dynamodb.utils.SchemaExtractor.get_table_schema")
def test_get_key_schema_without_table_definition(mock_get_table_schema):
    schema_extractor = SchemaExtractor()

    key_schema = [{"AttributeName": "id", "KeyType": "HASH"}]
    attr_definitions = [
        {"AttributeName": "Artist", "AttributeType": "S"},
        {"AttributeName": "SongTitle", "AttributeType": "S"},
    ]
    table_name = "nonexistent_table"

    mock_get_table_schema.return_value = {
        "Table": {"KeySchema": key_schema, "AttributeDefinitions": attr_definitions}
    }

    schema = schema_extractor.get_key_schema(table_name)

    # Assert output is expected from the get_table_schema (fallback)
    assert schema == key_schema
    # Assert table_definitions has new table entry (cache)
    dynamodb_store = get_store(account_id=get_aws_account_id(), region_name=aws_stack.get_region())
    assert table_name in dynamodb_store.table_definitions
    # Assert table_definitions has the correct content
    assert (
        dynamodb_store.table_definitions[table_name] == mock_get_table_schema.return_value["Table"]
    )
