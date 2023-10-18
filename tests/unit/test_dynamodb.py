from unittest.mock import patch

import pytest

from localstack.constants import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.services.dynamodb.provider import DynamoDBProvider, get_store
from localstack.services.dynamodb.utils import (
    SCHEMA_CACHE,
    ItemSet,
    SchemaExtractor,
    dynamize_value,
)
from localstack.utils.aws import aws_stack
from localstack.utils.aws.arns import dynamodb_table_arn


def test_fix_region_in_headers():
    # the NoSQL Workbench sends "localhost" or "local" as the region name
    # TODO: this may need to be updated once we migrate DynamoDB to ASF

    for region_name in ["local", "localhost"]:
        headers = aws_stack.mock_aws_request_headers("dynamodb", region_name=region_name)
        assert TEST_AWS_REGION_NAME not in headers.get("Authorization")

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

    schema = schema_extractor.get_key_schema(
        table_name, account_id=TEST_AWS_ACCOUNT_ID, region_name=TEST_AWS_REGION_NAME
    )

    # Assert output is expected from the get_table_schema (fallback)
    assert schema == key_schema
    # Assert table_definitions has new table entry (cache)
    dynamodb_store = get_store(account_id=TEST_AWS_ACCOUNT_ID, region_name=TEST_AWS_REGION_NAME)
    assert table_name in dynamodb_store.table_definitions
    # Assert table_definitions has the correct content
    assert (
        dynamodb_store.table_definitions[table_name] == mock_get_table_schema.return_value["Table"]
    )


def test_invalidate_table_schema():
    schema_extractor = SchemaExtractor()

    key_schema = [{"AttributeName": "id", "KeyType": "HASH"}]
    attr_definitions = [
        {"AttributeName": "Artist", "AttributeType": "S"},
        {"AttributeName": "SongTitle", "AttributeType": "S"},
    ]
    table_name = "nonexistent_table"

    key = dynamodb_table_arn(
        table_name=table_name, account_id=TEST_AWS_ACCOUNT_ID, region_name=TEST_AWS_REGION_NAME
    )

    table_schema = {"Table": {"KeySchema": key_schema, "AttributeDefinitions": attr_definitions}}
    # This isn't great but we need to inject into the cache here so that we're not trying to hit dynamodb
    # to look up the table later on
    SCHEMA_CACHE[key] = table_schema

    schema = schema_extractor.get_table_schema(
        table_name, account_id=TEST_AWS_ACCOUNT_ID, region_name=TEST_AWS_REGION_NAME
    )

    # Assert output is expected from the get_table_schema (fallback)
    assert schema == table_schema
    # Invalidate the cache now for the table
    schema_extractor.invalidate_table_schema(table_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)
    # Assert that the key is now set to None
    assert SCHEMA_CACHE.get(key) is None


@pytest.mark.parametrize(
    "value, result",
    [
        (True, {"BOOL": True}),
        (None, {"NULL": True}),
        ("test", {"S": "test"}),
        (1, {"N": "1"}),
        ({"test", "test1"}, {"SS": ["test", "test1"]}),
        ({1, 2}, {"NS": ["1", "2"]}),
        ({b"test", b"test1"}, {"BS": [b"test", b"test1"]}),
        (b"test", {"B": b"test"}),
        ({"key": "val"}, {"M": {"key": {"S": "val"}}}),
        (["val", 2], {"L": [{"S": "val"}, {"N": "2"}]}),
    ],
)
def test_dynamize_value(value, result):
    # we need to set a special case for SS, NS and BS because sets are unordered, and won't keep the order when
    # transformed into lists
    if isinstance(value, (set, frozenset)):
        dynamized = dynamize_value(value)
        assert dynamized.keys() == result.keys()
        for key, val in dynamized.items():
            result[key].sort()
            val.sort()
            assert result[key] == val
    else:
        assert dynamize_value(value) == result
