from localstack.services.dynamodb.provider import DynamoDBProvider
from localstack.services.dynamodb.utils import ItemSet
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
