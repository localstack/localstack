import json
import re
from datetime import datetime
from time import sleep
from typing import Dict

import pytest
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import STRING

from localstack.aws.api.dynamodb import (
    ContinuousBackupsUnavailableException,
    PointInTimeRecoverySpecification,
)
from localstack.constants import TEST_AWS_SECRET_ACCESS_KEY
from localstack.services.dynamodbstreams.dynamodbstreams_api import get_kinesis_stream_name
from localstack.testing.aws.lambda_utils import _await_dynamodb_table_active
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils import testutil
from localstack.utils.aws import arns, aws_stack, queries, resources
from localstack.utils.common import json_safe, long_uid, retry, short_uid
from localstack.utils.sync import poll_condition

from .test_kinesis import get_shard_iterator

PARTITION_KEY = "id"

TEST_DDB_TABLE_NAME = "test-ddb-table-1"
TEST_DDB_TABLE_NAME_2 = "test-ddb-table-2"
TEST_DDB_TABLE_NAME_3 = "test-ddb-table-3"

TEST_DDB_TAGS = [
    {"Key": "Name", "Value": "test-table"},
    {"Key": "TestKey", "Value": "true"},
]


@pytest.fixture()
def dynamodb(dynamodb_resource):
    return dynamodb_resource


@pytest.fixture(autouse=True)
def transcribe_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.dynamodb_api())


class TestDynamoDB:
    @pytest.mark.only_localstack
    def test_non_ascii_chars(self, dynamodb):
        resources.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME)

        # write some items containing non-ASCII characters
        items = {
            "id1": {PARTITION_KEY: "id1", "data": "foobar123 ✓"},
            "id2": {PARTITION_KEY: "id2", "data": "foobar123 £"},
            "id3": {PARTITION_KEY: "id3", "data": "foobar123 ¢"},
        }
        for k, item in items.items():
            table.put_item(Item=item)

        for item_id in items.keys():
            item = table.get_item(Key={PARTITION_KEY: item_id})["Item"]

            # need to fix up the JSON and convert str to unicode for Python 2
            item1 = json_safe(item)
            item2 = json_safe(items[item_id])
            assert item1 == item2

        # clean up
        delete_table(TEST_DDB_TABLE_NAME)

    @pytest.mark.only_localstack
    def test_large_data_download(self, dynamodb):
        resources.create_dynamodb_table(TEST_DDB_TABLE_NAME_2, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME_2)

        # Create a large amount of items
        num_items = 20
        for i in range(0, num_items):
            item = {PARTITION_KEY: "id%s" % i, "data1": "foobar123 " * 1000}
            table.put_item(Item=item)

        # Retrieve the items. The data will be transmitted to the client with chunked transfer encoding
        result = table.scan(TableName=TEST_DDB_TABLE_NAME_2)
        assert len(result["Items"]) == num_items

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_2)

    @pytest.mark.only_localstack
    def test_time_to_live(self, dynamodb):
        resources.create_dynamodb_table(TEST_DDB_TABLE_NAME_3, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME_3)

        # Insert some items to the table
        items = {
            "id1": {PARTITION_KEY: "id1", "data": "IT IS"},
            "id2": {PARTITION_KEY: "id2", "data": "TIME"},
            "id3": {PARTITION_KEY: "id3", "data": "TO LIVE!"},
        }
        for k, item in items.items():
            table.put_item(Item=item)

        # Describe TTL when still unset
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        assert response.status_code == 200
        assert (
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"] == "DISABLED"
        )

        # Enable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, True)
        assert response.status_code == 200
        assert json.loads(response._content)["TimeToLiveSpecification"]["Enabled"]

        # Describe TTL status after being enabled.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        assert response.status_code == 200
        assert (
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"] == "ENABLED"
        )

        # Disable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, False)
        assert response.status_code == 200
        assert not json.loads(response._content)["TimeToLiveSpecification"]["Enabled"]

        # Describe TTL status after being disabled.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        assert response.status_code == 200
        assert (
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"] == "DISABLED"
        )

        # Enable TTL for given table again
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, True)
        assert response.status_code == 200
        assert json.loads(response._content)["TimeToLiveSpecification"]["Enabled"]

        # Describe TTL status after being enabled again.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        assert response.status_code == 200
        assert (
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"] == "ENABLED"
        )

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_3)

    @pytest.mark.only_localstack
    def test_list_tags_of_resource(self, dynamodb):
        table_name = "ddb-table-%s" % short_uid()
        dynamodb = aws_stack.create_external_boto_client("dynamodb")

        rs = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )
        table_arn = rs["TableDescription"]["TableArn"]

        rs = dynamodb.list_tags_of_resource(ResourceArn=table_arn)

        assert rs["Tags"] == TEST_DDB_TAGS

        dynamodb.tag_resource(ResourceArn=table_arn, Tags=[{"Key": "NewKey", "Value": "TestValue"}])

        rs = dynamodb.list_tags_of_resource(ResourceArn=table_arn)

        assert len(rs["Tags"]) == len(TEST_DDB_TAGS) + 1

        tags = {tag["Key"]: tag["Value"] for tag in rs["Tags"]}
        assert "NewKey" in tags.keys()
        assert tags["NewKey"] == "TestValue"

        dynamodb.untag_resource(ResourceArn=table_arn, TagKeys=["Name", "NewKey"])

        rs = dynamodb.list_tags_of_resource(ResourceArn=table_arn)
        tags = {tag["Key"]: tag["Value"] for tag in rs["Tags"]}
        assert "Name" not in tags.keys()
        assert "NewKey" not in tags.keys()

        delete_table(table_name)

    @pytest.mark.only_localstack
    def test_stream_spec_and_region_replacement(self, dynamodb):
        ddbstreams = aws_stack.create_external_boto_client("dynamodbstreams")
        kinesis = aws_stack.create_external_boto_client("kinesis")
        table_name = f"ddb-{short_uid()}"
        resources.create_dynamodb_table(
            table_name,
            partition_key=PARTITION_KEY,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )

        table = dynamodb.Table(table_name)

        # assert ARN formats
        expected_arn_prefix = "arn:aws:dynamodb:" + aws_stack.get_local_region()
        assert table.table_arn.startswith(expected_arn_prefix)
        assert table.latest_stream_arn.startswith(expected_arn_prefix)

        # assert stream has been created
        stream_tables = [s["TableName"] for s in ddbstreams.list_streams()["Streams"]]
        assert table_name in stream_tables
        stream_name = get_kinesis_stream_name(table_name)
        assert stream_name in kinesis.list_streams()["StreamNames"]

        # assert shard ID formats
        result = ddbstreams.describe_stream(StreamArn=table.latest_stream_arn)["StreamDescription"]
        assert "Shards" in result
        for shard in result["Shards"]:
            assert re.match(r"^shardId-[0-9]{20}-[a-zA-Z0-9]{1,36}$", shard["ShardId"])

        # clean up
        delete_table(table_name)

        def _assert_stream_deleted():
            stream_tables = [s["TableName"] for s in ddbstreams.list_streams()["Streams"]]
            assert table_name not in stream_tables
            assert stream_name not in kinesis.list_streams()["StreamNames"]

        # assert stream has been deleted
        retry(_assert_stream_deleted, sleep=0.4, retries=5)

    @pytest.mark.only_localstack
    def test_multiple_update_expressions(self, dynamodb):
        dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
        resources.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME)

        item_id = short_uid()
        table.put_item(Item={PARTITION_KEY: item_id, "data": "foobar123 ✓"})
        response = dynamodb_client.update_item(
            TableName=TEST_DDB_TABLE_NAME,
            Key={PARTITION_KEY: {"S": item_id}},
            UpdateExpression="SET attr1 = :v1, attr2 = :v2",
            ExpressionAttributeValues={":v1": {"S": "value1"}, ":v2": {"S": "value2"}},
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        item = table.get_item(Key={PARTITION_KEY: item_id})["Item"]
        assert item["attr1"] == "value1"
        assert item["attr2"] == "value2"
        attributes = [{"AttributeName": "id", "AttributeType": STRING}]

        user_id_idx = [
            {
                "Create": {
                    "IndexName": "id-index",
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                    "Projection": {
                        "ProjectionType": "INCLUDE",
                        "NonKeyAttributes": ["data"],
                    },
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    },
                }
            },
        ]

        # for each index
        table.update(AttributeDefinitions=attributes, GlobalSecondaryIndexUpdates=user_id_idx)

        with pytest.raises(Exception) as ctx:
            table.query(
                TableName=TEST_DDB_TABLE_NAME,
                IndexName="id-index",
                KeyConditionExpression=Key(PARTITION_KEY).eq(item_id),
                Select="ALL_ATTRIBUTES",
            )
        assert ctx.match("ValidationException")

    @pytest.mark.only_localstack
    def test_invalid_query_index(self, dynamodb):
        """Raises an exception when a query requests ALL_ATTRIBUTES,
        but the index does not have a ProjectionType of ALL"""
        table_name = f"test-table-{short_uid()}"
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "id", "AttributeType": "S"},
                {"AttributeName": "field_a", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "field_a_index",
                    "KeySchema": [{"AttributeName": "field_a", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 1,
                        "WriteCapacityUnits": 1,
                    },
                },
            ],
        )

        with pytest.raises(Exception) as ctx:
            table.query(
                TableName=table_name,
                IndexName="field_a_index",
                KeyConditionExpression=Key("field_a").eq("xyz"),
                Select="ALL_ATTRIBUTES",
            )
        assert ctx.match("ValidationException")

        # clean up
        delete_table(table_name)

    @pytest.mark.only_localstack
    def test_valid_query_index(self, dynamodb):
        """Query requests ALL_ATTRIBUTES and the named index has a ProjectionType of ALL,
        no exception should be raised."""
        table_name = f"test-table-{short_uid()}"
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "id", "AttributeType": "S"},
                {"AttributeName": "field_a", "AttributeType": "S"},
                {"AttributeName": "field_b", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "field_a_index",
                    "KeySchema": [{"AttributeName": "field_a", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 1,
                        "WriteCapacityUnits": 1,
                    },
                },
                {
                    "IndexName": "field_b_index",
                    "KeySchema": [{"AttributeName": "field_b", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 1,
                        "WriteCapacityUnits": 1,
                    },
                },
            ],
        )

        table.query(
            TableName=table_name,
            IndexName="field_b_index",
            KeyConditionExpression=Key("field_b").eq("xyz"),
            Select="ALL_ATTRIBUTES",
        )

        # clean up
        delete_table(table_name)

    @pytest.mark.aws_validated
    def test_valid_local_secondary_index(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"test-table-{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "LSI1SK", "AttributeType": "N"},
            ],
            LocalSecondaryIndexes=[
                {
                    "IndexName": "LSI1",
                    "KeySchema": [
                        {"AttributeName": "PK", "KeyType": "HASH"},
                        {"AttributeName": "LSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )

        item = {"SK": {"S": "hello"}, "LSI1SK": {"N": "123"}, "PK": {"S": "test one"}}

        aws_client.dynamodb.put_item(TableName=table_name, Item=item)
        result = aws_client.dynamodb.query(
            TableName=table_name,
            IndexName="LSI1",
            KeyConditionExpression="PK = :v1",
            ExpressionAttributeValues={":v1": {"S": "test one"}},
            Select="ALL_ATTRIBUTES",
        )
        transformed_dict = SortingTransformer("Items", lambda x: x).transform(result)
        snapshot.match("Items", transformed_dict)

    @pytest.mark.only_localstack(reason="AWS has a 20 GSI limit")
    def test_more_than_20_global_secondary_indexes(
        self, dynamodb_create_table_with_parameters, aws_client
    ):
        table_name = f"test-table-{short_uid()}"
        num_gsis = 25
        attrs = [{"AttributeName": f"a{i}", "AttributeType": "S"} for i in range(num_gsis)]
        gsis = [
            {
                "IndexName": f"gsi_{i}",
                "KeySchema": [{"AttributeName": f"a{i}", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
            for i in range(num_gsis)
        ]
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}, *attrs],
            GlobalSecondaryIndexes=gsis,
            BillingMode="PAY_PER_REQUEST",
        )

        table = aws_client.dynamodb.describe_table(TableName=table_name)
        assert len(table["Table"]["GlobalSecondaryIndexes"]) == num_gsis

    @pytest.mark.aws_validated
    def test_return_values_in_put_item(self, dynamodb, snapshot, aws_client):
        resources.create_dynamodb_table(
            TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY, client=aws_client.dynamodb
        )
        table = dynamodb.Table(TEST_DDB_TABLE_NAME)

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: "id1", "data": "foobar"}
        item1b = {PARTITION_KEY: "id1", "data": "barfoo"}
        item2 = {PARTITION_KEY: "id2", "data": "foobar"}

        # there is no data present in the table already so even if return values
        # is set to 'ALL_OLD' as there is no data it will not return any data.
        response = table.put_item(Item=item1, ReturnValues="ALL_OLD")
        snapshot.match("PutFirstItem", response)

        # now the same data is present so when we pass return values as 'ALL_OLD'
        # it should give us attributes
        response = table.put_item(Item=item1, ReturnValues="ALL_OLD")
        snapshot.match("PutFirstItemOLD", response)

        # now a previous version of data is present, so when we pass return
        # values as 'ALL_OLD' it should give us the old attributes
        response = table.put_item(Item=item1b, ReturnValues="ALL_OLD")
        snapshot.match("PutFirstItemB", response)

        # we do not have any same item as item2 already so when we add this by default
        # return values is set to None so no Attribute values should be returned
        response = table.put_item(Item=item2)
        snapshot.match("PutSecondItem", response)

        # in this case we already have item2 in the table so on this request
        # it should not return any data as return values is set to None so no
        # Attribute values should be returned
        response = table.put_item(Item=item2)
        snapshot.match("PutSecondItemReturnNone", response)

        # cleanup
        table.delete()

    @pytest.mark.aws_validated
    def test_empty_and_binary_values(self, dynamodb, snapshot, aws_client):
        table_name = f"table-{short_uid()}"
        resources.create_dynamodb_table(
            table_name=table_name, partition_key=PARTITION_KEY, client=aws_client.dynamodb
        )
        table = dynamodb.Table(table_name)

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: "id1", "data": ""}
        item2 = {PARTITION_KEY: "id2", "data": b"\x90"}

        response = table.put_item(Item=item1)
        snapshot.match("PutFirstItem", response)

        response = table.put_item(Item=item2)
        snapshot.match("PutSecondItem", response)

        # clean up
        table.delete()

    @pytest.mark.aws_validated
    def test_batch_write_binary(self, dynamodb_create_table_with_parameters, snapshot, aws_client):
        table_name = f"table_batch_binary_{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        aws_client.dynamodb.put_item(
            TableName=table_name,
            Item={"PK": {"S": "hello"}, "SK": {"S": "user"}, "data": {"B": b"test"}},
        )

        item = {
            "Item": {
                "PK": {"S": "hello-1"},
                "SK": {"S": "user-1"},
                "data": {"B": b"test-1"},
            }
        }
        item_non_decodable = {
            "Item": {
                "PK": {"S": "hello-2"},
                "SK": {"S": "user-2"},
                "data": {"B": b"test \xc0 \xed"},
            }
        }
        response = aws_client.dynamodb.batch_write_item(
            RequestItems={table_name: [{"PutRequest": item}, {"PutRequest": item_non_decodable}]}
        )
        snapshot.match("Response", response)

    @pytest.mark.only_localstack
    def test_binary_data_with_stream(
        self, wait_for_stream_ready, dynamodb_create_table_with_parameters, aws_client
    ):
        table_name = f"table-{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "NEW_AND_OLD_IMAGES",
            },
        )
        stream_name = get_kinesis_stream_name(table_name)
        wait_for_stream_ready(stream_name)
        response = aws_client.dynamodb.put_item(
            TableName=table_name, Item={"id": {"S": "id1"}, "data": {"B": b"\x90"}}
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        iterator = get_shard_iterator(stream_name, aws_client.kinesis)
        response = aws_client.kinesis.get_records(ShardIterator=iterator)
        json_records = response.get("Records")
        assert 1 == len(json_records)
        assert "Data" in json_records[0]

    @pytest.mark.only_localstack
    def test_dynamodb_stream_shard_iterator(
        self, wait_for_stream_ready, dynamodb_create_table_with_parameters
    ):
        ddbstreams = aws_stack.create_external_boto_client("dynamodbstreams")

        table_name = f"table_with_stream-{short_uid()}"
        table = dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "NEW_IMAGE",
            },
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        stream_name = get_kinesis_stream_name(table_name)

        wait_for_stream_ready(stream_name)

        stream_arn = table["TableDescription"]["LatestStreamArn"]
        result = ddbstreams.describe_stream(StreamArn=stream_arn)

        response = ddbstreams.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["StreamDescription"]["Shards"][0]["ShardId"],
            ShardIteratorType="LATEST",
        )
        assert "ShardIterator" in response
        response = ddbstreams.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["StreamDescription"]["Shards"][0]["ShardId"],
            ShardIteratorType="AT_SEQUENCE_NUMBER",
            SequenceNumber=result["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber"),
        )
        assert "ShardIterator" in response

    @pytest.mark.only_localstack
    def test_dynamodb_create_table_with_class(
        self, dynamodb_create_table_with_parameters, aws_client
    ):
        table_name = f"table_with_class_{short_uid()}"
        # create table
        result = dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            TableClass="STANDARD",
        )
        assert result["TableDescription"]["TableClassSummary"]["TableClass"] == "STANDARD"
        result = aws_client.dynamodb.describe_table(TableName=table_name)
        assert result["Table"]["TableClassSummary"]["TableClass"] == "STANDARD"
        result = aws_client.dynamodb.update_table(
            TableName=table_name, TableClass="STANDARD_INFREQUENT_ACCESS"
        )
        assert (
            result["TableDescription"]["TableClassSummary"]["TableClass"]
            == "STANDARD_INFREQUENT_ACCESS"
        )
        result = aws_client.dynamodb.describe_table(TableName=table_name)
        assert result["Table"]["TableClassSummary"]["TableClass"] == "STANDARD_INFREQUENT_ACCESS"

    @pytest.mark.aws_validated
    def test_dynamodb_execute_transaction(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"table_{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        statements = [
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user01'}}"},
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user02'}}"},
        ]
        result = aws_client.dynamodb.execute_transaction(TransactStatements=statements)
        snapshot.match("ExecutedTransaction", result)

        result = aws_client.dynamodb.scan(TableName=table_name)
        transformed_dict = SortingTransformer("Items", lambda x: x["Username"]["S"]).transform(
            result
        )
        snapshot.match("TableScan", transformed_dict)

    @pytest.mark.aws_validated
    def test_dynamodb_batch_execute_statement(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"test_table_{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        aws_client.dynamodb.put_item(TableName=table_name, Item={"Username": {"S": "user02"}})
        statements = [
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user01'}}"},
            {"Statement": f"UPDATE {table_name} SET Age=20 WHERE Username='user02'"},
        ]
        result = aws_client.dynamodb.batch_execute_statement(Statements=statements)
        # actions always succeeds
        sorted_result = SortingTransformer("Responses", lambda x: x["TableName"]).transform(result)
        snapshot.match("ExecutedStatement", sorted_result)

        item = aws_client.dynamodb.get_item(
            TableName=table_name, Key={"Username": {"S": "user02"}}
        )["Item"]
        snapshot.match("ItemUser2", item)

        item = aws_client.dynamodb.get_item(
            TableName=table_name, Key={"Username": {"S": "user01"}}
        )["Item"]
        snapshot.match("ItemUser1", item)

        aws_client.dynamodb.delete_table(TableName=table_name)

    @pytest.mark.aws_validated
    def test_dynamodb_partiql_missing(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"table_with_stream_{short_uid()}"

        # create table
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        # create items with FirstName attribute
        aws_client.dynamodb.execute_statement(
            Statement=f"INSERT INTO {table_name} VALUE {{'Username': 'Alice123', 'FirstName':'Alice'}}"
        )
        items = aws_client.dynamodb.execute_statement(
            Statement=f"SELECT * FROM {table_name} WHERE FirstName IS NOT MISSING"
        )["Items"]
        snapshot.match("FirstNameNotMissing", items)

        items = aws_client.dynamodb.execute_statement(
            Statement=f"SELECT * FROM {table_name} WHERE FirstName IS MISSING"
        )["Items"]
        assert len(items) == 0
        aws_client.dynamodb.delete_table(TableName=table_name)

    @pytest.mark.only_localstack
    def test_dynamodb_stream_stream_view_type(self):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        ddbstreams = aws_stack.create_external_boto_client("dynamodbstreams")
        table_name = "table_with_stream_%s" % short_uid()

        # create table
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "KEYS_ONLY",
            },
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        stream_arn = table["TableDescription"]["LatestStreamArn"]
        # wait for stream to be created
        sleep(1)

        # put item in table - INSERT event
        dynamodb.put_item(TableName=table_name, Item={"Username": {"S": "Fred"}})
        # update item in table - MODIFY event
        dynamodb.update_item(
            TableName=table_name,
            Key={"Username": {"S": "Fred"}},
            UpdateExpression="set S=:r",
            ExpressionAttributeValues={":r": {"S": "Fred_Modified"}},
            ReturnValues="UPDATED_NEW",
        )
        # delete item in table - REMOVE event
        dynamodb.delete_item(TableName=table_name, Key={"Username": {"S": "Fred"}})
        result = ddbstreams.describe_stream(StreamArn=stream_arn)
        # assert stream_view_type of the table
        assert result["StreamDescription"]["StreamViewType"] == "KEYS_ONLY"

        # add item via PartiQL query - INSERT event
        dynamodb.execute_statement(
            Statement=f"INSERT INTO {table_name} VALUE {{'Username': 'Alice'}}"
        )
        # run update via PartiQL query - MODIFY event
        dynamodb.execute_statement(
            Statement=f"UPDATE {table_name} SET partiql=1 WHERE Username='Alice'"
        )
        # run update via PartiQL query - REMOVE event
        dynamodb.execute_statement(Statement=f"DELETE FROM {table_name} WHERE Username='Alice'")

        # get shard iterator
        response = ddbstreams.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["StreamDescription"]["Shards"][0]["ShardId"],
            ShardIteratorType="AT_SEQUENCE_NUMBER",
            SequenceNumber=result["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber"),
        )

        # get stream records
        records = ddbstreams.get_records(ShardIterator=response["ShardIterator"])["Records"]
        assert len(records) == 6
        events = [rec["eventName"] for rec in records]
        assert events == ["INSERT", "MODIFY", "REMOVE"] * 2
        # assert that all records contain proper event IDs
        event_ids = [rec.get("eventID") for rec in records]
        assert all(event_ids)

        # assert that updates have been received from regular table operations and PartiQL query operations
        for idx, record in enumerate(records):
            assert "SequenceNumber" in record["dynamodb"]
            assert record["dynamodb"]["StreamViewType"] == "KEYS_ONLY"
            assert record["dynamodb"]["Keys"] == {"Username": {"S": "Fred" if idx < 3 else "Alice"}}
            assert "OldImage" not in record["dynamodb"]
            assert "NewImage" not in record["dynamodb"]

        # clean up
        delete_table(table_name)

    @pytest.mark.only_localstack
    def test_dynamodb_with_kinesis_stream(self):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        # Create Kinesis stream in another account to test that integration works cross-account
        kinesis = aws_stack.create_external_boto_client(
            "kinesis",
            aws_access_key_id="222244448888",
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        )

        # create kinesis datastream
        stream_name = f"kinesis_dest_stream_{short_uid()}"
        kinesis.create_stream(StreamName=stream_name, ShardCount=1)
        # wait for the stream to be created
        sleep(1)
        # Get stream description
        stream_description = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        table_name = "table_with_kinesis_stream-%s" % short_uid()
        # create table
        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        # Enable kinesis destination for the table
        dynamodb.enable_kinesis_streaming_destination(
            TableName=table_name, StreamArn=stream_description["StreamARN"]
        )

        # put item into table
        dynamodb.put_item(TableName=table_name, Item={"Username": {"S": "Fred"}})

        # update item in table
        dynamodb.update_item(
            TableName=table_name,
            Key={"Username": {"S": "Fred"}},
            UpdateExpression="set S=:r",
            ExpressionAttributeValues={":r": {"S": "Fred_Modified"}},
            ReturnValues="UPDATED_NEW",
        )

        # delete item in table
        dynamodb.delete_item(TableName=table_name, Key={"Username": {"S": "Fred"}})

        def _fetch_records():
            records = queries.kinesis_get_latest_records(
                stream_name,
                shard_id=stream_description["Shards"][0]["ShardId"],
                client=kinesis,
            )
            assert len(records) == 3
            return records

        # get records from the stream
        records = retry(_fetch_records)

        for record in records:
            record = json.loads(record["Data"])
            assert record["tableName"] == table_name
            # check eventSourceARN not exists in the stream record
            assert "eventSourceARN" not in record
            if record["eventName"] == "INSERT":
                assert "OldImage" not in record["dynamodb"]
                assert "NewImage" in record["dynamodb"]
            elif record["eventName"] == "MODIFY":
                assert "NewImage" in record["dynamodb"]
                assert "OldImage" in record["dynamodb"]
            elif record["eventName"] == "REMOVE":
                assert "NewImage" not in record["dynamodb"]
                assert "OldImage" in record["dynamodb"]
        # describe kinesis streaming destination of the table
        destinations = dynamodb.describe_kinesis_streaming_destination(TableName=table_name)
        destination = destinations["KinesisDataStreamDestinations"][0]

        # assert kinesis streaming destination status
        assert stream_description["StreamARN"] == destination["StreamArn"]
        assert destination["DestinationStatus"] == "ACTIVE"

        # Disable kinesis destination
        dynamodb.disable_kinesis_streaming_destination(
            TableName=table_name, StreamArn=stream_description["StreamARN"]
        )

        # describe kinesis streaming destination of the table
        result = dynamodb.describe_kinesis_streaming_destination(TableName=table_name)
        destination = result["KinesisDataStreamDestinations"][0]

        # assert kinesis streaming destination status
        assert stream_description["StreamARN"] == destination["StreamArn"]
        assert destination["DestinationStatus"] == "DISABLED"

        # clean up
        delete_table(table_name)
        kinesis.delete_stream(StreamName=stream_name)

    @pytest.mark.only_localstack
    def test_global_tables_version_2019(
        self, create_boto_client, cleanups, dynamodb_wait_for_table_active
    ):
        # Following https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables.tutorial.html

        # Create clients
        dynamodb_us_east_1 = create_boto_client("dynamodb", region_name="us-east-1")
        dynamodb_eu_west_1 = create_boto_client("dynamodb", region_name="eu-west-1")
        dynamodb_ap_south_1 = create_boto_client("dynamodb", region_name="ap-south-1")
        dynamodb_sa_east_1 = create_boto_client("dynamodb", region_name="sa-east-1")

        # Create table in AP
        table_name = f"table-{short_uid()}"
        dynamodb_ap_south_1.create_table(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "Artist", "KeyType": "HASH"},
                {"AttributeName": "SongTitle", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "Artist", "AttributeType": "S"},
                {"AttributeName": "SongTitle", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        cleanups.append(lambda: dynamodb_ap_south_1.delete_table(TableName=table_name))
        dynamodb_wait_for_table_active(table_name=table_name, client=dynamodb_ap_south_1)

        # Replicate table in US and EU
        dynamodb_ap_south_1.update_table(
            TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": "us-east-1"}}]
        )
        dynamodb_ap_south_1.update_table(
            TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": "eu-west-1"}}]
        )

        # Ensure all replicas can be described
        response = dynamodb_ap_south_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 3
        response = dynamodb_us_east_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 3
        response = dynamodb_eu_west_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 3
        with pytest.raises(Exception) as exc:
            dynamodb_sa_east_1.describe_table(TableName=table_name)
        exc.match("ResourceNotFoundException")

        # Ensure replicas can be listed everywhere
        response = dynamodb_ap_south_1.list_tables()
        assert table_name in response["TableNames"]
        response = dynamodb_us_east_1.list_tables()
        assert table_name in response["TableNames"]
        response = dynamodb_eu_west_1.list_tables()
        assert table_name in response["TableNames"]
        response = dynamodb_sa_east_1.list_tables()
        assert table_name not in response["TableNames"]

        # Put item in AP
        dynamodb_ap_south_1.put_item(
            TableName=table_name,
            Item={"Artist": {"S": "item_1"}, "SongTitle": {"S": "Song Value 1"}},
        )

        # Ensure item in US and EU
        item_us_east = dynamodb_us_east_1.get_item(
            TableName=table_name,
            Key={"Artist": {"S": "item_1"}, "SongTitle": {"S": "Song Value 1"}},
        )["Item"]
        assert item_us_east
        item_eu_west = dynamodb_eu_west_1.get_item(
            TableName=table_name,
            Key={"Artist": {"S": "item_1"}, "SongTitle": {"S": "Song Value 1"}},
        )["Item"]
        assert item_eu_west

        # Delete EU replica
        dynamodb_ap_south_1.update_table(
            TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": "eu-west-1"}}]
        )
        with pytest.raises(Exception) as ctx:
            dynamodb_eu_west_1.get_item(
                TableName=table_name,
                Key={"Artist": {"S": "item_1"}, "SongTitle": {"S": "Song Value 1"}},
            )
        ctx.match("ResourceNotFoundException")

        # Ensure deleting a non-existent replica raises
        with pytest.raises(Exception) as exc:
            dynamodb_ap_south_1.update_table(
                TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": "eu-west-1"}}]
            )
        exc.match(
            "Update global table operation failed because one or more replicas were not part of the global table"
        )

        # Ensure replica details are updated in other regions
        response = dynamodb_us_east_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 2
        response = dynamodb_ap_south_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 2

        # Ensure removing the last replica disables global table
        dynamodb_us_east_1.update_table(
            TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": "us-east-1"}}]
        )
        response = dynamodb_ap_south_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 0

    @pytest.mark.only_localstack
    def test_global_tables(self):
        resources.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        dynamodb = aws_stack.create_external_boto_client("dynamodb")

        # create global table
        regions = [
            {"RegionName": "us-east-1"},
            {"RegionName": "us-west-1"},
            {"RegionName": "eu-central-1"},
        ]
        response = dynamodb.create_global_table(
            GlobalTableName=TEST_DDB_TABLE_NAME, ReplicationGroup=regions
        )["GlobalTableDescription"]
        assert "ReplicationGroup" in response
        assert len(response["ReplicationGroup"]) == len(regions)

        # describe global table
        response = dynamodb.describe_global_table(GlobalTableName=TEST_DDB_TABLE_NAME)[
            "GlobalTableDescription"
        ]
        assert "ReplicationGroup" in response
        assert len(regions) == len(response["ReplicationGroup"])

        # update global table
        updates = [
            {"Create": {"RegionName": "us-east-2"}},
            {"Create": {"RegionName": "us-west-2"}},
            {"Delete": {"RegionName": "us-west-1"}},
        ]
        response = dynamodb.update_global_table(
            GlobalTableName=TEST_DDB_TABLE_NAME, ReplicaUpdates=updates
        )["GlobalTableDescription"]
        assert "ReplicationGroup" in response
        assert len(response["ReplicationGroup"]) == len(regions) + 1

        # assert exceptions for invalid requests
        with pytest.raises(Exception) as ctx:
            dynamodb.create_global_table(
                GlobalTableName=TEST_DDB_TABLE_NAME, ReplicationGroup=regions
            )
        assert ctx.match("GlobalTableAlreadyExistsException")
        with pytest.raises(Exception) as ctx:
            dynamodb.describe_global_table(GlobalTableName="invalid-table-name")
        assert ctx.match("GlobalTableNotFoundException")

    @pytest.mark.aws_validated
    def test_create_duplicate_table(self, dynamodb_create_table_with_parameters, snapshot):
        table_name = f"test_table_{short_uid()}"

        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )

        with pytest.raises(Exception) as ctx:
            dynamodb_create_table_with_parameters(
                TableName=table_name,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                Tags=TEST_DDB_TAGS,
            )
        snapshot.match("Error", ctx.value)

    @pytest.mark.only_localstack(
        reason="timing issues - needs a check to see if table is successfully deleted"
    )
    def test_delete_table(self, dynamodb_create_table, aws_client):
        table_name = f"test-ddb-table-{short_uid()}"

        tables_before = len(aws_client.dynamodb.list_tables()["TableNames"])

        dynamodb_create_table(
            table_name=table_name,
            partition_key=PARTITION_KEY,
        )

        table_list = aws_client.dynamodb.list_tables()
        # TODO: fix assertion, to enable parallel test execution!
        assert tables_before + 1 == len(table_list["TableNames"])
        assert table_name in table_list["TableNames"]

        aws_client.dynamodb.delete_table(TableName=table_name)

        table_list = aws_client.dynamodb.list_tables()
        assert tables_before == len(table_list["TableNames"])

        with pytest.raises(Exception) as ctx:
            aws_client.dynamodb.delete_table(TableName=table_name)
        assert ctx.match("ResourceNotFoundException")

    @pytest.mark.aws_validated
    def test_transaction_write_items(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"test-ddb-table-{short_uid()}"

        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )

        response = aws_client.dynamodb.transact_write_items(
            TransactItems=[
                {
                    "ConditionCheck": {
                        "TableName": table_name,
                        "ConditionExpression": "attribute_not_exists(id)",
                        "Key": {"id": {"S": "test1"}},
                    }
                },
                {"Put": {"TableName": table_name, "Item": {"id": {"S": "test2"}}}},
                {
                    "Update": {
                        "TableName": table_name,
                        "Key": {"id": {"S": "test3"}},
                        "UpdateExpression": "SET attr1 = :v1, attr2 = :v2",
                        "ExpressionAttributeValues": {
                            ":v1": {"S": "value1"},
                            ":v2": {"S": "value2"},
                        },
                    }
                },
                {"Delete": {"TableName": table_name, "Key": {"id": {"S": "test4"}}}},
            ]
        )
        snapshot.match("Response", response)

    @pytest.mark.aws_validated
    def test_transaction_write_canceled(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"table_{short_uid()}"

        # create table
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        # put item in table - INSERT event
        aws_client.dynamodb.put_item(TableName=table_name, Item={"Username": {"S": "Fred"}})

        # provoke a TransactionCanceledException by adding a condition which is not met
        with pytest.raises(Exception) as ctx:
            aws_client.dynamodb.transact_write_items(
                TransactItems=[
                    {
                        "ConditionCheck": {
                            "TableName": table_name,
                            "ConditionExpression": "attribute_not_exists(Username)",
                            "Key": {"Username": {"S": "Fred"}},
                        }
                    },
                    {"Delete": {"TableName": table_name, "Key": {"Username": {"S": "Bert"}}}},
                ]
            )
        snapshot.match("Error", ctx.value)

    @pytest.mark.aws_validated
    def test_transaction_write_binary_data(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"test-ddb-table-{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )
        binary_item = {"B": b"foobar"}
        response = aws_client.dynamodb.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": table_name,
                        "Item": {
                            "id": {"S": "someUser"},
                            "binaryData": binary_item,
                        },
                    }
                }
            ]
        )
        snapshot.match("WriteResponse", response)

        item = aws_client.dynamodb.get_item(TableName=table_name, Key={"id": {"S": "someUser"}})[
            "Item"
        ]
        snapshot.match("GetItem", item)

    @pytest.mark.aws_validated
    def test_transact_get_items(self, dynamodb_create_table, snapshot, aws_client):
        table_name = f"test-ddb-table-{short_uid()}"
        dynamodb_create_table(
            table_name=table_name,
            partition_key=PARTITION_KEY,
        )
        aws_client.dynamodb.put_item(TableName=table_name, Item={"id": {"S": "John"}})
        result = aws_client.dynamodb.transact_get_items(
            TransactItems=[{"Get": {"Key": {"id": {"S": "John"}}, "TableName": table_name}}]
        )
        snapshot.match("TransactGetItems", result)

    @pytest.mark.aws_validated
    def test_batch_write_items(self, dynamodb_create_table_with_parameters, snapshot, aws_client):
        table_name = f"test-ddb-table-{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )
        aws_client.dynamodb.put_item(TableName=table_name, Item={"id": {"S": "Fred"}})
        response = aws_client.dynamodb.batch_write_item(
            RequestItems={
                table_name: [
                    {"DeleteRequest": {"Key": {"id": {"S": "Fred"}}}},
                    {"PutRequest": {"Item": {"id": {"S": "Bob"}}}},
                ]
            }
        )
        snapshot.match("BatchWriteResponse", response)

    @pytest.mark.xfail(reason="this test flakes regularly in CI")
    def test_dynamodb_stream_records_with_update_item(
        self, dynamodb_resource, dynamodb_create_table, wait_for_stream_ready, aws_client
    ):
        table_name = f"test-ddb-table-{short_uid()}"

        dynamodb_create_table(
            table_name=table_name,
            partition_key=PARTITION_KEY,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )
        table = dynamodb_resource.Table(table_name)
        stream_name = get_kinesis_stream_name(table_name)

        wait_for_stream_ready(stream_name)

        response = aws_client.dynamodbstreams.describe_stream(StreamArn=table.latest_stream_arn)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(response["StreamDescription"]["Shards"]) == 1
        shard_id = response["StreamDescription"]["Shards"][0]["ShardId"]
        starting_sequence_number = int(
            response["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber")
        )

        response = aws_client.dynamodbstreams.get_shard_iterator(
            StreamArn=table.latest_stream_arn,
            ShardId=shard_id,
            ShardIteratorType="LATEST",
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert "ShardIterator" in response
        iterator_id = response["ShardIterator"]

        item_id = short_uid()
        for _ in range(2):
            aws_client.dynamodb.update_item(
                TableName=table_name,
                Key={PARTITION_KEY: {"S": item_id}},
                UpdateExpression="SET attr1 = :v1, attr2 = :v2",
                ExpressionAttributeValues={
                    ":v1": {"S": "value1"},
                    ":v2": {"S": "value2"},
                },
                ReturnValues="ALL_NEW",
                ReturnConsumedCapacity="INDEXES",
            )

        def check_expected_records():
            records = aws_client.dynamodbstreams.get_records(ShardIterator=iterator_id)
            assert records["ResponseMetadata"]["HTTPStatusCode"] == 200
            assert len(records["Records"]) == 2
            assert isinstance(
                records["Records"][0]["dynamodb"]["ApproximateCreationDateTime"],
                datetime,
            )
            assert records["Records"][0]["dynamodb"]["ApproximateCreationDateTime"].microsecond == 0
            assert records["Records"][0]["eventVersion"] == "1.1"
            assert records["Records"][0]["eventName"] == "INSERT"
            assert "OldImage" not in records["Records"][0]["dynamodb"]
            assert (
                int(records["Records"][0]["dynamodb"]["SequenceNumber"]) > starting_sequence_number
            )
            assert isinstance(
                records["Records"][1]["dynamodb"]["ApproximateCreationDateTime"],
                datetime,
            )
            assert records["Records"][1]["dynamodb"]["ApproximateCreationDateTime"].microsecond == 0
            assert records["Records"][1]["eventVersion"] == "1.1"
            assert records["Records"][1]["eventName"] == "MODIFY"
            assert "OldImage" in records["Records"][1]["dynamodb"]
            assert (
                int(records["Records"][1]["dynamodb"]["SequenceNumber"]) > starting_sequence_number
            )

        retry(check_expected_records, retries=5, sleep=1, sleep_before=2)

    @pytest.mark.only_localstack
    def test_query_on_deleted_resource(self, dynamodb_create_table, aws_client):
        table_name = f"ddb-table-{short_uid()}"
        partition_key = "username"

        dynamodb_create_table(table_name=table_name, partition_key=partition_key)

        rs = aws_client.dynamodb.query(
            TableName=table_name,
            KeyConditionExpression="{} = :username".format(partition_key),
            ExpressionAttributeValues={":username": {"S": "test"}},
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        aws_client.dynamodb.delete_table(TableName=table_name)

        with pytest.raises(Exception) as ctx:
            aws_client.dynamodb.query(
                TableName=table_name,
                KeyConditionExpression="{} = :username".format(partition_key),
                ExpressionAttributeValues={":username": {"S": "test"}},
            )
        assert ctx.match("ResourceNotFoundException")

    @pytest.mark.aws_validated
    def test_dynamodb_pay_per_request(self, dynamodb_create_table_with_parameters, snapshot):
        table_name = f"ddb-table-{short_uid()}"

        with pytest.raises(Exception) as e:
            dynamodb_create_table_with_parameters(
                TableName=table_name,
                KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                BillingMode="PAY_PER_REQUEST",
            )
        snapshot.match("Error", e.value)

    @pytest.mark.only_localstack
    def test_dynamodb_create_table_with_sse_specification(
        self, dynamodb_create_table_with_parameters
    ):
        table_name = f"ddb-table-{short_uid()}"

        kms_master_key_id = long_uid()
        sse_specification = {"Enabled": True, "SSEType": "KMS", "KMSMasterKeyId": kms_master_key_id}
        kms_master_key_arn = arns.kms_key_arn(kms_master_key_id)

        result = dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            SSESpecification=sse_specification,
            Tags=TEST_DDB_TAGS,
        )

        assert result["TableDescription"]["SSEDescription"]
        assert result["TableDescription"]["SSEDescription"]["Status"] == "ENABLED"
        assert result["TableDescription"]["SSEDescription"]["KMSMasterKeyArn"] == kms_master_key_arn

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..KeyMetadata..KeyUsage",
            "$..KeyMetadata..MultiRegion",
            "$..KeyMetadata..SigningAlgorithms",
        ]
    )
    def test_dynamodb_create_table_with_partial_sse_specification(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"test_table_{short_uid()}"
        sse_specification = {"Enabled": True}

        result = dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            SSESpecification=sse_specification,
            Tags=TEST_DDB_TAGS,
        )

        snapshot.match("SSEDescription", result["TableDescription"]["SSEDescription"])

        kms_master_key_arn = result["TableDescription"]["SSEDescription"]["KMSMasterKeyArn"]
        result = aws_client.kms.describe_key(KeyId=kms_master_key_arn)
        snapshot.match("KMSDescription", result)

    @pytest.mark.aws_validated
    def test_dynamodb_get_batch_items(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"test_table_{short_uid()}"

        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        result = aws_client.dynamodb.batch_get_item(
            RequestItems={table_name: {"Keys": [{"PK": {"S": "test-key"}}]}}
        )
        snapshot.match("Response", result)

    @pytest.mark.only_localstack
    def test_dynamodb_streams_describe_with_exclusive_start_shard_id(
        self, dynamodb_resource, dynamodb_create_table
    ):
        table_name = f"test-ddb-table-{short_uid()}"
        ddbstreams = aws_stack.create_external_boto_client("dynamodbstreams")

        dynamodb_create_table(
            table_name=table_name,
            partition_key=PARTITION_KEY,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )
        table = dynamodb_resource.Table(table_name)

        response = ddbstreams.describe_stream(StreamArn=table.latest_stream_arn)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(response["StreamDescription"]["Shards"]) == 1
        shard_id = response["StreamDescription"]["Shards"][0]["ShardId"]

        response = ddbstreams.describe_stream(
            StreamArn=table.latest_stream_arn, ExclusiveStartShardId=shard_id
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(response["StreamDescription"]["Shards"]) == 0

    @pytest.mark.aws_validated
    def test_dynamodb_streams_shard_iterator_format(
        self,
        dynamodb_create_table,
        wait_for_dynamodb_stream_ready,
        aws_client,
    ):
        """Test the dynamodb stream iterators starting with the stream arn followed by |<int>|"""
        table_name = f"test-table-{short_uid()}"
        partition_key = "my_partition_key"

        dynamodb_create_table(table_name=table_name, partition_key=partition_key)

        _await_dynamodb_table_active(aws_client.dynamodb, table_name)
        stream_arn = aws_client.dynamodb.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        )["TableDescription"]["LatestStreamArn"]
        assert wait_for_dynamodb_stream_ready(stream_arn)

        describe_stream_result = aws_client.dynamodbstreams.describe_stream(StreamArn=stream_arn)[
            "StreamDescription"
        ]
        shard_id = describe_stream_result["Shards"][0]["ShardId"]

        shard_iterator = aws_client.dynamodbstreams.get_shard_iterator(
            StreamArn=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]

        def _matches(iterator: str) -> bool:
            return bool(re.match(rf"^{stream_arn}\|\d\|.+$", iterator))

        assert _matches(shard_iterator)

        get_records_result = aws_client.dynamodbstreams.get_records(ShardIterator=shard_iterator)
        shard_iterator = get_records_result["NextShardIterator"]
        assert _matches(shard_iterator)
        assert not get_records_result["Records"]

    @pytest.mark.aws_validated
    def test_dynamodb_idempotent_writing(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"ddb-table-{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "id", "KeyType": "HASH"},
                {"AttributeName": "name", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "id", "AttributeType": "S"},
                {"AttributeName": "name", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        def _transact_write(_d: Dict):
            return aws_client.dynamodb.transact_write_items(
                ClientRequestToken="dedupe_token",
                TransactItems=[
                    {
                        "Put": {
                            "TableName": table_name,
                            "Item": _d,
                        }
                    },
                ],
            )

        response = _transact_write({"id": {"S": "id1"}, "name": {"S": "name1"}})
        snapshot.match("Response1", response)
        response = _transact_write({"name": {"S": "name1"}, "id": {"S": "id1"}})
        snapshot.match("Response2", response)

    @pytest.mark.aws_validated
    def test_batch_write_not_matching_schema(
        self,
        dynamodb_create_table_with_parameters,
        dynamodb_wait_for_table_active,
        snapshot,
        aws_client,
    ):
        table_name = f"ddb-table-{short_uid()}"

        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "id", "KeyType": "HASH"},
                {"AttributeName": "sortKey", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "id", "AttributeType": "S"},
                {"AttributeName": "sortKey", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        dynamodb_wait_for_table_active(table_name)

        faulty_item = {"Item": {"nonKey": {"S": "hello"}}}
        with pytest.raises(Exception) as ctx:
            aws_client.dynamodb.batch_write_item(
                RequestItems={table_name: [{"PutRequest": faulty_item}]}
            )
        snapshot.match("ValidationException", ctx.value)

    def test_batch_write_not_existing_table(self, aws_client):
        with pytest.raises(Exception) as ctx:
            aws_client.dynamodb.transact_write_items(
                TransactItems=[{"Put": {"TableName": "non-existing-table", "Item": {}}}]
            )
        ctx.match("ResourceNotFoundException")
        assert "retries" not in str(ctx)

    @pytest.mark.only_localstack
    def test_nosql_workbench_localhost_region(self, dynamodb_create_table, aws_client):
        """Test for AWS NoSQL Workbench, which sends "localhost" as region in header"""
        table_name = f"t-{short_uid()}"
        dynamodb_create_table(table_name=table_name, partition_key=PARTITION_KEY)
        # describe table for default region
        table = aws_client.dynamodb.describe_table(TableName=table_name)
        assert table.get("Table")
        # describe table for "localhost" region
        client = aws_stack.connect_to_service("dynamodb", region_name="localhost")
        table = client.describe_table(TableName=table_name)
        assert table.get("Table")

    @pytest.mark.only_localstack(reason="wait_for_stream_ready of kinesis stream")
    @pytest.mark.skip_snapshot_verify(paths=["$..eventID", "$..SequenceNumber", "$..SizeBytes"])
    def test_data_encoding_consistency(
        self, dynamodb_create_table_with_parameters, wait_for_stream_ready, snapshot, aws_client
    ):
        table_name = f"table-{short_uid()}"
        table = dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "NEW_AND_OLD_IMAGES",
            },
        )
        stream_name = get_kinesis_stream_name(table_name)
        wait_for_stream_ready(stream_name)

        # put item
        aws_client.dynamodb.put_item(
            TableName=table_name,
            Item={PARTITION_KEY: {"S": "id1"}, "version": {"N": "1"}, "data": {"B": b"\x90"}},
        )

        # get item
        item = aws_client.dynamodb.get_item(
            TableName=table_name, Key={PARTITION_KEY: {"S": "id1"}}
        )["Item"]
        snapshot.match("GetItem", item)

        # get stream records
        stream_arn = table["TableDescription"]["LatestStreamArn"]

        result = aws_client.dynamodbstreams.describe_stream(StreamArn=stream_arn)[
            "StreamDescription"
        ]

        response = aws_client.dynamodbstreams.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["Shards"][0]["ShardId"],
            ShardIteratorType="AT_SEQUENCE_NUMBER",
            SequenceNumber=result["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber"),
        )
        records = aws_client.dynamodbstreams.get_records(ShardIterator=response["ShardIterator"])[
            "Records"
        ]

        snapshot.match("GetRecords", records[0]["dynamodb"]["NewImage"])

        # update item
        aws_client.dynamodb.update_item(
            TableName=table_name,
            Key={PARTITION_KEY: {"S": "id1"}},
            UpdateExpression="SET version=:v",
            ExpressionAttributeValues={":v": {"N": "2"}},
        )

        # get item and get_records again to check for consistency
        item = aws_client.dynamodb.get_item(
            TableName=table_name, Key={PARTITION_KEY: {"S": "id1"}}
        )["Item"]
        snapshot.match("GetItemAfterUpdate", item)

        records = aws_client.dynamodbstreams.get_records(ShardIterator=response["ShardIterator"])[
            "Records"
        ]
        snapshot.match("GetRecordsAfterUpdate", records[1]["dynamodb"]["NewImage"])

    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..PointInTimeRecoveryDescription..EarliestRestorableDateTime",
            "$..PointInTimeRecoveryDescription..LatestRestorableDateTime",
        ]
    )
    def test_continuous_backup_update(self, dynamodb_create_table, snapshot, aws_client):
        table_name = f"table-{short_uid()}"
        dynamodb_create_table(
            table_name=table_name,
            partition_key=PARTITION_KEY,
        )

        def wait_for_continuous_backend():
            try:
                aws_client.dynamodb.update_continuous_backups(
                    TableName=table_name,
                    PointInTimeRecoverySpecification=PointInTimeRecoverySpecification(
                        PointInTimeRecoveryEnabled=True
                    ),
                )
                return True
            except ContinuousBackupsUnavailableException:
                return False

        assert poll_condition(wait_for_continuous_backend, timeout=10)

        response = aws_client.dynamodb.update_continuous_backups(
            TableName=table_name,
            PointInTimeRecoverySpecification=PointInTimeRecoverySpecification(
                PointInTimeRecoveryEnabled=True
            ),
        )

        snapshot.match("update-continuous-backup", response)

        response = aws_client.dynamodb.describe_continuous_backups(TableName=table_name)
        snapshot.match("describe-continuous-backup", response)


def delete_table(name):
    dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
    dynamodb_client.delete_table(TableName=name)
