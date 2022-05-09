# -*- coding: utf-8 -*-
import json
import re
from datetime import datetime
from time import sleep

import pytest
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import STRING

from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.services.dynamodbstreams.dynamodbstreams_api import get_kinesis_stream_name
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import KinesisStream
from localstack.utils.aws.aws_stack import get_environment
from localstack.utils.common import json_safe, long_uid, retry, short_uid
from localstack.utils.sync import poll_condition
from localstack.utils.testutil import check_expected_lambda_log_events_length

from .awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO

PARTITION_KEY = "id"

TEST_DDB_TABLE_NAME = "test-ddb-table-1"
TEST_DDB_TABLE_NAME_2 = "test-ddb-table-2"
TEST_DDB_TABLE_NAME_3 = "test-ddb-table-3"

TEST_DDB_TAGS = [
    {"Key": "Name", "Value": "test-table"},
    {"Key": "TestKey", "Value": "true"},
]


@pytest.fixture(scope="module")
def dynamodb():
    return aws_stack.connect_to_resource("dynamodb")


class TestDynamoDB:
    def test_non_ascii_chars(self, dynamodb):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
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

    def test_large_data_download(self, dynamodb):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME_2, partition_key=PARTITION_KEY)
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

    def test_time_to_live(self, dynamodb):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME_3, partition_key=PARTITION_KEY)
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

    def test_stream_spec_and_region_replacement(self, dynamodb):
        ddbstreams = aws_stack.create_external_boto_client("dynamodbstreams")
        kinesis = aws_stack.create_external_boto_client("kinesis")
        table_name = f"ddb-{short_uid()}"
        aws_stack.create_dynamodb_table(
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
        # assert stream has been deleted
        stream_tables = [s["TableName"] for s in ddbstreams.list_streams()["Streams"]]
        assert table_name not in stream_tables
        assert stream_name not in kinesis.list_streams()["StreamNames"]

    def test_multiple_update_expressions(self, dynamodb):
        dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
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

    def test_valid_local_secondary_index(self, dynamodb_client, dynamodb_create_table):
        try:
            table_name = f"test-table-{short_uid()}"
            dynamodb_client.create_table(
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

            def wait_for_table_created():
                return (
                    dynamodb_client.describe_table(TableName=table_name)["Table"]["TableStatus"]
                    == "ACTIVE"
                )

            poll_condition(wait_for_table_created, timeout=30)
            item = {"SK": {"S": "hello"}, "LSI1SK": {"N": "123"}, "PK": {"S": "test one"}}

            dynamodb_client.put_item(TableName=table_name, Item=item)
            result = dynamodb_client.query(
                TableName=table_name,
                IndexName="LSI1",
                KeyConditionExpression="PK = :v1",
                ExpressionAttributeValues={":v1": {"S": "test one"}},
                Select="ALL_ATTRIBUTES",
            )
            assert result["Items"] == [item]
        finally:
            dynamodb_client.delete_table(TableName=table_name)

    def test_more_than_20_global_secondary_indexes(self, dynamodb, dynamodb_client):
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
        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}, *attrs],
            GlobalSecondaryIndexes=gsis,
            BillingMode="PAY_PER_REQUEST",
        )

        table = dynamodb_client.describe_table(TableName=table_name)
        assert len(table["Table"]["GlobalSecondaryIndexes"]) == num_gsis

        # clean up
        delete_table(table_name)

    def test_return_values_in_put_item(self, dynamodb):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME)

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: "id1", "data": "foobar"}
        item2 = {PARTITION_KEY: "id2", "data": "foobar"}

        response = table.put_item(Item=item1, ReturnValues="ALL_OLD")
        # there is no data present in the table already so even if return values
        # is set to 'ALL_OLD' as there is no data it will not return any data.
        assert not response.get("Attributes")
        # now the same data is present so when we pass return values as 'ALL_OLD'
        # it should give us attributes
        response = table.put_item(Item=item1, ReturnValues="ALL_OLD")
        assert response.get("Attributes")
        assert item1.get("id") == response.get("Attributes").get("id")
        assert item1.get("data") == response.get("Attributes").get("data")

        response = table.put_item(Item=item2)
        # we do not have any same item as item2 already so when we add this by default
        # return values is set to None so no Attribute values should be returned
        assert not response.get("Attributes")

        response = table.put_item(Item=item2)
        # in this case we already have item2 in the table so on this request
        # it should not return any data as return values is set to None so no
        # Attribute values should be returned
        assert not response.get("Attributes")

    def test_empty_and_binary_values(self, dynamodb):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME)

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: "id1", "data": ""}
        item2 = {PARTITION_KEY: "id2", "data": b"foobar"}

        response = table.put_item(Item=item1)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        response = table.put_item(Item=item2)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_batch_write_binary(self, dynamodb_client):
        table_name = "table_batch_binary_%s" % short_uid()
        dynamodb_client.create_table(
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
        dynamodb_client.put_item(
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
        response = dynamodb_client.batch_write_item(
            RequestItems={table_name: [{"PutRequest": item}, {"PutRequest": item_non_decodable}]}
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        dynamodb_client.delete_table(TableName=table_name)

    def test_dynamodb_stream_shard_iterator(self):
        def wait_for_stream_created(table_name):
            stream_name = get_kinesis_stream_name(table_name)
            stream = KinesisStream(id=stream_name, num_shards=1)
            kinesis = aws_stack.create_external_boto_client("kinesis", env=get_environment(None))
            stream.connect(kinesis)
            stream.wait_for()

        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        ddbstreams = aws_stack.create_external_boto_client("dynamodbstreams")

        table_name = "table_with_stream-%s" % short_uid()
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "NEW_IMAGE",
            },
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        wait_for_stream_created(table_name)

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

    def test_dynamodb_create_table_with_class(self, dynamodb_client):
        table_name = "table_with_class_%s" % short_uid()
        # create table
        result = dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            TableClass="STANDARD",
        )
        assert result["TableDescription"]["TableClassSummary"]["TableClass"] == "STANDARD"
        result = dynamodb_client.describe_table(TableName=table_name)
        assert result["Table"]["TableClassSummary"]["TableClass"] == "STANDARD"
        result = dynamodb_client.update_table(
            TableName=table_name, TableClass="STANDARD_INFREQUENT_ACCESS"
        )
        assert (
            result["TableDescription"]["TableClassSummary"]["TableClass"]
            == "STANDARD_INFREQUENT_ACCESS"
        )
        result = dynamodb_client.describe_table(TableName=table_name)
        assert result["Table"]["TableClassSummary"]["TableClass"] == "STANDARD_INFREQUENT_ACCESS"
        # clean resources
        dynamodb_client.delete_table(TableName=table_name)

    def test_dynamodb_execute_transaction(self, dynamodb_client):
        table_name = "table_%s" % short_uid()
        dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        statements = [
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user01'}}"},
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user02'}}"},
        ]
        result = dynamodb_client.execute_transaction(TransactStatements=statements)
        assert result["ResponseMetadata"]["HTTPStatusCode"] == 200

        result = dynamodb_client.scan(TableName=table_name)
        assert result["ScannedCount"] == 2

        dynamodb_client.delete_table(TableName=table_name)

    def test_dynamodb_batch_execute_statement(self, dynamodb_client):
        table_name = "table_%s" % short_uid()
        dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        dynamodb_client.put_item(TableName=table_name, Item={"Username": {"S": "user02"}})
        statements = [
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user01'}}"},
            {"Statement": f"UPDATE {table_name} SET Age=20 WHERE Username='user02'"},
        ]
        result = dynamodb_client.batch_execute_statement(Statements=statements)
        # actions always succeeds
        assert not any("Error" in r for r in result["Responses"])

        item = dynamodb_client.get_item(TableName=table_name, Key={"Username": {"S": "user02"}})[
            "Item"
        ]
        assert item["Age"]["N"] == "20"

        item = dynamodb_client.get_item(TableName=table_name, Key={"Username": {"S": "user01"}})[
            "Item"
        ]
        assert item

        dynamodb_client.delete_table(TableName=table_name)

    def test_dynamodb_partiql_missing(self, dynamodb_client):
        table_name = "table_with_stream_%s" % short_uid()

        # create table
        dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        # create items with FirstName attribute
        dynamodb_client.execute_statement(
            Statement=f"INSERT INTO {table_name} VALUE {{'Username': 'Alice123', 'FirstName':'Alice'}}"
        )
        items = dynamodb_client.execute_statement(
            Statement=f"SELECT * FROM {table_name} WHERE FirstName IS NOT MISSING"
        )["Items"]
        assert len(items) == 1
        items = dynamodb_client.execute_statement(
            Statement=f"SELECT * FROM {table_name} WHERE FirstName IS MISSING"
        )["Items"]
        assert len(items) == 0
        dynamodb_client.delete_table(TableName=table_name)

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

    def test_dynamodb_with_kinesis_stream(self):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        kinesis = aws_stack.create_external_boto_client("kinesis")

        # create kinesis datastream
        stream_name = "kinesis_dest_stream"
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
            records = aws_stack.kinesis_get_latest_records(
                stream_name, shard_id=stream_description["Shards"][0]["ShardId"]
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
        kinesis.delete_stream(StreamName="kinesis_dest_stream")

    def test_global_tables(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
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

    def test_create_duplicate_table(self):
        table_name = "duplicateTable"
        dynamodb = aws_stack.create_external_boto_client("dynamodb")

        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )

        with pytest.raises(Exception) as ctx:
            dynamodb.create_table(
                TableName=table_name,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                Tags=TEST_DDB_TAGS,
            )
        ctx.match("ResourceInUseException")

        # clean up
        delete_table(table_name)

    def test_delete_table(self):
        table_name = "test-ddb-table-%s" % short_uid()
        dynamodb = aws_stack.create_external_boto_client("dynamodb")

        tables_before = len(dynamodb.list_tables()["TableNames"])

        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        table_list = dynamodb.list_tables()
        # TODO: fix assertion, to enable parallel test execution!
        assert tables_before + 1 == len(table_list["TableNames"])
        assert table_name in table_list["TableNames"]

        dynamodb.delete_table(TableName=table_name)

        table_list = dynamodb.list_tables()
        assert tables_before == len(table_list["TableNames"])

        with pytest.raises(Exception) as ctx:
            dynamodb.delete_table(TableName=table_name)
        assert ctx.match("ResourceNotFoundException")

    def test_transaction_write_items(self):
        table_name = "test-ddb-table-%s" % short_uid()
        dynamodb = aws_stack.create_external_boto_client("dynamodb")

        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )

        response = dynamodb.transact_write_items(
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
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # clean up
        dynamodb.delete_table(TableName=table_name)

    def test_transact_get_items(self, dynamodb_client):
        table_name = "test-ddb-table-%s" % short_uid()
        dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        dynamodb_client.put_item(TableName=table_name, Item={"id": {"S": "John"}})
        result = dynamodb_client.transact_get_items(
            TransactItems=[{"Get": {"Key": {"id": {"S": "John"}}, "TableName": table_name}}]
        )
        assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
        dynamodb_client.delete_table(TableName=table_name)

    def test_batch_write_items(self):
        table_name = "test-ddb-table-%s" % short_uid()
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )
        dynamodb.put_item(TableName=table_name, Item={"id": {"S": "Fred"}})
        response = dynamodb.batch_write_item(
            RequestItems={
                table_name: [
                    {"DeleteRequest": {"Key": {"id": {"S": "Fred"}}}},
                    {"PutRequest": {"Item": {"id": {"S": "Bob"}}}},
                ]
            }
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # clean up
        dynamodb.delete_table(TableName=table_name)

    def test_dynamodb_stream_records_with_update_item(self, dynamodb):
        table_name = f"test-ddb-table-{short_uid()}"
        dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
        ddbstreams = aws_stack.create_external_boto_client("dynamodbstreams")

        aws_stack.create_dynamodb_table(
            table_name,
            partition_key=PARTITION_KEY,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )
        table = dynamodb.Table(table_name)

        response = ddbstreams.describe_stream(StreamArn=table.latest_stream_arn)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(response["StreamDescription"]["Shards"]) == 1
        shard_id = response["StreamDescription"]["Shards"][0]["ShardId"]
        starting_sequence_number = int(
            response["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber")
        )

        response = ddbstreams.get_shard_iterator(
            StreamArn=table.latest_stream_arn,
            ShardId=shard_id,
            ShardIteratorType="LATEST",
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert "ShardIterator" in response
        iterator_id = response["ShardIterator"]

        item_id = short_uid()
        for _ in range(2):
            dynamodb_client.update_item(
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
            records = ddbstreams.get_records(ShardIterator=iterator_id)
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

        retry(check_expected_records, retries=5, sleep=1)

        dynamodb_client.delete_table(TableName=table_name)

    def test_query_on_deleted_resource(self):
        table_name = "ddb-table-%s" % short_uid()
        partition_key = "username"

        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        aws_stack.create_dynamodb_table(table_name, partition_key)

        rs = dynamodb.query(
            TableName=table_name,
            KeyConditionExpression="{} = :username".format(partition_key),
            ExpressionAttributeValues={":username": {"S": "test"}},
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        dynamodb.delete_table(TableName=table_name)

        with pytest.raises(Exception) as ctx:
            dynamodb.query(
                TableName=table_name,
                KeyConditionExpression="{} = :username".format(partition_key),
                ExpressionAttributeValues={":username": {"S": "test"}},
            )
        assert ctx.match("ResourceNotFoundException")

    def test_dynamodb_stream_to_lambda(self, dynamodb):
        table_name = "ddb-table-%s" % short_uid()
        function_name = "func-%s" % short_uid()
        partition_key = "SK"

        aws_stack.create_dynamodb_table(
            table_name=table_name,
            partition_key=partition_key,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )
        table = dynamodb.Table(table_name)
        latest_stream_arn = table.latest_stream_arn

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        lambda_client = aws_stack.create_external_boto_client("lambda")
        mapping_uuid = lambda_client.create_event_source_mapping(
            EventSourceArn=latest_stream_arn,
            FunctionName=function_name,
            StartingPosition="TRIM_HORIZON",
        )["UUID"]

        item = {"SK": short_uid(), "Name": "name-{}".format(short_uid())}

        table.put_item(Item=item)

        events = retry(
            check_expected_lambda_log_events_length,
            retries=10,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            regex_filter=r"Records",
        )

        assert len(events) == 1
        assert len(events[0]["Records"]) == 1

        dynamodb_event = events[0]["Records"][0]["dynamodb"]
        assert dynamodb_event["StreamViewType"] == "NEW_AND_OLD_IMAGES"
        assert dynamodb_event["Keys"] == {"SK": {"S": item["SK"]}}
        assert dynamodb_event["NewImage"]["Name"] == {"S": item["Name"]}
        assert "SequenceNumber" in dynamodb_event

        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        dynamodb.delete_table(TableName=table_name)
        lambda_client.delete_event_source_mapping(UUID=mapping_uuid)

    def test_dynamodb_batch_write_item(self):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        table_name = "ddb-table-%s" % short_uid()

        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )

        result = dynamodb.batch_write_item(
            RequestItems={
                table_name: [
                    {"PutRequest": {"Item": {PARTITION_KEY: {"S": "Test1"}}}},
                    {"PutRequest": {"Item": {PARTITION_KEY: {"S": "Test2"}}}},
                    {"PutRequest": {"Item": {PARTITION_KEY: {"S": "Test3"}}}},
                ]
            }
        )

        assert result.get("UnprocessedItems") == {}

    def test_dynamodb_pay_per_request(self):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        table_name = "ddb-table-%s" % short_uid()

        with pytest.raises(Exception) as e:
            dynamodb.create_table(
                TableName=table_name,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                BillingMode="PAY_PER_REQUEST",
            )
        assert e.match("ValidationException")

    def test_dynamodb_create_table_with_sse_specification(self):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        table_name = "ddb-table-%s" % short_uid()

        kms_master_key_id = long_uid()
        sse_specification = {"Enabled": True, "SSEType": "KMS", "KMSMasterKeyId": kms_master_key_id}
        kms_master_key_arn = aws_stack.kms_key_arn(kms_master_key_id)

        result = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            SSESpecification=sse_specification,
            Tags=TEST_DDB_TAGS,
        )

        assert result["TableDescription"]["SSEDescription"]
        assert result["TableDescription"]["SSEDescription"]["Status"] == "ENABLED"
        assert result["TableDescription"]["SSEDescription"]["KMSMasterKeyArn"] == kms_master_key_arn

        delete_table(table_name)

    def test_dynamodb_create_table_with_partial_sse_specification(self):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        table_name = "ddb-table-%s" % short_uid()

        sse_specification = {"Enabled": True}

        result = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            SSESpecification=sse_specification,
            Tags=TEST_DDB_TAGS,
        )

        assert result["TableDescription"]["SSEDescription"]
        assert result["TableDescription"]["SSEDescription"]["Status"] == "ENABLED"
        assert result["TableDescription"]["SSEDescription"]["SSEType"] == "KMS"
        assert "KMSMasterKeyArn" in result["TableDescription"]["SSEDescription"]
        kms_master_key_arn = result["TableDescription"]["SSEDescription"]["KMSMasterKeyArn"]
        kms_client = aws_stack.create_external_boto_client("kms")
        result = kms_client.describe_key(KeyId=kms_master_key_arn)
        assert result["KeyMetadata"]["KeyManager"] == "AWS"

        delete_table(table_name)

    def test_dynamodb_get_batch_items(self):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        table_name = "ddb-table-%s" % short_uid()

        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        result = dynamodb.batch_get_item(
            RequestItems={table_name: {"Keys": [{"PK": {"S": "test-key"}}]}}
        )
        assert list(result["Responses"])[0] == table_name


def delete_table(name):
    dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
    dynamodb_client.delete_table(TableName=name)
