# -*- coding: utf-8 -*-
import json
import time
from datetime import datetime
from typing import Dict

import pytest
from boto3.dynamodb.types import STRING

from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.services.dynamodbstreams.dynamodbstreams_api import get_kinesis_stream_name
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import long_uid, retry, short_uid
from localstack.utils.testutil import check_expected_lambda_log_events_length

from .awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO
from .test_kinesis import get_shard_iterator

PARTITION_KEY = "id"

TEST_DDB_TABLE_NAME_3 = "test-ddb-table-3"

TEST_DDB_TAGS = [
    {"Key": "Name", "Value": "test-table"},
    {"Key": "TestKey", "Value": "true"},
]


@pytest.fixture(autouse=True)
def dynamodb_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.dynamodb_api())


@pytest.fixture()
def dynamodb(dynamodb_resource):
    return dynamodb_resource


class TestDynamoDB:
    @pytest.mark.aws_validated
    def test_delete_table(self, dynamodb_client, dynamodb_create_table, snapshot):
        # This test has a race condition with global table tests
        # global tables are not properly deleted, therefore, the first list_tables call
        # will return existing tables. Temporary fix is to change order.
        tables_before = dynamodb_client.list_tables()
        snapshot.match("TablesBefore", tables_before)

        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        table_list = dynamodb_client.list_tables()
        snapshot.match("ListTables", table_list)

        dynamodb_client.delete_table(TableName=table_name)
        # wait a bit for deletion
        time.sleep(2)

        table_list = dynamodb_client.list_tables()
        snapshot.match("DeletedTable", table_list)

        with pytest.raises(Exception) as ctx:
            dynamodb_client.delete_table(TableName=table_name)
        snapshot.match("ErrorFailedDelete", ctx.value)

    @pytest.mark.aws_validated
    def test_non_ascii_chars(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        # write some items containing non-ASCII characters
        items = {
            "id1": {PARTITION_KEY: {"S": "id1"}, "data": {"S": "foobar123 ✓"}},
            "id2": {PARTITION_KEY: {"S": "id2"}, "data": {"S": "foobar123 £"}},
            "id3": {PARTITION_KEY: {"S": "id3"}, "data": {"S": "foobar123 ¢"}},
        }
        for k, item in items.items():
            dynamodb_client.put_item(TableName=table_name, Item=item)

        result = []
        for item_id in items.keys():
            item = dynamodb_client.get_item(
                TableName=table_name, Key={PARTITION_KEY: {"S": item_id}}
            )["Item"]
            result.append(item)

        result.sort(key=lambda k: k.get("id").get("S"))
        snapshot.match("Items", result)

    @pytest.mark.aws_validated
    def test_large_data_download(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        # Create a large amount of items
        num_items = 20
        for i in range(0, num_items):
            item = {PARTITION_KEY: {"S": "id%s" % i}, "data1": {"S": "foobar123 " * 1000}}
            dynamodb_client.put_item(TableName=table_name, Item=item)

        # Retrieve the items. The data will be transmitted to the client with chunked transfer encoding
        result = dynamodb_client.scan(TableName=table_name)
        sorted_items = result["Items"]
        sorted_items.sort(key=lambda k: k.get("id").get("S"))
        snapshot.match("Items", sorted_items)

    @pytest.mark.aws_validated
    def test_time_to_live(self, dynamodb_client, dynamodb_create_table):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        # Insert some items to the table
        items = {
            "id1": {PARTITION_KEY: {"S": "id1"}, "data": {"S": "IT IS"}},
            "id2": {PARTITION_KEY: {"S": "id2"}, "data": {"S": "TIME"}},
            "id3": {PARTITION_KEY: {"S": "id3"}, "data": {"S": "TO LIVE!"}},
        }
        for k, item in items.items():
            dynamodb_client.put_item(TableName=table_name, Item=item)

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
        delete_table(table_name)

    @pytest.mark.aws_validated
    def test_list_tags_of_resource(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            Tags=TEST_DDB_TAGS,
        )
        table_arn = table["TableDescription"]["TableArn"]

        rs = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)["Tags"]
        rs.sort(key=lambda k: k.get("Key"))
        snapshot.match("ResourceTags", rs)

        dynamodb_client.tag_resource(
            ResourceArn=table_arn, Tags=[{"Key": "NewKey", "Value": "TestValue"}]
        )

        rs = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)["Tags"]
        rs.sort(key=lambda k: k.get("Key"))
        snapshot.match("ResourceTagsOneAdded", rs)

        dynamodb_client.untag_resource(ResourceArn=table_arn, TagKeys=["Name", "NewKey"])

        rs = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)["Tags"]
        rs.sort(key=lambda k: k.get("Key"))
        snapshot.match("UntaggedResource", rs)

    @pytest.mark.aws_validated
    def test_stream_spec_and_region_replacement(
        self, kinesis_client, dynamodbstreams_client, dynamodb_create_table, snapshot
    ):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )
        table_name = table["TableDescription"]["TableName"]

        # assert stream has been created
        stream_tables = dynamodbstreams_client.list_streams()
        # assert table_name in stream_tables
        stream_name = get_kinesis_stream_name(table_name)
        assert stream_name in kinesis_client.list_streams()["StreamNames"]
        snapshot.match("StreamTables", stream_tables)

        # assert shard ID formats
        result = dynamodbstreams_client.describe_stream(
            StreamArn=table["TableDescription"]["LatestStreamArn"]
        )["StreamDescription"]
        snapshot.match("DescribeStream", result)

    @pytest.mark.aws_validated
    def test_multiple_update_expressions(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table_name = table["TableDescription"]["TableName"]
        item_id = "test_id"

        dynamodb_client.put_item(
            TableName=table_name, Item={PARTITION_KEY: {"S": item_id}, "data": {"S": "foobar123 ✓"}}
        )
        response = dynamodb_client.update_item(
            TableName=table_name,
            Key={PARTITION_KEY: {"S": item_id}},
            UpdateExpression="SET attr1 = :v1, attr2 = :v2",
            ExpressionAttributeValues={":v1": {"S": "value1"}, ":v2": {"S": "value2"}},
        )

        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        item = dynamodb_client.get_item(TableName=table_name, Key={PARTITION_KEY: {"S": item_id}})[
            "Item"
        ]

        snapshot.match("GetItem", item)
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
            dynamodb_client.query(
                TableName=table_name,
                IndexName="id-index",
                KeyConditionExpression=f"{PARTITION_KEY} = :{PARTITION_KEY}",
                ExpressionAttributeValues={f":{PARTITION_KEY}": {"S": item_id}},
                Select="ALL_ATTRIBUTES",
            )
        snapshot.match("ValidationException", ctx.value)

    @pytest.mark.aws_validated
    def test_query_index(self, dynamodb_client, dynamodb_create_table, snapshot):
        def create_table(projection_type: str = "INCLUDE"):
            # create valid table
            return dynamodb_create_table(
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

        table1 = create_table("INCLUDE")
        table_name = table1["TableDescription"]["TableName"]

        # query ALL_ATTRIBUTES
        resp = dynamodb_client.query(
            TableName=table_name,
            IndexName="field_b_index",
            KeyConditionExpression="field_b = :field_b",
            ExpressionAttributeValues={":field_b": {"S": "XYZ"}},
            Select="ALL_ATTRIBUTES",
        )

        snapshot.match("AllAttributesValid", resp)

        # projection type KEYS_ONLY should make the following query invalid
        table2 = create_table("KEYS_ONLY")
        table_name = table2["TableDescription"]["TableName"]

        with pytest.raises(Exception) as ctx:
            dynamodb_client.query(
                TableName=table_name,
                IndexName="field_a_index",
                KeyConditionExpression="field_b = :field_b",
                ExpressionAttributeValues={":field_b": {"S": "XYZ"}},
                Select="ALL_ATTRIBUTES",
            )
        snapshot.match("ProjectionError", ctx.value)

    @pytest.mark.aws_validated
    def test_valid_local_secondary_index(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
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
            BillingMode="PROVISIONED",
        )
        table_name = table["TableDescription"]["TableName"]

        item = {"SK": {"S": "hello"}, "LSI1SK": {"N": "123"}, "PK": {"S": "test one"}}

        dynamodb_client.put_item(TableName=table_name, Item=item)
        result = dynamodb_client.query(
            TableName=table_name,
            IndexName="LSI1",
            KeyConditionExpression="PK = :v1",
            ExpressionAttributeValues={":v1": {"S": "test one"}},
            Select="ALL_ATTRIBUTES",
        )
        snapshot.match("Items", result)

    @pytest.mark.only_localstack(reason="AWS has a 20 gsi limit")
    def test_more_than_20_global_secondary_indexes(self, dynamodb_client, dynamodb_create_table):
        num_gsis = 25
        attrs = [{"AttributeName": f"a{i}", "AttributeType": "S"} for i in range(num_gsis)]
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}, *attrs],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": f"gsi_{i}",
                    "KeySchema": [{"AttributeName": f"a{i}", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                }
                for i in range(num_gsis)
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table_name = table["TableDescription"]["TableName"]

        table = dynamodb_client.describe_table(TableName=table_name)
        assert len(table["Table"]["GlobalSecondaryIndexes"]) == num_gsis

    @pytest.mark.aws_validated
    def test_return_values_in_put_item(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: {"S": "id1"}, "data": {"S": "foobar"}}
        item1b = {PARTITION_KEY: {"S": "id1"}, "data": {"S": "barfoo"}}
        item2 = {PARTITION_KEY: {"S": "id2"}, "data": {"S": "foobar"}}

        # there is no data present in the table already so even if return values
        # is set to 'ALL_OLD' as there is no data it will not return any data.
        response = dynamodb_client.put_item(
            TableName=table_name, Item=item1, ReturnValues="ALL_OLD"
        )
        snapshot.match("PutItem1", response)
        # now the same data is present so when we pass return values as 'ALL_OLD'
        # it should give us attributes
        response = dynamodb_client.put_item(
            TableName=table_name, Item=item1, ReturnValues="ALL_OLD"
        )
        snapshot.match("PutItem1Old", response)

        # now a previous version of data is present, so when we pass return
        # values as 'ALL_OLD' it should give us the old attributes
        response = dynamodb_client.put_item(
            TableName=table_name, Item=item1b, ReturnValues="ALL_OLD"
        )
        snapshot.match("PutItem1b", response)

        # we do not have any same item as item2 already so when we add this by default
        # return values is set to None so no Attribute values should be returned
        response = dynamodb_client.put_item(TableName=table_name, Item=item2)
        snapshot.match("PutItem2", response)

        # in this case we already have item2 in the table so on this request
        # it should not return any data as return values is set to None so no
        # Attribute values should be returned
        response = dynamodb_client.put_item(TableName=table_name, Item=item2)
        snapshot.match("PutItem2ReturnNone", response)

    @pytest.mark.aws_validated
    def test_empty_and_binary_values(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table_name = table["TableDescription"]["TableName"]

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: {"S": "id1"}, "data": {"S": ""}}
        item2 = {PARTITION_KEY: {"S": "id2"}, "data": {"B": b"\x90"}}

        response = dynamodb_client.put_item(TableName=table_name, Item=item1)
        snapshot.match("PutFirstItem", response)

        response = dynamodb_client.put_item(TableName=table_name, Item=item2)
        snapshot.match("PutSecondItem", response)

    @pytest.mark.aws_validated
    def test_batch_write_binary(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
        )
        table_name = table["TableDescription"]["TableName"]

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
        snapshot.match("Response", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..Data"], reason="Encoding error described in issues 6700 & 6786"
    )
    def test_binary_data_with_stream(
        self,
        wait_for_stream_ready,
        dynamodb_create_table,
        dynamodb_client,
        kinesis_client,
        snapshot,
    ):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "NEW_AND_OLD_IMAGES",
            },
            BillingMode="PROVISIONED",
        )
        table_name = table["TableDescription"]["TableName"]
        stream_name = get_kinesis_stream_name(table_name)
        wait_for_stream_ready(stream_name)
        response = dynamodb_client.put_item(
            TableName=table_name, Item={"id": {"S": "id1"}, "data": {"B": b"\x90"}}
        )
        snapshot.match("PutItemResponse", response)

        iterator = get_shard_iterator(stream_name, kinesis_client)
        response = kinesis_client.get_records(ShardIterator=iterator)
        json_records = response.get("Records")
        snapshot.match("KinesisGetRecords", json_records)

    @pytest.mark.aws_validated
    def test_dynamodb_stream_shard_iterator(
        self, dynamodbstreams_client, wait_for_stream_ready, dynamodb_create_table, snapshot
    ):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "NEW_IMAGE",
            },
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            BillingMode="PROVISIONED",
        )
        table_name = table["TableDescription"]["TableName"]
        stream_name = get_kinesis_stream_name(table_name)

        wait_for_stream_ready(stream_name)

        stream_arn = table["TableDescription"]["LatestStreamArn"]
        result = dynamodbstreams_client.describe_stream(StreamArn=stream_arn)

        response = dynamodbstreams_client.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["StreamDescription"]["Shards"][0]["ShardId"],
            ShardIteratorType="LATEST",
        )
        snapshot.match("GetShardIteratorLatest", response)
        assert "ShardIterator" in response
        response = dynamodbstreams_client.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["StreamDescription"]["Shards"][0]["ShardId"],
            ShardIteratorType="AT_SEQUENCE_NUMBER",
            SequenceNumber=result["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber"),
        )
        snapshot.match("GetShardIteratorAtSequenceNumber", response)

        assert "ShardIterator" in response

    @pytest.mark.aws_validated
    def test_dynamodb_create_table_with_class(
        self, dynamodb_client, dynamodb_create_table, snapshot
    ):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            TableClass="STANDARD",
        )
        table_name = table["TableDescription"]["TableName"]

        snapshot.match("TableDescription", table["TableDescription"])

        result = dynamodb_client.describe_table(TableName=table_name)
        snapshot.match("DynamodbDescribeTable", result)

        result = dynamodb_client.update_table(
            TableName=table_name, TableClass="STANDARD_INFREQUENT_ACCESS"
        )
        snapshot.match("UpdateTableResult", result)

        result = dynamodb_client.describe_table(TableName=table_name)
        snapshot.match("DescribeTableResult", result)

    @pytest.mark.aws_validated
    def test_dynamodb_execute_transaction(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        statements = [
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user01'}}"},
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user02'}}"},
        ]
        result = dynamodb_client.execute_transaction(TransactStatements=statements)
        snapshot.match("ExecutedTransaction", result)

        result = dynamodb_client.scan(TableName=table_name)
        snapshot.match("TableScan", result)

    @pytest.mark.aws_validated
    def test_dynamodb_batch_execute_statement(
        self, dynamodb_client, dynamodb_create_table, snapshot
    ):
        table_name = f"table_{short_uid()}"
        dynamodb_create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
        )

        dynamodb_client.put_item(TableName=table_name, Item={"Username": {"S": "user02"}})
        statements = [
            {"Statement": f"INSERT INTO {table_name} VALUE {{'Username': 'user01'}}"},
            {"Statement": f"UPDATE {table_name} SET Age=20 WHERE Username='user02'"},
        ]
        result = dynamodb_client.batch_execute_statement(Statements=statements)
        snapshot.match("ExecutedStatement", result)

        item = dynamodb_client.get_item(TableName=table_name, Key={"Username": {"S": "user02"}})
        snapshot.match("ItemUser2", item)

        item = dynamodb_client.get_item(TableName=table_name, Key={"Username": {"S": "user01"}})
        snapshot.match("ItemUser1", item)

    @pytest.mark.aws_validated
    def test_dynamodb_partiql_missing(self, dynamodb_client, dynamodb_create_table, snapshot):
        # create table
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table_name = table["TableDescription"]["TableName"]

        # create items with FirstName attribute
        dynamodb_client.execute_statement(
            Statement=f"INSERT INTO {table_name} VALUE {{'Username': 'Alice123', 'FirstName':'Alice'}}"
        )
        items = dynamodb_client.execute_statement(
            Statement=f"SELECT * FROM {table_name} WHERE FirstName IS NOT MISSING"
        )["Items"]
        snapshot.match("FirstNameNotMissing", items)

        items = dynamodb_client.execute_statement(
            Statement=f"SELECT * FROM {table_name} WHERE FirstName IS MISSING"
        )["Items"]
        assert len(items) == 0

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..StreamDescription..Shards"])
    def test_dynamodb_stream_stream_view_type(
        self, dynamodb_client, dynamodbstreams_client, dynamodb_create_table, snapshot
    ):
        # create table
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "KEYS_ONLY",
            },
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        stream_arn = table["TableDescription"]["LatestStreamArn"]
        table_name = table["TableDescription"]["TableName"]

        # put item in table - INSERT event
        dynamodb_client.put_item(TableName=table_name, Item={"Username": {"S": "Fred"}})
        # update item in table - MODIFY event
        dynamodb_client.update_item(
            TableName=table_name,
            Key={"Username": {"S": "Fred"}},
            UpdateExpression="set S=:r",
            ExpressionAttributeValues={":r": {"S": "Fred_Modified"}},
            ReturnValues="UPDATED_NEW",
        )
        # delete item in table - REMOVE event
        dynamodb_client.delete_item(TableName=table_name, Key={"Username": {"S": "Fred"}})
        result = dynamodbstreams_client.describe_stream(StreamArn=stream_arn)
        # assert stream_view_type of the table
        snapshot.match("DescribeStream", result)

        # add item via PartiQL query - INSERT event
        dynamodb_client.execute_statement(
            Statement=f"INSERT INTO {table_name} VALUE {{'Username': 'Alice'}}"
        )
        # run update via PartiQL query - MODIFY event
        dynamodb_client.execute_statement(
            Statement=f"UPDATE {table_name} SET partiql=1 WHERE Username='Alice'"
        )
        # run update via PartiQL query - REMOVE event
        dynamodb_client.execute_statement(
            Statement=f"DELETE FROM {table_name} WHERE Username='Alice'"
        )

        # get shard iterator
        response = dynamodbstreams_client.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["StreamDescription"]["Shards"][0]["ShardId"],
            ShardIteratorType="AT_SEQUENCE_NUMBER",
            SequenceNumber=result["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber"),
        )

        # get stream records
        records = dynamodbstreams_client.get_records(ShardIterator=response["ShardIterator"])[
            "Records"
        ]

        snapshot.match("StreamRecords", records)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Data..dynamodb..ApproximateCreationDateTime"])
    def test_dynamodb_with_kinesis_stream(
        self,
        wait_for_stream_ready,
        dynamodb_client,
        kinesis_client,
        dynamodb_create_table,
        snapshot,
    ):
        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        kinesis = aws_stack.create_external_boto_client("kinesis")

        # create kinesis datastream
        stream_name = "kinesis_dest_stream"
        kinesis.create_stream(StreamName=stream_name, ShardCount=1)
        # wait for the stream to be created
        wait_for_stream_ready(stream_name)
        # Get stream description
        stream_description = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]

        # create table
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table_name = table["TableDescription"]["TableName"]

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
        snapshot.match("Records", records)

        # describe kinesis streaming destination of the table
        destinations = dynamodb.describe_kinesis_streaming_destination(TableName=table_name)
        destination = destinations["KinesisDataStreamDestinations"][0]
        snapshot.match("DescribeKinesisStreamingActive", destination)

        # Disable kinesis destination
        dynamodb.disable_kinesis_streaming_destination(
            TableName=table_name, StreamArn=stream_description["StreamARN"]
        )

        # describe kinesis streaming destination of the table
        result = dynamodb.describe_kinesis_streaming_destination(TableName=table_name)
        destination = result["KinesisDataStreamDestinations"][0]
        snapshot.match("DescribeKinesisStreamingDisabled", destination)

        # clean up
        delete_table(table_name)
        kinesis.delete_stream(StreamName="kinesis_dest_stream")

    @pytest.mark.only_localstack
    def test_global_tables_version_2019(
        self, create_boto_client, cleanups, dynamodb_wait_for_table_active
    ):
        # following https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables.tutorial.html

        # create clients
        dynamodb_us_east_1 = create_boto_client("dynamodb", region_name="us-east-1")
        dynamodb_eu_west_1 = create_boto_client("dynamodb", region_name="eu-west-1")
        dynamodb_us_east_2 = create_boto_client("dynamodb", region_name="us-east-2")

        # create table on us-east-1
        table_name = f"table-{short_uid()}"
        dynamodb_us_east_2.create_table(
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
        cleanups.append(lambda: dynamodb_us_east_2.delete_table(TableName=table_name))
        dynamodb_wait_for_table_active(table_name=table_name, client=dynamodb_us_east_2)
        # replica table on us-east-1
        dynamodb_us_east_2.update_table(
            TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": "us-east-1"}}]
        )
        # replica table on eu-west-1
        dynamodb_us_east_2.update_table(
            TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": "eu-west-1"}}]
        )
        response = dynamodb_us_east_2.describe_table(TableName=table_name)

        assert len(response["Table"]["Replicas"]) == 2

        # put item on us-east-2
        dynamodb_us_east_2.put_item(
            TableName=table_name,
            Item={"Artist": {"S": "item_1"}, "SongTitle": {"S": "Song Value 1"}},
        )
        # check the item on us-east-1 and eu-west-1
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
        # delete replica on us-west-1
        dynamodb_us_east_2.update_table(
            TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": "eu-west-1"}}]
        )
        with pytest.raises(Exception) as ctx:
            dynamodb_eu_west_1.get_item(
                TableName=table_name,
                Key={"Artist": {"S": "item_1"}, "SongTitle": {"S": "Song Value 1"}},
            )
        ctx.match("ResourceNotFoundException")

    @pytest.mark.aws_validated
    def test_global_tables(self, dynamodb_client):
        table_name = f"test_table_{short_uid()}"
        aws_stack.create_dynamodb_table(table_name, partition_key=PARTITION_KEY)
        aws_stack.create_external_boto_client("dynamodb")

        # create global table
        regions = [
            {"RegionName": "us-east-1"},
            {"RegionName": "us-west-1"},
            {"RegionName": "eu-central-1"},
        ]
        response = dynamodb_client.create_global_table(
            GlobalTableName=table_name, ReplicationGroup=regions
        )["GlobalTableDescription"]
        assert "ReplicationGroup" in response
        assert len(response["ReplicationGroup"]) == len(regions)

        # describe global table
        response = dynamodb_client.describe_global_table(GlobalTableName=table_name)[
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
        response = dynamodb_client.update_global_table(
            GlobalTableName=table_name, ReplicaUpdates=updates
        )["GlobalTableDescription"]
        assert "ReplicationGroup" in response
        assert len(response["ReplicationGroup"]) == len(regions) + 1

        # assert exceptions for invalid requests
        with pytest.raises(Exception) as ctx:
            dynamodb_client.create_global_table(
                GlobalTableName=table_name, ReplicationGroup=regions
            )
        assert ctx.match("GlobalTableAlreadyExistsException")
        with pytest.raises(Exception) as ctx:
            dynamodb_client.describe_global_table(GlobalTableName="invalid-table-name")
        assert ctx.match("GlobalTableNotFoundException")

    @pytest.mark.aws_validated
    def test_create_duplicate_table(self, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            Tags=TEST_DDB_TAGS,
        )
        table_name = table["TableDescription"]["TableName"]

        with pytest.raises(Exception) as ctx:
            dynamodb_create_table(
                TableName=table_name,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                Tags=TEST_DDB_TAGS,
            )
        snapshot.match("Error", ctx.value)

    @pytest.mark.aws_validated
    def test_transaction_write_items(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        response = dynamodb_client.transact_write_items(
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
    def test_transaction_write_canceled(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        # put item in table - INSERT event
        dynamodb_client.put_item(TableName=table_name, Item={"Username": {"S": "Fred"}})

        # provoke a TransactionCanceledException by adding a condition which is not met
        with pytest.raises(Exception) as ctx:
            dynamodb_client.transact_write_items(
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
    def test_transaction_write_binary_data(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        binary_item = {"B": b"foobar"}
        response = dynamodb_client.transact_write_items(
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

        item = dynamodb_client.get_item(TableName=table_name, Key={"id": {"S": "someUser"}})["Item"]
        snapshot.match("GetItem", item)

    @pytest.mark.aws_validated
    def test_transact_get_items(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]
        dynamodb_client.put_item(TableName=table_name, Item={"id": {"S": "John"}})
        result = dynamodb_client.transact_get_items(
            TransactItems=[{"Get": {"Key": {"id": {"S": "John"}}, "TableName": table_name}}]
        )
        snapshot.match("TransactGetItems", result)

    @pytest.mark.aws_validated
    def test_batch_write_items(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]
        dynamodb_client.put_item(TableName=table_name, Item={"id": {"S": "Fred"}})
        response = dynamodb_client.batch_write_item(
            RequestItems={
                table_name: [
                    {"DeleteRequest": {"Key": {"id": {"S": "Fred"}}}},
                    {"PutRequest": {"Item": {"id": {"S": "Bob"}}}},
                ]
            }
        )
        # assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        snapshot.match("BatchWriteResponse", response)

    @pytest.mark.xfail(reason="this test flakes regularly in CI")
    def test_dynamodb_stream_records_with_update_item(
        self,
        dynamodb_client,
        dynamodbstreams_client,
        dynamodb_resource,
        dynamodb_create_table,
        wait_for_stream_ready,
    ):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )
        table_name = table["TableDescription"]["TableName"]
        table_arn = table["TableDescription"]["TableArn"]
        stream_name = get_kinesis_stream_name(table_arn)

        wait_for_stream_ready(stream_name)

        response = dynamodbstreams_client.describe_stream(StreamArn=table.latest_stream_arn)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(response["StreamDescription"]["Shards"]) == 1
        shard_id = response["StreamDescription"]["Shards"][0]["ShardId"]
        starting_sequence_number = int(
            response["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber")
        )

        response = dynamodbstreams_client.get_shard_iterator(
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
            records = dynamodbstreams_client.get_records(ShardIterator=iterator_id)
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

    @pytest.mark.aws_validated
    def test_query_on_deleted_resource(self, dynamodb_client, dynamodb_create_table, snapshot):

        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
        )
        table_name = table["TableDescription"]["TableName"]

        rs = dynamodb_client.query(
            TableName=table_name,
            KeyConditionExpression=f"{PARTITION_KEY} = :{PARTITION_KEY}",
            ExpressionAttributeValues={f":{PARTITION_KEY}": {"S": "test"}},
            Select="ALL_ATTRIBUTES",
        )
        snapshot.match("QueryResult", rs)

        dynamodb_client.delete_table(TableName=table_name)

        with pytest.raises(Exception) as ctx:
            dynamodb_client.query(
                TableName=table_name,
                KeyConditionExpression=f"{PARTITION_KEY} = :{PARTITION_KEY}",
                ExpressionAttributeValues={f":{PARTITION_KEY}": {"S": "test"}},
            )
        snapshot.match("Error", ctx.value)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Records..dynamodb..ApproximateCreationDateTime",
            "$..ApproximateCreationDateTime",
        ]
    )
    def test_dynamodb_stream_to_lambda(
        self,
        lambda_client,
        dynamodb_client,
        dynamodb_resource,
        dynamodb_create_table,
        wait_for_stream_ready,
        snapshot,
    ):
        function_name = "func-%s" % short_uid()
        partition_key = "SK"

        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": partition_key, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": partition_key, "AttributeType": "S"}],
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )
        table_name = table["TableDescription"]["TableName"]
        latest_stream_arn = table["TableDescription"]["LatestStreamArn"]

        stream_name = get_kinesis_stream_name(table_name)
        wait_for_stream_ready(stream_name)

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        mapping_uuid = lambda_client.create_event_source_mapping(
            EventSourceArn=latest_stream_arn,
            FunctionName=function_name,
            StartingPosition="TRIM_HORIZON",
        )["UUID"]

        item = {"SK": {"S": "test-SK"}, "Name": {"S": "test-name"}}

        dynamodb_client.put_item(TableName=table_name, Item=item)

        events = retry(
            check_expected_lambda_log_events_length,
            retries=10,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            regex_filter=r"Records",
        )

        snapshot.match("Records", events)

        dynamodb_event = events[0]["Records"][0]["dynamodb"]
        snapshot.match("DynamoEvent", dynamodb_event)

        lambda_client.delete_event_source_mapping(UUID=mapping_uuid)

    @pytest.mark.aws_validated
    def test_dynamodb_batch_write_item(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            BillingMode="PROVISIONED",
        )
        table_name = table["TableDescription"]["TableName"]

        result = dynamodb_client.batch_write_item(
            RequestItems={
                table_name: [
                    {"PutRequest": {"Item": {PARTITION_KEY: {"S": "Test1"}}}},
                    {"PutRequest": {"Item": {PARTITION_KEY: {"S": "Test2"}}}},
                    {"PutRequest": {"Item": {PARTITION_KEY: {"S": "Test3"}}}},
                ]
            }
        )

        snapshot.match("Result", result)

    @pytest.mark.aws_validated
    def test_dynamodb_pay_per_request(self, dynamodb_create_table, snapshot):
        with pytest.raises(Exception) as e:
            dynamodb_create_table(
                KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                BillingMode="PAY_PER_REQUEST",
            )

        snapshot.match("Error", e.value)

    @pytest.mark.aws_validated
    def test_dynamodb_create_table_with_sse_specification(self, dynamodb_create_table, snapshot):
        kms_master_key_id = long_uid()
        sse_specification = {"Enabled": True, "SSEType": "KMS", "KMSMasterKeyId": kms_master_key_id}

        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            BillingMode="PROVISIONED",
            SSESpecification=sse_specification,
            Tags=TEST_DDB_TAGS,
        )

        snapshot.match(
            "TableDescription", sorted(table["TableDescription"].keys(), key=lambda x: x.lower())
        )

    @pytest.mark.aws_validated
    def test_dynamodb_create_table_with_partial_sse_specification(
        self, dynamodb_create_table, kms_client, snapshot
    ):
        sse_specification = {"Enabled": True}

        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            SSESpecification=sse_specification,
            BillingMode="PROVISIONED",
            Tags=TEST_DDB_TAGS,
        )

        snapshot.match("Table", table)
        kms_master_key_arn = table["TableDescription"]["SSEDescription"]["KMSMasterKeyArn"]
        result = kms_client.describe_key(KeyId=kms_master_key_arn)
        snapshot.match("KMSDescription", result)

    @pytest.mark.aws_validated
    def test_dynamodb_get_batch_items(self, dynamodb_client, dynamodb_create_table, snapshot):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            BillingMode="PROVISIONED",
        )
        table_name = table["TableDescription"]["TableName"]

        result = dynamodb_client.batch_get_item(
            RequestItems={table_name: {"Keys": [{"PK": {"S": "test-key"}}]}}
        )
        snapshot.match("Response", result)

    @pytest.mark.aws_validated
    def test_dynamodb_streams_describe_with_exclusive_start_shard_id(
        self, dynamodbstreams_client, dynamodb_create_table, snapshot
    ):
        table = dynamodb_create_table(
            KeySchema=[{"AttributeName": "Username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "Username", "AttributeType": "S"}],
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )
        stream_arn = table["TableDescription"]["LatestStreamArn"]

        response = dynamodbstreams_client.describe_stream(StreamArn=stream_arn)
        snapshot.match("DescribeStream", response)

        shard_id = response["StreamDescription"]["Shards"][0]["ShardId"]
        response = dynamodbstreams_client.describe_stream(
            StreamArn=stream_arn, ExclusiveStartShardId=shard_id
        )
        snapshot.match("DescribeStreamShardStart", response)

    @pytest.mark.aws_validated
    def test_dynamodb_idempotent_writing(self, dynamodb_create_table, dynamodb_client, snapshot):
        table = dynamodb_create_table(
            KeySchema=[
                {"AttributeName": "id", "KeyType": "HASH"},
                {"AttributeName": "name", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "id", "AttributeType": "S"},
                {"AttributeName": "name", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            BillingMode="PROVISIONED",
        )
        table_name = table["TableDescription"]["TableName"]

        def _transact_write(_d: Dict):
            res = dynamodb_client.transact_write_items(
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
            return res

        response = _transact_write({"id": {"S": "id1"}, "name": {"S": "name1"}})
        snapshot.match("Response1", response)
        response = _transact_write({"name": {"S": "name1"}, "id": {"S": "id1"}})
        snapshot.match("Response2", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..Error..Message"])
    def test_batch_write_not_matching_schema(
        self, dynamodb_client, dynamodb_create_table, snapshot
    ):
        table = dynamodb_create_table(
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

        faulty_item = {"Item": {"nonKey": {"S": "hello"}}}
        with pytest.raises(Exception) as ctx:
            dynamodb_client.batch_write_item(
                RequestItems={table.name: [{"PutRequest": faulty_item}]}
            )
        snapshot.match("ValidationException", ctx.value)


def delete_table(name):
    dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
    dynamodb_client.delete_table(TableName=name)
