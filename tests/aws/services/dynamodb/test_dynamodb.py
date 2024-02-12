import json
import re
import time
from datetime import datetime
from time import sleep
from typing import Dict

import botocore.exceptions
import pytest
import requests
from boto3.dynamodb.types import STRING
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack import config
from localstack.aws.api.dynamodb import PointInTimeRecoverySpecification
from localstack.constants import AWS_REGION_US_EAST_1, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.services.dynamodbstreams.dynamodbstreams_api import get_kinesis_stream_name
from localstack.testing.aws.lambda_utils import _await_dynamodb_table_active
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils import testutil
from localstack.utils.aws import arns, queries, resources
from localstack.utils.aws.resources import create_dynamodb_table
from localstack.utils.common import json_safe, long_uid, retry, short_uid
from localstack.utils.sync import poll_condition, wait_until
from tests.aws.services.kinesis.test_kinesis import get_shard_iterator

PARTITION_KEY = "id"

TEST_DDB_TAGS = [
    {"Key": "Name", "Value": "test-table"},
    {"Key": "TestKey", "Value": "true"},
]


@pytest.fixture(autouse=True)
def dynamodb_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.dynamodb_api())


@pytest.fixture
def dynamodbstreams_snapshot_transformers(snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("TableName"),
            snapshot.transform.key_value("TableStatus"),
            snapshot.transform.key_value("LatestStreamLabel"),
            snapshot.transform.key_value("StartingSequenceNumber", reference_replacement=False),
            snapshot.transform.key_value("ShardId"),
            snapshot.transform.key_value("StreamLabel"),
            snapshot.transform.key_value("SequenceNumber"),
            snapshot.transform.key_value("eventID"),
        ]
    )
    snapshot.add_transformer(snapshot.transform.key_value("NextShardIterator"), priority=-1)
    snapshot.add_transformer(snapshot.transform.key_value("ShardIterator"), priority=-1)


class TestDynamoDB:
    @pytest.fixture
    def ddb_test_table(self, aws_client) -> str:
        """
        This fixture returns a DynamoDB table for testing.
        """
        table_name = f"ddb-test-table-{short_uid()}"
        resources.create_dynamodb_table(
            table_name, partition_key=PARTITION_KEY, client=aws_client.dynamodb
        )

        yield table_name

        aws_client.dynamodb.delete_table(TableName=table_name)

    @markers.aws.only_localstack
    def test_non_ascii_chars(self, aws_client, ddb_test_table):
        # write some items containing non-ASCII characters
        items = {
            "id1": {PARTITION_KEY: {"S": "id1"}, "data": {"S": "foobar123 ✓"}},
            "id2": {PARTITION_KEY: {"S": "id2"}, "data": {"S": "foobar123 £"}},
            "id3": {PARTITION_KEY: {"S": "id3"}, "data": {"S": "foobar123 ¢"}},
        }
        for _, item in items.items():
            aws_client.dynamodb.put_item(TableName=ddb_test_table, Item=item)

        for item_id in items.keys():
            item = aws_client.dynamodb.get_item(
                TableName=ddb_test_table, Key={PARTITION_KEY: {"S": item_id}}
            )["Item"]

            # need to fix up the JSON and convert str to unicode for Python 2
            item1 = json_safe(item)
            item2 = json_safe(items[item_id])
            assert item1 == item2

    @markers.aws.only_localstack
    def test_large_data_download(self, aws_client, ddb_test_table):
        # Create a large amount of items
        num_items = 20
        for i in range(0, num_items):
            item = {PARTITION_KEY: {"S": "id%s" % i}, "data1": {"S": "foobar123 " * 1000}}
            aws_client.dynamodb.put_item(TableName=ddb_test_table, Item=item)

        # Retrieve the items. The data will be transmitted to the client with chunked transfer encoding
        result = aws_client.dynamodb.scan(TableName=ddb_test_table)
        assert len(result["Items"]) == num_items

    @markers.aws.only_localstack
    def test_time_to_live_deletion(self, aws_client, ddb_test_table):
        table_name = ddb_test_table
        aws_client.dynamodb.update_time_to_live(
            TableName=table_name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "expiringAt"},
        )
        aws_client.dynamodb.describe_time_to_live(TableName=table_name)

        exp = int(time.time()) - 10  # expired
        items = [
            {PARTITION_KEY: {"S": "expired"}, "expiringAt": {"N": str(exp)}},
            {PARTITION_KEY: {"S": "not-expired"}, "expiringAt": {"N": str(exp + 120)}},
        ]
        for item in items:
            aws_client.dynamodb.put_item(TableName=table_name, Item=item)

        url = f"{config.internal_service_url()}/_aws/dynamodb/expired"
        response = requests.delete(url)
        assert response.status_code == 200
        assert response.json() == {"ExpiredItems": 1}

        result = aws_client.dynamodb.get_item(
            TableName=table_name, Key={PARTITION_KEY: {"S": "not-expired"}}
        )
        assert result.get("Item")
        result = aws_client.dynamodb.get_item(
            TableName=table_name, Key={PARTITION_KEY: {"S": "expired"}}
        )
        assert not result.get("Item")

    @markers.aws.only_localstack
    def test_time_to_live(self, aws_client, ddb_test_table):
        # check response for nonexistent table
        response = testutil.send_describe_dynamodb_ttl_request("test")
        assert json.loads(response._content)["__type"] == "ResourceNotFoundException"
        assert response.status_code == 400

        response = testutil.send_update_dynamodb_ttl_request("test", True)
        assert json.loads(response._content)["__type"] == "ResourceNotFoundException"
        assert response.status_code == 400

        # Insert some items to the table
        items = {
            "id1": {PARTITION_KEY: {"S": "id1"}, "data": {"S": "IT IS"}},
            "id2": {PARTITION_KEY: {"S": "id2"}, "data": {"S": "TIME"}},
            "id3": {PARTITION_KEY: {"S": "id3"}, "data": {"S": "TO LIVE!"}},
        }

        for _, item in items.items():
            aws_client.dynamodb.put_item(TableName=ddb_test_table, Item=item)

        # Describe TTL when still unset
        response = testutil.send_describe_dynamodb_ttl_request(ddb_test_table)
        assert response.status_code == 200
        assert (
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"] == "DISABLED"
        )

        # Enable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(ddb_test_table, True)
        assert response.status_code == 200
        assert json.loads(response._content)["TimeToLiveSpecification"]["Enabled"]

        # Describe TTL status after being enabled.
        response = testutil.send_describe_dynamodb_ttl_request(ddb_test_table)
        assert response.status_code == 200
        assert (
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"] == "ENABLED"
        )

        # Disable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(ddb_test_table, False)
        assert response.status_code == 200
        assert not json.loads(response._content)["TimeToLiveSpecification"]["Enabled"]

        # Describe TTL status after being disabled.
        response = testutil.send_describe_dynamodb_ttl_request(ddb_test_table)
        assert response.status_code == 200
        assert (
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"] == "DISABLED"
        )

        # Enable TTL for given table again
        response = testutil.send_update_dynamodb_ttl_request(ddb_test_table, True)
        assert response.status_code == 200
        assert json.loads(response._content)["TimeToLiveSpecification"]["Enabled"]

        # Describe TTL status after being enabled again.
        response = testutil.send_describe_dynamodb_ttl_request(ddb_test_table)
        assert response.status_code == 200
        assert (
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"] == "ENABLED"
        )

    @markers.aws.only_localstack
    def test_list_tags_of_resource(self, aws_client):
        table_name = "ddb-table-%s" % short_uid()

        rs = aws_client.dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )
        table_arn = rs["TableDescription"]["TableArn"]

        rs = aws_client.dynamodb.list_tags_of_resource(ResourceArn=table_arn)

        assert rs["Tags"] == TEST_DDB_TAGS

        aws_client.dynamodb.tag_resource(
            ResourceArn=table_arn, Tags=[{"Key": "NewKey", "Value": "TestValue"}]
        )

        rs = aws_client.dynamodb.list_tags_of_resource(ResourceArn=table_arn)

        assert len(rs["Tags"]) == len(TEST_DDB_TAGS) + 1

        tags = {tag["Key"]: tag["Value"] for tag in rs["Tags"]}
        assert "NewKey" in tags.keys()
        assert tags["NewKey"] == "TestValue"

        aws_client.dynamodb.untag_resource(ResourceArn=table_arn, TagKeys=["Name", "NewKey"])

        rs = aws_client.dynamodb.list_tags_of_resource(ResourceArn=table_arn)
        tags = {tag["Key"]: tag["Value"] for tag in rs["Tags"]}
        assert "Name" not in tags.keys()
        assert "NewKey" not in tags.keys()

        aws_client.dynamodb.delete_table(TableName=table_name)

    @markers.aws.only_localstack
    def test_multiple_update_expressions(self, aws_client, ddb_test_table):
        item_id = short_uid()
        aws_client.dynamodb.put_item(
            TableName=ddb_test_table,
            Item={PARTITION_KEY: {"S": item_id}, "data": {"S": "foobar123 ✓"}},
        )
        response = aws_client.dynamodb.update_item(
            TableName=ddb_test_table,
            Key={PARTITION_KEY: {"S": item_id}},
            UpdateExpression="SET attr1 = :v1, attr2 = :v2",
            ExpressionAttributeValues={":v1": {"S": "value1"}, ":v2": {"S": "value2"}},
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        item = aws_client.dynamodb.get_item(
            TableName=ddb_test_table, Key={PARTITION_KEY: {"S": item_id}}
        )["Item"]
        assert item["attr1"] == {"S": "value1"}
        assert item["attr2"] == {"S": "value2"}
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
        aws_client.dynamodb.update_table(
            TableName=ddb_test_table,
            AttributeDefinitions=attributes,
            GlobalSecondaryIndexUpdates=user_id_idx,
        )

        with pytest.raises(Exception) as ctx:
            aws_client.dynamodb.query(
                TableName=ddb_test_table,
                IndexName="id-index",
                KeyConditionExpression=f"{PARTITION_KEY} = :item",
                ExpressionAttributeValues={":item": {"S": item_id}},
                Select="ALL_ATTRIBUTES",
            )
        assert ctx.match("ValidationException")

    @markers.aws.only_localstack
    def test_invalid_query_index(self, aws_client):
        """Raises an exception when a query requests ALL_ATTRIBUTES,
        but the index does not have a ProjectionType of ALL"""
        table_name = f"test-table-{short_uid()}"
        aws_client.dynamodb.create_table(
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
            aws_client.dynamodb.query(
                TableName=table_name,
                IndexName="field_a_index",
                KeyConditionExpression="field_a = :field_value",
                ExpressionAttributeValues={":field_value": {"S": "xyz"}},
                Select="ALL_ATTRIBUTES",
            )
        assert ctx.match("ValidationException")

        # clean up
        aws_client.dynamodb.delete_table(TableName=table_name)

    @markers.aws.only_localstack
    def test_valid_query_index(self, aws_client):
        """Query requests ALL_ATTRIBUTES and the named index has a ProjectionType of ALL,
        no exception should be raised."""
        table_name = f"test-table-{short_uid()}"
        aws_client.dynamodb.create_table(
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

        aws_client.dynamodb.query(
            TableName=table_name,
            IndexName="field_b_index",
            KeyConditionExpression="field_b = :field_value",
            ExpressionAttributeValues={":field_value": {"S": "xyz"}},
            Select="ALL_ATTRIBUTES",
        )

        # clean up
        aws_client.dynamodb.delete_table(TableName=table_name)

    @markers.aws.validated
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

    @markers.aws.only_localstack(reason="AWS has a 20 GSI limit")
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

    @markers.aws.validated
    def test_return_values_in_put_item(self, snapshot, aws_client, ddb_test_table):
        # items which are being used to put in the table
        item1 = {PARTITION_KEY: {"S": "id1"}, "data": {"S": "foobar"}}
        item1b = {PARTITION_KEY: {"S": "id1"}, "data": {"S": "barfoo"}}
        item2 = {PARTITION_KEY: {"S": "id1"}, "data": {"S": "foobar"}}

        # there is no data present in the table already so even if return values
        # is set to 'ALL_OLD' as there is no data it will not return any data.
        response = aws_client.dynamodb.put_item(
            TableName=ddb_test_table, Item=item1, ReturnValues="ALL_OLD"
        )
        snapshot.match("PutFirstItem", response)

        # now the same data is present so when we pass return values as 'ALL_OLD'
        # it should give us attributes
        response = aws_client.dynamodb.put_item(
            TableName=ddb_test_table, Item=item1, ReturnValues="ALL_OLD"
        )
        snapshot.match("PutFirstItemOLD", response)

        # now a previous version of data is present, so when we pass return
        # values as 'ALL_OLD' it should give us the old attributes
        response = aws_client.dynamodb.put_item(
            TableName=ddb_test_table, Item=item1b, ReturnValues="ALL_OLD"
        )
        snapshot.match("PutFirstItemB", response)

        # we do not have any same item as item2 already so when we add this by default
        # return values is set to None so no Attribute values should be returned
        response = aws_client.dynamodb.put_item(TableName=ddb_test_table, Item=item2)
        snapshot.match("PutSecondItem", response)

        # in this case we already have item2 in the table so on this request
        # it should not return any data as return values is set to None so no
        # Attribute values should be returned
        response = aws_client.dynamodb.put_item(TableName=ddb_test_table, Item=item2)
        snapshot.match("PutSecondItemReturnNone", response)

    @markers.aws.validated
    def test_empty_and_binary_values(self, snapshot, aws_client):
        table_name = f"table-{short_uid()}"
        resources.create_dynamodb_table(
            table_name=table_name, partition_key=PARTITION_KEY, client=aws_client.dynamodb
        )

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: {"S": "id1"}, "data": {"S": ""}}
        item2 = {PARTITION_KEY: {"S": "id2"}, "data": {"B": b"\x90"}}

        response = aws_client.dynamodb.put_item(TableName=table_name, Item=item1)
        snapshot.match("PutFirstItem", response)

        response = aws_client.dynamodb.put_item(TableName=table_name, Item=item2)
        snapshot.match("PutSecondItem", response)

        # clean up
        aws_client.dynamodb.delete_table(TableName=table_name)

    @markers.aws.validated
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

    @markers.aws.only_localstack
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

    @markers.aws.only_localstack
    def test_dynamodb_stream_shard_iterator(
        self, aws_client, wait_for_stream_ready, dynamodb_create_table_with_parameters
    ):
        ddbstreams = aws_client.dynamodbstreams

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

    @markers.aws.only_localstack
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

    @markers.aws.validated
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

    @markers.aws.validated
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

    @markers.aws.validated
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

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..SizeBytes",
            "$..DeletionProtectionEnabled",
            "$..ProvisionedThroughput.NumberOfDecreasesToday",
            "$..StreamDescription.CreationRequestDateTime",
        ]
    )
    def test_dynamodb_stream_stream_view_type(
        self,
        aws_client,
        dynamodb_create_table_with_parameters,
        wait_for_dynamodb_stream_ready,
        snapshot,
        dynamodbstreams_snapshot_transformers,
    ):
        dynamodb = aws_client.dynamodb
        ddbstreams = aws_client.dynamodbstreams
        table_name = f"table_with_stream_{short_uid()}"

        # create table
        table = dynamodb_create_table_with_parameters(
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
        snapshot.match("create-table", table)
        wait_for_dynamodb_stream_ready(stream_arn=stream_arn)

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
        snapshot.match("describe-stream", result)

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
        snapshot.match("get-shard-iterator", response)

        shard_iterator = response["ShardIterator"]
        # get stream records
        records = []

        def _get_records_amount(record_amount: int):
            nonlocal shard_iterator
            if len(records) < record_amount:
                _resp = aws_client.dynamodbstreams.get_records(ShardIterator=shard_iterator)
                records.extend(_resp["Records"])
                if next_shard_iterator := _resp.get("NextShardIterator"):
                    shard_iterator = next_shard_iterator

            assert len(records) >= record_amount

        retry(lambda: _get_records_amount(6), sleep=1, retries=3)
        snapshot.match("get-records", {"Records": records})

    @markers.aws.only_localstack
    def test_dynamodb_with_kinesis_stream(self, aws_client, secondary_aws_client):
        dynamodb = aws_client.dynamodb
        # Create Kinesis stream in another account to test that integration works cross-account
        kinesis = secondary_aws_client.kinesis

        # create kinesis datastream
        stream_name = f"kinesis_dest_stream_{short_uid()}"
        kinesis.create_stream(StreamName=stream_name, ShardCount=1)
        # wait for the stream to be created
        sleep(1)
        # Get stream description
        stream_description = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        table_name = f"table_with_kinesis_stream-{short_uid()}"
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
        dynamodb.delete_table(TableName=table_name)
        kinesis.delete_stream(StreamName=stream_name)

    @markers.aws.only_localstack
    def test_global_tables_version_2019(
        self, aws_client, aws_client_factory, cleanups, dynamodb_wait_for_table_active
    ):
        # Following https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables.tutorial.html

        # Create clients
        dynamodb_us_east_1 = aws_client_factory(region_name="us-east-1").dynamodb
        dynamodb_eu_west_1 = aws_client_factory(region_name="eu-west-1").dynamodb
        dynamodb_ap_south_1 = aws_client_factory(region_name="ap-south-1").dynamodb
        dynamodb_sa_east_1 = aws_client_factory(region_name="sa-east-1").dynamodb

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
            TableName=table_name,
            ReplicaUpdates=[{"Create": {"RegionName": "us-east-1", "KMSMasterKeyId": "foo"}}],
        )
        dynamodb_ap_south_1.update_table(
            TableName=table_name,
            ReplicaUpdates=[{"Create": {"RegionName": "eu-west-1", "KMSMasterKeyId": "bar"}}],
        )

        # Ensure all replicas can be described
        response = dynamodb_ap_south_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 2
        response = dynamodb_us_east_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 2
        assert "bar" in [replica.get("KMSMasterKeyId") for replica in response["Table"]["Replicas"]]
        response = dynamodb_eu_west_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 2
        assert "foo" in [replica.get("KMSMasterKeyId") for replica in response["Table"]["Replicas"]]
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

        # Ensure GetItem in US and EU
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

        # Ensure Scan in US and EU
        scan_us_east = dynamodb_us_east_1.scan(TableName=table_name)
        assert scan_us_east["Items"]
        scan_eu_west = dynamodb_eu_west_1.scan(TableName=table_name)
        assert scan_eu_west["Items"]

        # Ensure Query in US and EU
        query_us_east = dynamodb_us_east_1.query(
            TableName=table_name,
            KeyConditionExpression="Artist = :artist",
            ExpressionAttributeValues={":artist": {"S": "item_1"}},
        )
        assert query_us_east["Items"]
        query_eu_west = dynamodb_eu_west_1.query(
            TableName=table_name,
            KeyConditionExpression="Artist = :artist",
            ExpressionAttributeValues={":artist": {"S": "item_1"}},
        )
        assert query_eu_west["Items"]

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
        assert len(response["Table"]["Replicas"]) == 1
        response = dynamodb_ap_south_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 1

        # Ensure removing the last replica disables global table
        dynamodb_us_east_1.update_table(
            TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": "us-east-1"}}]
        )
        response = dynamodb_ap_south_1.describe_table(TableName=table_name)
        assert len(response["Table"]["Replicas"]) == 0

    @markers.aws.only_localstack
    def test_global_tables(self, aws_client, ddb_test_table):
        dynamodb = aws_client.dynamodb

        # create global table
        regions = [
            {"RegionName": "us-east-1"},
            {"RegionName": "us-west-1"},
            {"RegionName": "eu-central-1"},
        ]
        response = dynamodb.create_global_table(
            GlobalTableName=ddb_test_table, ReplicationGroup=regions
        )["GlobalTableDescription"]
        assert "ReplicationGroup" in response
        assert len(response["ReplicationGroup"]) == len(regions)

        # describe global table
        response = dynamodb.describe_global_table(GlobalTableName=ddb_test_table)[
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
            GlobalTableName=ddb_test_table, ReplicaUpdates=updates
        )["GlobalTableDescription"]
        assert "ReplicationGroup" in response
        assert len(response["ReplicationGroup"]) == len(regions) + 1

        # assert exceptions for invalid requests
        with pytest.raises(Exception) as ctx:
            dynamodb.create_global_table(GlobalTableName=ddb_test_table, ReplicationGroup=regions)
        assert ctx.match("GlobalTableAlreadyExistsException")
        with pytest.raises(Exception) as ctx:
            dynamodb.describe_global_table(GlobalTableName="invalid-table-name")
        assert ctx.match("GlobalTableNotFoundException")

    @markers.aws.validated
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

    @markers.aws.only_localstack(
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

    @markers.aws.validated
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

    @markers.aws.validated
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

    @markers.aws.validated
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

    @markers.aws.validated
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

    @markers.aws.validated
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

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..SizeBytes",
            "$..DeletionProtectionEnabled",
            "$..ProvisionedThroughput.NumberOfDecreasesToday",
            "$..StreamDescription.CreationRequestDateTime",
        ]
    )
    def test_batch_write_items_streaming(
        self,
        dynamodb_create_table_with_parameters,
        wait_for_dynamodb_stream_ready,
        snapshot,
        aws_client,
        dynamodbstreams_snapshot_transformers,
    ):
        # TODO: add a test with both Kinesis and DDBStreams destinations
        table_name = f"test-ddb-table-{short_uid()}"
        create_table = dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )
        snapshot.match("create-table", create_table)
        stream_arn = create_table["TableDescription"]["LatestStreamArn"]
        wait_for_dynamodb_stream_ready(stream_arn=stream_arn)

        describe_stream_result = aws_client.dynamodbstreams.describe_stream(StreamArn=stream_arn)
        snapshot.match("describe-stream", describe_stream_result)

        shard_id = describe_stream_result["StreamDescription"]["Shards"][0]["ShardId"]
        shard_iterator = aws_client.dynamodbstreams.get_shard_iterator(
            StreamArn=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]

        resp = aws_client.dynamodb.put_item(TableName=table_name, Item={"id": {"S": "Fred"}})
        snapshot.match("put-item-1", resp)

        # Overwrite the key, show that no event are sent for this one
        response = aws_client.dynamodb.batch_write_item(
            RequestItems={
                table_name: [
                    {"PutRequest": {"Item": {"id": {"S": "Fred"}}}},
                    {"PutRequest": {"Item": {"id": {"S": "NewKey"}}}},
                ]
            }
        )
        snapshot.match("batch-write-response-overwrite-item-1", response)

        # delete the key
        response = aws_client.dynamodb.batch_write_item(
            RequestItems={
                table_name: [
                    {"DeleteRequest": {"Key": {"id": {"S": "NewKey"}}}},
                    {"PutRequest": {"Item": {"id": {"S": "Fred"}, "name": {"S": "Fred"}}}},
                ]
            }
        )
        snapshot.match("batch-write-response-delete", response)

        # Total amount of records should be 4:
        # - PutItem
        # - BatchWriteItem on NewKey insert
        # - BatchWriteItem on NewKey delete
        # - BatchWriteItem on Fred modify
        # don't send an event when Fred is overwritten with the same value
        # get all records:
        records = []

        def _get_records_amount(record_amount: int):
            nonlocal shard_iterator
            if len(records) < record_amount:
                _resp = aws_client.dynamodbstreams.get_records(ShardIterator=shard_iterator)
                records.extend(_resp["Records"])
                if next_shard_iterator := _resp.get("NextShardIterator"):
                    shard_iterator = next_shard_iterator

            assert len(records) >= record_amount

        retry(lambda: _get_records_amount(4), sleep=1, retries=3)
        snapshot.match("get-records", {"Records": records})

    @pytest.mark.xfail(reason="this test flakes regularly in CI")
    @markers.aws.unknown
    def test_dynamodb_stream_records_with_update_item(
        self, dynamodb_create_table, wait_for_stream_ready, aws_client
    ):
        table_name = f"test-ddb-table-{short_uid()}"

        dynamodb_create_table(
            table_name=table_name,
            partition_key=PARTITION_KEY,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )
        table = aws_client.dynamodb.describe_table(TableName=table_name)
        stream_name = get_kinesis_stream_name(table_name)

        wait_for_stream_ready(stream_name)

        response = aws_client.dynamodbstreams.describe_stream(StreamArn=table["LatestStreamArn"])
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(response["StreamDescription"]["Shards"]) == 1
        shard_id = response["StreamDescription"]["Shards"][0]["ShardId"]
        starting_sequence_number = int(
            response["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber")
        )

        response = aws_client.dynamodbstreams.get_shard_iterator(
            StreamArn=table["LatestStreamArn"],
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

    @markers.aws.only_localstack
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

    @markers.aws.validated
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

    @markers.aws.only_localstack
    def test_dynamodb_create_table_with_sse_specification(
        self, dynamodb_create_table_with_parameters
    ):
        table_name = f"ddb-table-{short_uid()}"

        kms_master_key_id = long_uid()
        sse_specification = {"Enabled": True, "SSEType": "KMS", "KMSMasterKeyId": kms_master_key_id}
        kms_master_key_arn = arns.kms_key_arn(
            kms_master_key_id, account_id=TEST_AWS_ACCOUNT_ID, region_name=TEST_AWS_REGION_NAME
        )

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

    @markers.aws.validated
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

        result = aws_client.dynamodb.update_table(
            TableName=table_name, SSESpecification={"Enabled": False}
        )
        snapshot.match(
            "update-table-disable-sse-spec", result["TableDescription"]["SSEDescription"]
        )

        result = aws_client.dynamodb.describe_table(TableName=table_name)
        assert "SSESpecification" not in result["Table"]

    @markers.aws.validated
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

    @markers.aws.validated
    def test_dynamodb_streams_describe_with_exclusive_start_shard_id(
        self,
        aws_client,
        dynamodb_create_table_with_parameters,
        wait_for_dynamodb_stream_ready,
    ):
        # not using snapshots here as AWS will often return 4 Shards where we return only one
        table_name = f"test-ddb-table-{short_uid()}"
        ddbstreams = aws_client.dynamodbstreams

        create_table = dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": PARTITION_KEY, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": PARTITION_KEY, "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )
        stream_arn = create_table["TableDescription"]["LatestStreamArn"]
        wait_for_dynamodb_stream_ready(stream_arn=stream_arn)

        table = aws_client.dynamodb.describe_table(TableName=table_name)

        response = ddbstreams.describe_stream(StreamArn=table["Table"]["LatestStreamArn"])

        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(response["StreamDescription"]["Shards"]) >= 1
        shard_id = response["StreamDescription"]["Shards"][0]["ShardId"]

        # assert that the excluded shard it not in the response
        response = ddbstreams.describe_stream(
            StreamArn=table["Table"]["LatestStreamArn"], ExclusiveStartShardId=shard_id
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert not any(
            shard_id == shard["ShardId"] for shard in response["StreamDescription"]["Shards"]
        )

    @markers.aws.validated
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

    @markers.aws.validated
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

    @markers.aws.validated
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

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..Error.Message", "$..message"],  # error message is not right
    )
    def test_batch_write_not_existing_table(self, aws_client, snapshot):
        with pytest.raises(ClientError) as e:
            aws_client.dynamodb.transact_write_items(
                TransactItems=[{"Put": {"TableName": "non-existing-table", "Item": {}}}]
            )
        snapshot.match("exc-not-found-transact-write-items", e.value.response)

    @markers.aws.only_localstack
    def test_nosql_workbench_localhost_region(self, dynamodb_create_table, aws_client_factory):
        """
        Test for AWS NoSQL Workbench, which sends "localhost" as region in header.
        LocalStack must assume "us-east-1" region in such cases.
        """
        table_name = f"t-{short_uid()}"

        # Create a table in the `us-east-1` region
        client = aws_client_factory(region_name=AWS_REGION_US_EAST_1).dynamodb
        create_dynamodb_table(table_name, PARTITION_KEY, client=client)
        table = client.describe_table(TableName=table_name)
        assert table.get("Table")

        # Ensure the `localhost` region points to `us-east-1`
        client = aws_client_factory(region_name="localhost").dynamodb
        table = client.describe_table(TableName=table_name)
        assert table.get("Table")

    @markers.aws.validated
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
        if not is_aws_cloud():
            # required for LS because the stream is using kinesis, which needs to be ready
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

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..PointInTimeRecoveryDescription..EarliestRestorableDateTime",
            "$..PointInTimeRecoveryDescription..LatestRestorableDateTime",
        ]
    )
    @markers.aws.validated
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
            except Exception:  # noqa
                return False

        assert poll_condition(
            wait_for_continuous_backend,
            timeout=50 if is_aws_cloud() else 10,
            interval=1 if is_aws_cloud() else 0.5,
        )

        response = aws_client.dynamodb.update_continuous_backups(
            TableName=table_name,
            PointInTimeRecoverySpecification=PointInTimeRecoverySpecification(
                PointInTimeRecoveryEnabled=True
            ),
        )

        snapshot.match("update-continuous-backup", response)

        response = aws_client.dynamodb.describe_continuous_backups(TableName=table_name)
        snapshot.match("describe-continuous-backup", response)

    @markers.aws.validated
    def test_stream_destination_records(
        self,
        aws_client,
        dynamodb_create_table_with_parameters,
        kinesis_create_stream,
        wait_for_stream_ready,
    ):
        table_name = f"table-{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        # get stream arn
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        aws_client.dynamodb.enable_kinesis_streaming_destination(
            TableName=table_name,
            StreamArn=stream_arn,
        )

        def check_destination_status():
            response = aws_client.dynamodb.describe_kinesis_streaming_destination(
                TableName=table_name,
            )
            return response["KinesisDataStreamDestinations"][0]["DestinationStatus"] == "ACTIVE"

        wait = 30 if is_aws_cloud() else 3
        max_retries = 10 if is_aws_cloud() else 2
        wait_until(check_destination_status(), wait=wait, max_retries=max_retries)

        iterator = get_shard_iterator(stream_name, aws_client.kinesis)

        def assert_records():
            # put item could not trigger the event at the beginning so it's best to try to put it again
            aws_client.dynamodb.put_item(
                TableName=table_name,
                Item={
                    PARTITION_KEY: {"S": f"id{short_uid()}"},
                    "version": {"N": "1"},
                    "data": {"B": b"\x90"},
                },
            )

            # get stream records
            response = aws_client.kinesis.get_records(
                ShardIterator=iterator,
            )
            records = response["Records"]
            assert len(records) > 0

        sleep_secs = 2
        retries = 10
        if is_aws_cloud():
            sleep_secs = 5
            retries = 30

        retry(
            assert_records,
            retries=retries,
            sleep=sleep_secs,
            sleep_before=2,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..message"])
    def test_return_values_on_conditions_check_failure(
        self, dynamodb_create_table_with_parameters, snapshot, aws_client
    ):
        table_name = f"table-{short_uid()}"
        dynamodb_create_table_with_parameters(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        item = {
            PARTITION_KEY: {"S": "456"},
            "price": {"N": "650"},
            "product": {"S": "sporting goods"},
        }
        aws_client.dynamodb.put_item(TableName=table_name, Item=item)
        try:
            aws_client.dynamodb.delete_item(
                TableName=table_name,
                Key={PARTITION_KEY: {"S": "456"}},
                ConditionExpression="price between :lo and :hi",
                ExpressionAttributeValues={":lo": {"N": "500"}, ":hi": {"N": "600"}},
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
            )
        except botocore.exceptions.ClientError as error:
            snapshot.match("items", error.response)  # noqa
