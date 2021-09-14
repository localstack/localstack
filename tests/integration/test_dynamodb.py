# -*- coding: utf-8 -*-
import json
import os
import unittest
from datetime import datetime
from time import sleep

from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import STRING

from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.services.dynamodbstreams.dynamodbstreams_api import get_kinesis_stream_name
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import KinesisStream
from localstack.utils.aws.aws_stack import get_environment
from localstack.utils.common import json_safe, retry, short_uid
from localstack.utils.testutil import check_expected_lambda_log_events_length

PARTITION_KEY = "id"

TEST_DDB_TABLE_NAME = "test-ddb-table-1"
TEST_DDB_TABLE_NAME_2 = "test-ddb-table-2"
TEST_DDB_TABLE_NAME_3 = "test-ddb-table-3"

TEST_DDB_TAGS = [
    {"Key": "Name", "Value": "test-table"},
    {"Key": "TestKey", "Value": "true"},
]

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_ECHO_FILE = os.path.join(THIS_FOLDER, "lambdas", "lambda_echo.py")


class TestDynamoDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dynamodb = aws_stack.connect_to_resource("dynamodb")

    def test_non_ascii_chars(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME)

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
            self.assertEqual(item1, item2)

        # clean up
        delete_table(TEST_DDB_TABLE_NAME)

    def test_large_data_download(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME_2, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME_2)

        # Create a large amount of items
        num_items = 20
        for i in range(0, num_items):
            item = {PARTITION_KEY: "id%s" % i, "data1": "foobar123 " * 1000}
            table.put_item(Item=item)

        # Retrieve the items. The data will be transmitted to the client with chunked transfer encoding
        result = table.scan(TableName=TEST_DDB_TABLE_NAME_2)
        self.assertEqual(num_items, len(result["Items"]))

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_2)

    def test_time_to_live(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME_3, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME_3)

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
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"],
            "DISABLED",
        )

        # Enable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, True)
        self.assertEqual(200, response.status_code)
        self.assertTrue(json.loads(response._content)["TimeToLiveSpecification"]["Enabled"])

        # Describe TTL status after being enabled.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"],
            "ENABLED",
        )

        # Disable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, False)
        self.assertEqual(200, response.status_code)
        self.assertFalse(json.loads(response._content)["TimeToLiveSpecification"]["Enabled"])

        # Describe TTL status after being disabled.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"],
            "DISABLED",
        )

        # Enable TTL for given table again
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, True)
        self.assertEqual(200, response.status_code)
        self.assertTrue(json.loads(response._content)["TimeToLiveSpecification"]["Enabled"])

        # Describe TTL status after being enabled again.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            json.loads(response._content)["TimeToLiveDescription"]["TimeToLiveStatus"],
            "ENABLED",
        )

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_3)

    def test_list_tags_of_resource(self):
        table_name = "ddb-table-%s" % short_uid()
        dynamodb = aws_stack.connect_to_service("dynamodb")

        rs = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )
        table_arn = rs["TableDescription"]["TableArn"]

        rs = dynamodb.list_tags_of_resource(ResourceArn=table_arn)

        self.assertEqual(TEST_DDB_TAGS, rs["Tags"])

        dynamodb.tag_resource(ResourceArn=table_arn, Tags=[{"Key": "NewKey", "Value": "TestValue"}])

        rs = dynamodb.list_tags_of_resource(ResourceArn=table_arn)

        self.assertEqual(len(TEST_DDB_TAGS) + 1, len(rs["Tags"]))

        tags = {tag["Key"]: tag["Value"] for tag in rs["Tags"]}
        self.assertIn("NewKey", tags.keys())
        self.assertEqual("TestValue", tags["NewKey"])

        dynamodb.untag_resource(ResourceArn=table_arn, TagKeys=["Name", "NewKey"])

        rs = dynamodb.list_tags_of_resource(ResourceArn=table_arn)
        tags = {tag["Key"]: tag["Value"] for tag in rs["Tags"]}
        self.assertNotIn("Name", tags.keys())
        self.assertNotIn("NewKey", tags.keys())

        delete_table(table_name)

    def test_stream_spec_and_region_replacement(self):
        ddbstreams = aws_stack.connect_to_service("dynamodbstreams")
        kinesis = aws_stack.connect_to_service("kinesis")
        table_name = "ddb-%s" % short_uid()
        aws_stack.create_dynamodb_table(
            table_name,
            partition_key=PARTITION_KEY,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )

        table = self.dynamodb.Table(table_name)

        # assert ARN formats
        expected_arn_prefix = "arn:aws:dynamodb:" + aws_stack.get_local_region()
        self.assertTrue(table.table_arn.startswith(expected_arn_prefix))
        self.assertTrue(table.latest_stream_arn.startswith(expected_arn_prefix))

        # assert stream has been created
        stream_tables = [s["TableName"] for s in ddbstreams.list_streams()["Streams"]]
        self.assertIn(table_name, stream_tables)
        stream_name = get_kinesis_stream_name(table_name)
        self.assertIn(stream_name, kinesis.list_streams()["StreamNames"])

        # assert shard ID formats
        result = ddbstreams.describe_stream(StreamArn=table.latest_stream_arn)["StreamDescription"]
        self.assertIn("Shards", result)
        for shard in result["Shards"]:
            self.assertRegex(shard["ShardId"], r"^shardId\-[0-9]{20}\-[a-zA-Z0-9]{1,36}$")

        # clean up
        delete_table(table_name)
        # assert stream has been deleted
        stream_tables = [s["TableName"] for s in ddbstreams.list_streams()["Streams"]]
        self.assertNotIn(table_name, stream_tables)
        self.assertNotIn(stream_name, kinesis.list_streams()["StreamNames"])

    def test_multiple_update_expressions(self):
        dynamodb = aws_stack.connect_to_service("dynamodb")
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME)

        item_id = short_uid()
        table.put_item(Item={PARTITION_KEY: item_id, "data": "foobar123 ✓"})
        response = dynamodb.update_item(
            TableName=TEST_DDB_TABLE_NAME,
            Key={PARTITION_KEY: {"S": item_id}},
            UpdateExpression="SET attr1 = :v1, attr2 = :v2",
            ExpressionAttributeValues={":v1": {"S": "value1"}, ":v2": {"S": "value2"}},
        )
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        item = table.get_item(Key={PARTITION_KEY: item_id})["Item"]
        self.assertEqual(item["attr1"], "value1")
        self.assertEqual(item["attr2"], "value2")
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

        with self.assertRaises(Exception) as ctx:
            table.query(
                TableName=TEST_DDB_TABLE_NAME,
                IndexName="id-index",
                KeyConditionExpression=Key(PARTITION_KEY).eq(item_id),
                Select="ALL_ATTRIBUTES",
            )
        self.assertIn("ValidationException", str(ctx.exception))

    def test_return_values_in_put_item(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME)

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: "id1", "data": "foobar"}
        item2 = {PARTITION_KEY: "id2", "data": "foobar"}

        response = table.put_item(Item=item1, ReturnValues="ALL_OLD")
        # there is no data present in the table already so even if return values
        # is set to 'ALL_OLD' as there is no data it will not return any data.
        self.assertFalse(response.get("Attributes"))
        # now the same data is present so when we pass return values as 'ALL_OLD'
        # it should give us attributes
        response = table.put_item(Item=item1, ReturnValues="ALL_OLD")
        self.assertTrue(response.get("Attributes"))
        self.assertEqual(item1.get("id"), response.get("Attributes").get("id"))
        self.assertEqual(item1.get("data"), response.get("Attributes").get("data"))

        response = table.put_item(Item=item2)
        # we do not have any same item as item2 already so when we add this by default
        # return values is set to None so no Attribute values should be returned
        self.assertFalse(response.get("Attributes"))

        response = table.put_item(Item=item2)
        # in this case we already have item2 in the table so on this request
        # it should not return any data as return values is set to None so no
        # Attribute values should be returned
        self.assertFalse(response.get("Attributes"))

    def test_empty_and_binary_values(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME)

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: "id1", "data": ""}
        item2 = {PARTITION_KEY: "id2", "data": b"foobar"}

        response = table.put_item(Item=item1)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        response = table.put_item(Item=item2)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

    def test_dynamodb_stream_shard_iterator(self):
        def wait_for_stream_created(table_name):
            stream_name = get_kinesis_stream_name(table_name)
            stream = KinesisStream(id=stream_name, num_shards=1)
            kinesis = aws_stack.connect_to_service("kinesis", env=get_environment(None))
            stream.connect(kinesis)
            stream.wait_for()

        dynamodb = aws_stack.connect_to_service("dynamodb")
        ddbstreams = aws_stack.connect_to_service("dynamodbstreams")

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
        self.assertIn("ShardIterator", response)
        response = ddbstreams.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["StreamDescription"]["Shards"][0]["ShardId"],
            ShardIteratorType="AT_SEQUENCE_NUMBER",
            SequenceNumber=result["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber"),
        )
        self.assertIn("ShardIterator", response)

    def test_dynamodb_stream_stream_view_type(self):
        dynamodb = aws_stack.connect_to_service("dynamodb")
        ddbstreams = aws_stack.connect_to_service("dynamodbstreams")
        table_name = "table_with_stream-%s" % short_uid()
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
        # put item in table - Insert event
        dynamodb.put_item(TableName=table_name, Item={"Username": {"S": "Fred"}})
        # update item in table - Modify event
        dynamodb.update_item(
            TableName=table_name,
            Key={"Username": {"S": "Fred"}},
            UpdateExpression="set S=:r",
            ExpressionAttributeValues={":r": {"S": "Fred_Modified"}},
            ReturnValues="UPDATED_NEW",
        )
        # delete item in table - Delete event
        dynamodb.delete_item(TableName=table_name, Key={"Username": {"S": "Fred"}})
        result = ddbstreams.describe_stream(StreamArn=stream_arn)
        # assert stream_view_type of the table
        self.assertEqual("KEYS_ONLY", result["StreamDescription"]["StreamViewType"])

        # get shard iterator
        response = ddbstreams.get_shard_iterator(
            StreamArn=stream_arn,
            ShardId=result["StreamDescription"]["Shards"][0]["ShardId"],
            ShardIteratorType="AT_SEQUENCE_NUMBER",
            SequenceNumber=result["StreamDescription"]["Shards"][0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber"),
        )

        # get records
        record = ddbstreams.get_records(ShardIterator=response["ShardIterator"])

        # assert stream_view_type of records forwarded to the stream
        self.assertEqual("KEYS_ONLY", record["Records"][0]["dynamodb"]["StreamViewType"])
        self.assertEqual("KEYS_ONLY", record["Records"][1]["dynamodb"]["StreamViewType"])
        self.assertEqual("KEYS_ONLY", record["Records"][2]["dynamodb"]["StreamViewType"])
        # assert Keys present in the record for all insert, modify and delete events
        self.assertEqual({"Username": {"S": "Fred"}}, record["Records"][0]["dynamodb"]["Keys"])
        self.assertEqual({"Username": {"S": "Fred"}}, record["Records"][1]["dynamodb"]["Keys"])
        self.assertEqual({"Username": {"S": "Fred"}}, record["Records"][2]["dynamodb"]["Keys"])
        # assert oldImage not in the records
        self.assertNotIn("OldImage", record["Records"][0]["dynamodb"])
        self.assertNotIn("OldImage", record["Records"][1]["dynamodb"])
        self.assertNotIn("OldImage", record["Records"][2]["dynamodb"])
        # assert newImage not in the record
        self.assertNotIn("NewImage", record["Records"][0]["dynamodb"])
        self.assertNotIn("NewImage", record["Records"][1]["dynamodb"])
        self.assertNotIn("NewImage", record["Records"][2]["dynamodb"])

        # clean up
        delete_table(table_name)

    def test_dynamodb_with_kinesis_stream(self):
        dynamodb = aws_stack.connect_to_service("dynamodb")
        kinesis = aws_stack.connect_to_service("kinesis")

        # create kinesis datastream
        kinesis.create_stream(StreamName="kinesis_dest_stream", ShardCount=1)
        # wait for the stream to be created
        sleep(1)
        # Get stream description
        stream_description = kinesis.describe_stream(StreamName="kinesis_dest_stream")[
            "StreamDescription"
        ]
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

        # get shard iterator of the stream
        shard_iterator = kinesis.get_shard_iterator(
            StreamName="kinesis_dest_stream",
            ShardId=stream_description["Shards"][0]["ShardId"],
            ShardIteratorType="TRIM_HORIZON",
        )["ShardIterator"]

        # get records from the stream
        rec = kinesis.get_records(ShardIterator=shard_iterator)["Records"]
        # assert records in stream
        self.assertEqual(1, len(rec))

        # check tableName exists in the stream record
        record_data = json.loads(rec[0]["Data"])
        self.assertEqual(record_data["tableName"], table_name)
        # check eventSourceARN not exists in the stream record
        self.assertNotIn("eventSourceARN", record_data)
        # describe kinesis streaming destination of the table
        describe = dynamodb.describe_kinesis_streaming_destination(TableName=table_name)[
            "KinesisDataStreamDestinations"
        ][0]

        # assert kinesis streaming destination status
        self.assertEqual(stream_description["StreamARN"], describe["StreamArn"])
        self.assertEqual("ACTIVE", describe["DestinationStatus"])

        # Disable kinesis destination
        dynamodb.disable_kinesis_streaming_destination(
            TableName=table_name, StreamArn=stream_description["StreamARN"]
        )

        # describe kinesis streaming destination of the table
        describe = dynamodb.describe_kinesis_streaming_destination(TableName=table_name)[
            "KinesisDataStreamDestinations"
        ][0]

        # assert kinesis streaming destination status
        self.assertEqual(stream_description["StreamARN"], describe["StreamArn"])
        self.assertEqual("DISABLED", describe["DestinationStatus"])

        # clean up
        delete_table(table_name)
        kinesis.delete_stream(StreamName="kinesis_dest_stream")

    def test_global_tables(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        dynamodb = aws_stack.connect_to_service("dynamodb")

        # create global table
        regions = [
            {"RegionName": "us-east-1"},
            {"RegionName": "us-west-1"},
            {"RegionName": "eu-central-1"},
        ]
        response = dynamodb.create_global_table(
            GlobalTableName=TEST_DDB_TABLE_NAME, ReplicationGroup=regions
        )["GlobalTableDescription"]
        self.assertIn("ReplicationGroup", response)
        self.assertEqual(len(regions), len(response["ReplicationGroup"]))

        # describe global table
        response = dynamodb.describe_global_table(GlobalTableName=TEST_DDB_TABLE_NAME)[
            "GlobalTableDescription"
        ]
        self.assertIn("ReplicationGroup", response)
        self.assertEqual(len(regions), len(response["ReplicationGroup"]))

        # update global table
        updates = [
            {"Create": {"RegionName": "us-east-2"}},
            {"Create": {"RegionName": "us-west-2"}},
            {"Delete": {"RegionName": "us-west-1"}},
        ]
        response = dynamodb.update_global_table(
            GlobalTableName=TEST_DDB_TABLE_NAME, ReplicaUpdates=updates
        )["GlobalTableDescription"]
        self.assertIn("ReplicationGroup", response)
        self.assertEqual(len(regions) + 1, len(response["ReplicationGroup"]))

        # assert exceptions for invalid requests
        with self.assertRaises(Exception) as ctx:
            dynamodb.create_global_table(
                GlobalTableName=TEST_DDB_TABLE_NAME, ReplicationGroup=regions
            )
        self.assertIn("GlobalTableAlreadyExistsException", str(ctx.exception))
        with self.assertRaises(Exception) as ctx:
            dynamodb.describe_global_table(GlobalTableName="invalid-table-name")
        self.assertIn("GlobalTableNotFoundException", str(ctx.exception))

    def test_create_duplicate_table(self):
        table_name = "duplicateTable"
        dynamodb = aws_stack.connect_to_service("dynamodb")

        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            Tags=TEST_DDB_TAGS,
        )

        with self.assertRaises(Exception) as ctx:
            dynamodb.create_table(
                TableName=table_name,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                Tags=TEST_DDB_TAGS,
            )
        self.assertIn("ResourceInUseException", str(ctx.exception))

        # clean up
        delete_table(table_name)

    def test_delete_table(self):
        table_name = "test-ddb-table-%s" % short_uid()
        dynamodb = aws_stack.connect_to_service("dynamodb")

        tables_before = len(dynamodb.list_tables()["TableNames"])

        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )

        table_list = dynamodb.list_tables()
        self.assertEqual(tables_before + 1, len(table_list["TableNames"]))
        self.assertEqual(table_name, table_list["TableNames"][-1])

        dynamodb.delete_table(TableName=table_name)

        table_list = dynamodb.list_tables()
        self.assertEqual(tables_before, len(table_list["TableNames"]))

        with self.assertRaises(Exception) as ctx:
            dynamodb.delete_table(TableName=table_name)
        self.assertIn("ResourceNotFoundException", str(ctx.exception))

    def test_transaction_write_items(self):
        table_name = "test-ddb-table-%s" % short_uid()
        dynamodb = aws_stack.connect_to_service("dynamodb")

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

        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        # clean up
        dynamodb.delete_table(TableName=table_name)

    def test_batch_write_items(self):
        table_name = "test-ddb-table-%s" % short_uid()
        dynamodb = aws_stack.connect_to_service("dynamodb")
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
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        # clean up
        dynamodb.delete_table(TableName=table_name)

    def test_dynamodb_stream_records_with_update_item(self):
        table_name = "test-ddb-table-%s" % short_uid()
        dynamodb = aws_stack.connect_to_service("dynamodb")
        ddbstreams = aws_stack.connect_to_service("dynamodbstreams")

        aws_stack.create_dynamodb_table(
            table_name,
            partition_key=PARTITION_KEY,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )
        table = self.dynamodb.Table(table_name)

        response = ddbstreams.describe_stream(StreamArn=table.latest_stream_arn)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(1, len(response["StreamDescription"]["Shards"]))
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
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        self.assertIn("ShardIterator", response)
        iterator_id = response["ShardIterator"]

        item_id = short_uid()
        for _ in range(2):
            dynamodb.update_item(
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

        records = ddbstreams.get_records(ShardIterator=iterator_id)
        self.assertEqual(200, records["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(2, len(records["Records"]))
        self.assertTrue(
            isinstance(
                records["Records"][0]["dynamodb"]["ApproximateCreationDateTime"],
                datetime,
            )
        )
        self.assertEqual("1.1", records["Records"][0]["eventVersion"])
        self.assertEqual("INSERT", records["Records"][0]["eventName"])
        self.assertNotIn("OldImage", records["Records"][0]["dynamodb"])
        self.assertGreater(
            int(records["Records"][0]["dynamodb"]["SequenceNumber"]),
            starting_sequence_number,
        )
        self.assertTrue(
            isinstance(
                records["Records"][1]["dynamodb"]["ApproximateCreationDateTime"],
                datetime,
            )
        )
        self.assertEqual("1.1", records["Records"][1]["eventVersion"])
        self.assertEqual("MODIFY", records["Records"][1]["eventName"])
        self.assertIn("OldImage", records["Records"][1]["dynamodb"])
        self.assertGreater(
            int(records["Records"][1]["dynamodb"]["SequenceNumber"]),
            starting_sequence_number,
        )

        dynamodb.delete_table(TableName=table_name)

    def test_query_on_deleted_resource(self):
        table_name = "ddb-table-%s" % short_uid()
        partition_key = "username"

        dynamodb = aws_stack.connect_to_service("dynamodb")
        aws_stack.create_dynamodb_table(table_name, partition_key)

        rs = dynamodb.query(
            TableName=table_name,
            KeyConditionExpression="{} = :username".format(partition_key),
            ExpressionAttributeValues={":username": {"S": "test"}},
        )
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        dynamodb.delete_table(TableName=table_name)

        with self.assertRaises(Exception) as ctx:
            dynamodb.query(
                TableName=table_name,
                KeyConditionExpression="{} = :username".format(partition_key),
                ExpressionAttributeValues={":username": {"S": "test"}},
            )

        self.assertIn("ResourceNotFoundException", str(ctx.exception))

    def test_dynamodb_stream_to_lambda(self):
        table_name = "ddb-table-%s" % short_uid()
        function_name = "func-%s" % short_uid()
        partition_key = "SK"

        aws_stack.create_dynamodb_table(
            table_name=table_name,
            partition_key=partition_key,
            stream_view_type="NEW_AND_OLD_IMAGES",
        )
        table = self.dynamodb.Table(table_name)
        latest_stream_arn = table.latest_stream_arn

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        lambda_client = aws_stack.connect_to_service("lambda")
        lambda_client.create_event_source_mapping(
            EventSourceArn=latest_stream_arn, FunctionName=function_name
        )

        item = {"SK": short_uid(), "Name": "name-{}".format(short_uid())}

        table.put_item(Item=item)

        events = retry(
            check_expected_lambda_log_events_length,
            retries=3,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            regex_filter=r"Records",
        )

        self.assertEqual(1, len(events))
        self.assertEqual(1, len(events[0]["Records"]))

        dynamodb_event = events[0]["Records"][0]["dynamodb"]
        self.assertEqual("NEW_AND_OLD_IMAGES", dynamodb_event["StreamViewType"])
        self.assertEqual({"SK": {"S": item["SK"]}}, dynamodb_event["Keys"])
        self.assertEqual({"S": item["Name"]}, dynamodb_event["NewImage"]["Name"])

        dynamodb = aws_stack.connect_to_service("dynamodb")
        dynamodb.delete_table(TableName=table_name)

    def test_dynamodb_batch_write_item(self):
        dynamodb = aws_stack.connect_to_service("dynamodb")
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

        self.assertEqual({}, result.get("UnprocessedItems"))


def delete_table(name):
    dynamodb_client = aws_stack.connect_to_service("dynamodb")
    dynamodb_client.delete_table(TableName=name)
