import json
import re

import aws_cdk as cdk
import pytest

from localstack import config
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import resources
from localstack.utils.aws.arns import kinesis_stream_arn
from localstack.utils.aws.queries import kinesis_get_latest_records
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

# default partition key used for test tables
PARTITION_KEY = "id"


class TestDynamoDBStreams:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Table.ProvisionedThroughput.LastDecreaseDateTime",
            "$..Table.ProvisionedThroughput.LastIncreaseDateTime",
            "$..Table.Replicas",
        ]
    )
    def test_table_v2_stream(self, aws_client, infrastructure_setup, snapshot):
        snapshot.add_transformer(snapshot.transform.dynamodb_streams_api())
        snapshot.add_transformer(snapshot.transform.key_value("LatestStreamArn"), priority=-1)
        snapshot.add_transformer(snapshot.transform.key_value("TableArn"), priority=-1)

        infra = infrastructure_setup(namespace="TestTableV2Stream")
        stack = cdk.Stack(infra.cdk_app, "TableV2StreamStack")

        table = cdk.aws_dynamodb.TableV2(
            stack,
            "v2table",
            partition_key=cdk.aws_dynamodb.Attribute(
                name=PARTITION_KEY, type=cdk.aws_dynamodb.AttributeType.STRING
            ),
            removal_policy=cdk.RemovalPolicy.DESTROY,
            dynamo_stream=cdk.aws_dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        )

        cdk.CfnOutput(stack, "tableName", value=table.table_name)

        with infra.provisioner(skip_teardown=False) as prov:
            table_name = prov.get_stack_outputs(stack_name="TableV2StreamStack")["tableName"]
            response = aws_client.dynamodb.describe_table(TableName=table_name)
            snapshot.match("global-table-v2", response)

    @markers.aws.only_localstack
    def test_stream_spec_and_region_replacement(self, aws_client, region_name):
        # our V1 and V2 implementation are pretty different, and we need different ways to test it
        ddbstreams = aws_client.dynamodbstreams
        table_name = f"ddb-{short_uid()}"
        resources.create_dynamodb_table(
            table_name,
            partition_key=PARTITION_KEY,
            stream_view_type="NEW_AND_OLD_IMAGES",
            client=aws_client.dynamodb,
        )

        table = aws_client.dynamodb.describe_table(TableName=table_name)["Table"]

        # assert ARN formats
        expected_arn_prefix = f"arn:aws:dynamodb:{region_name}"
        assert table["TableArn"].startswith(expected_arn_prefix)
        assert table["LatestStreamArn"].startswith(expected_arn_prefix)

        # test list_streams filtering
        stream_tables = ddbstreams.list_streams(TableName="foo")["Streams"]
        assert len(stream_tables) == 0

        if not config.DDB_STREAMS_PROVIDER_V2:
            from localstack.services.dynamodbstreams.dynamodbstreams_api import (
                get_kinesis_stream_name,
            )

            stream_name = get_kinesis_stream_name(table_name)
            assert stream_name in aws_client.kinesis.list_streams()["StreamNames"]

        # assert stream has been created
        stream_tables = [
            s["TableName"] for s in ddbstreams.list_streams(TableName=table_name)["Streams"]
        ]
        assert table_name in stream_tables
        assert len(stream_tables) == 1

        # assert shard ID formats
        result = ddbstreams.describe_stream(StreamArn=table["LatestStreamArn"])["StreamDescription"]
        assert "Shards" in result
        for shard in result["Shards"]:
            assert re.match(r"^shardId-[0-9]{20}-[a-zA-Z0-9]{1,36}$", shard["ShardId"])

        # clean up
        aws_client.dynamodb.delete_table(TableName=table_name)

        def _assert_stream_disabled():
            if config.DDB_STREAMS_PROVIDER_V2:
                _result = aws_client.dynamodbstreams.describe_stream(
                    StreamArn=table["LatestStreamArn"]
                )
                assert _result["StreamDescription"]["StreamStatus"] == "DISABLED"
            else:
                _stream_tables = [s["TableName"] for s in ddbstreams.list_streams()["Streams"]]
                assert table_name not in _stream_tables
                assert stream_name not in aws_client.kinesis.list_streams()["StreamNames"]

        # assert stream has been deleted
        retry(_assert_stream_disabled, sleep=1, retries=20)

    @pytest.mark.skipif(
        condition=not is_aws_cloud() or config.DDB_STREAMS_PROVIDER_V2,
        reason="Flaky, and not implemented yet on v2 implementation",
    )
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..EncryptionType", "$..SizeBytes"])
    def test_enable_kinesis_streaming_destination(
        self,
        aws_client,
        dynamodb_create_table,
        kinesis_create_stream,
        wait_for_stream_ready,
        account_id,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("SequenceNumber"))
        snapshot.add_transformer(snapshot.transform.key_value("PartitionKey"))
        snapshot.add_transformer(
            snapshot.transform.key_value("ApproximateArrivalTimestamp", reference_replacement=False)
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("ApproximateCreationDateTime", reference_replacement=False)
        )
        snapshot.add_transformer(snapshot.transform.key_value("eventID"))
        snapshot.add_transformer(snapshot.transform.key_value("tableName"))

        dynamodb = aws_client.dynamodb
        kinesis = aws_client.kinesis

        # create DDB table and Kinesis stream
        table = dynamodb_create_table()
        table_name = table["TableDescription"]["TableName"]
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)
        stream_arn = kinesis_stream_arn(
            stream_name, account_id, region_name=kinesis.meta.region_name
        )
        stream_details = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        shards = stream_details["Shards"]
        assert len(shards) == 1

        # enable kinesis streaming destination
        dynamodb.enable_kinesis_streaming_destination(TableName=table_name, StreamArn=stream_arn)

        def _stream_active():
            details = dynamodb.describe_kinesis_streaming_destination(TableName=table_name)
            destinations = details["KinesisDataStreamDestinations"]
            assert len(destinations) == 1
            assert destinations[0]["DestinationStatus"] == "ACTIVE"
            return destinations[0]

        # wait until stream is active
        retry(_stream_active, sleep=10 if is_aws_cloud() else 0.7, retries=10)

        # write item to table
        updates = [{"Put": {"Item": {PARTITION_KEY: {"S": "test"}}, "TableName": table_name}}]
        dynamodb.transact_write_items(TransactItems=updates)

        def _receive_records():
            _records = kinesis_get_latest_records(stream_name, shards[0]["ShardId"], client=kinesis)
            assert _records
            return _records

        # assert that record has been received in the stream
        records = retry(_receive_records, sleep=0.7, retries=15)

        for record in records:
            record["Data"] = json.loads(record["Data"])

        # assert that the PartitionKey is a Hex string looking like an MD5 hash
        assert len(records[0]["PartitionKey"]) == 32
        assert int(records[0]["PartitionKey"], 16)
        snapshot.match("result-records", records)
