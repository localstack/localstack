import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack import config
from localstack.testing.pytest import markers
from localstack.utils.aws import resources
from localstack.utils.common import short_uid

from .test_integration import PARTITION_KEY


class TestErrorInjection:
    @markers.aws.only_localstack
    def test_kinesis_error_injection(
        self, monkeypatch, wait_for_stream_ready, aws_client, aws_client_factory
    ):
        kinesis = aws_client_factory(config=self.retry_config()).kinesis
        stream_name = f"stream-{short_uid()}"
        resources.create_kinesis_stream(kinesis, stream_name)
        wait_for_stream_ready(stream_name)

        try:
            records = [{"Data": "0", "ExplicitHashKey": "0", "PartitionKey": "0"}]

            # by default, no errors
            test_no_errors = kinesis.put_records(StreamName=stream_name, Records=records)
            assert test_no_errors["FailedRecordCount"] == 0

            # with a probability of 1, always throw errors
            monkeypatch.setattr(config, "KINESIS_ERROR_PROBABILITY", 1.0)
            test_all_errors = kinesis.put_records(StreamName=stream_name, Records=records)
            assert test_all_errors["FailedRecordCount"] == 1
        finally:
            aws_client.kinesis.delete_stream(StreamName=stream_name)

    @markers.aws.only_localstack
    def test_dynamodb_error_injection(self, monkeypatch, aws_client, dynamodb_create_table):
        table_name = dynamodb_create_table()["TableDescription"]["TableName"]

        partition_key = short_uid()
        self.assert_zero_probability_read_error_injection(
            aws_client.dynamodb, table_name, partition_key
        )

        # with a probability of 1, always throw errors
        monkeypatch.setattr(config, "DYNAMODB_ERROR_PROBABILITY", 1.0)
        with pytest.raises(ClientError) as exc:
            aws_client.dynamodb.get_item(
                TableName=table_name, Key={PARTITION_KEY: {"S": partition_key}}
            )
        exc.match("ProvisionedThroughputExceededException")

    @markers.aws.only_localstack
    def test_dynamodb_read_error_injection(self, monkeypatch, aws_client, dynamodb_create_table):
        table_name = dynamodb_create_table()["TableDescription"]["TableName"]

        partition_key = short_uid()
        self.assert_zero_probability_read_error_injection(
            aws_client.dynamodb, table_name, partition_key
        )

        # with a probability of 1, always throw errors
        monkeypatch.setattr(config, "DYNAMODB_READ_ERROR_PROBABILITY", 1.0)
        with pytest.raises(ClientError) as exc:
            aws_client.dynamodb.get_item(
                TableName=table_name, Key={PARTITION_KEY: {"S": partition_key}}
            )
        exc.match("ProvisionedThroughputExceededException")

    @markers.aws.only_localstack
    def test_dynamodb_write_error_injection(self, monkeypatch, aws_client, dynamodb_create_table):
        table_name = dynamodb_create_table()["TableDescription"]["TableName"]

        # by default, no errors
        test_no_errors = aws_client.dynamodb.put_item(
            TableName=table_name,
            Item={PARTITION_KEY: {"S": short_uid()}, "data": {"S": "foobar123"}},
        )
        assert test_no_errors["ResponseMetadata"]["HTTPStatusCode"] == 200

        # with a probability of 1, always throw errors
        monkeypatch.setattr(config, "DYNAMODB_WRITE_ERROR_PROBABILITY", 1.0)
        with pytest.raises(ClientError) as exc:
            aws_client.dynamodb.put_item(
                TableName=table_name,
                Item={PARTITION_KEY: {"S": short_uid()}, "data": {"S": "foobar123"}},
            )
        exc.match("ProvisionedThroughputExceededException")

        # BatchWriteItem throws ProvisionedThroughputExceededException if ALL items in Batch are Throttled
        with pytest.raises(ClientError) as exc:
            for _ in range(3):
                aws_client.dynamodb.put_item(
                    TableName=table_name,
                    Item={
                        PARTITION_KEY: {"S": short_uid()},
                        "data": {"S": "foobar123"},
                    },
                )
        exc.match("ProvisionedThroughputExceededException")

    def retry_config(self):
        # set max_attempts=1 to speed up the test execution
        return Config(retries={"max_attempts": 1})

    @staticmethod
    def assert_zero_probability_read_error_injection(dynamodb_client, table_name, partition_key):
        # by default, no errors
        test_no_errors = dynamodb_client.get_item(
            TableName=table_name, Key={PARTITION_KEY: {"S": partition_key}}
        )
        assert test_no_errors["ResponseMetadata"]["HTTPStatusCode"] == 200
