import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack import config
from localstack.utils.aws import aws_stack, resources
from localstack.utils.common import short_uid

from .test_integration import PARTITION_KEY


class TestErrorInjection:
    @pytest.mark.only_localstack
    def test_kinesis_error_injection(self, monkeypatch, kinesis_client, wait_for_stream_ready):
        kinesis = aws_stack.create_external_boto_client("kinesis", config=self.retry_config())
        stream_name = f"stream-{short_uid()}"
        resources.create_kinesis_stream(stream_name)
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
            kinesis_client.delete_stream(StreamName=stream_name)

    @pytest.mark.only_localstack
    def test_dynamodb_error_injection(self, monkeypatch):
        table = self.get_dynamodb_table()

        try:
            partition_key = short_uid()
            self.assert_zero_probability_read_error_injection(table, partition_key)

            # with a probability of 1, always throw errors
            monkeypatch.setattr(config, "DYNAMODB_ERROR_PROBABILITY", 1.0)
            with pytest.raises(ClientError) as exc:
                table.get_item(Key={PARTITION_KEY: partition_key})
            exc.match("ProvisionedThroughputExceededException")
        finally:
            table.delete()

    @pytest.mark.only_localstack
    def test_dynamodb_read_error_injection(self, monkeypatch):
        table = self.get_dynamodb_table()

        try:
            partition_key = short_uid()
            self.assert_zero_probability_read_error_injection(table, partition_key)

            # with a probability of 1, always throw errors
            monkeypatch.setattr(config, "DYNAMODB_READ_ERROR_PROBABILITY", 1.0)
            with pytest.raises(ClientError) as exc:
                table.get_item(Key={PARTITION_KEY: partition_key})
            exc.match("ProvisionedThroughputExceededException")
        finally:
            table.delete()

    @pytest.mark.only_localstack
    def test_dynamodb_write_error_injection(self, monkeypatch):
        table = self.get_dynamodb_table()

        try:
            # by default, no errors
            test_no_errors = table.put_item(Item={PARTITION_KEY: short_uid(), "data": "foobar123"})
            assert test_no_errors["ResponseMetadata"]["HTTPStatusCode"] == 200

            # with a probability of 1, always throw errors
            monkeypatch.setattr(config, "DYNAMODB_WRITE_ERROR_PROBABILITY", 1.0)
            with pytest.raises(ClientError) as exc:
                table.put_item(Item={PARTITION_KEY: short_uid(), "data": "foobar123"})
            exc.match("ProvisionedThroughputExceededException")

            # BatchWriteItem throws ProvisionedThroughputExceededException if ALL items in Batch are Throttled
            with pytest.raises(ClientError) as exc:
                with table.batch_writer() as batch:
                    for _ in range(3):
                        batch.put_item(
                            Item={
                                PARTITION_KEY: short_uid(),
                                "data": "foobar123",
                            }
                        )
            exc.match("ProvisionedThroughputExceededException")
        finally:
            table.delete()

    def get_dynamodb_table(self):
        # set max_attempts=1 to speed up the test execution
        dynamodb = aws_stack.connect_to_resource("dynamodb", config=self.retry_config())
        table_name = f"table-{short_uid()}"
        resources.create_dynamodb_table(table_name, partition_key=PARTITION_KEY)
        return dynamodb.Table(table_name)

    def retry_config(self):
        # set max_attempts=1 to speed up the test execution
        return Config(retries={"max_attempts": 1})

    def assert_zero_probability_read_error_injection(self, table, partition_key):
        # by default, no errors
        test_no_errors = table.get_item(Key={PARTITION_KEY: partition_key})
        assert test_no_errors["ResponseMetadata"]["HTTPStatusCode"] == 200
