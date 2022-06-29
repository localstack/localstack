import logging
import re
from datetime import datetime

import cbor2
import pytest
import requests

from localstack import config, constants
from localstack.utils.aws import aws_stack
from localstack.utils.common import poll_condition, retry, select_attributes, short_uid
from localstack.utils.kinesis import kinesis_connector


def get_shard_iterator(stream_name, kinesis_client):
    response = kinesis_client.describe_stream(StreamName=stream_name)
    sequence_number = (
        response.get("StreamDescription")
        .get("Shards")[0]
        .get("SequenceNumberRange")
        .get("StartingSequenceNumber")
    )
    shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
    response = kinesis_client.get_shard_iterator(
        StreamName=stream_name,
        ShardId=shard_id,
        ShardIteratorType="AT_SEQUENCE_NUMBER",
        StartingSequenceNumber=sequence_number,
    )
    return response.get("ShardIterator")


class TestKinesis:
    def test_stream_consumers(
        self, kinesis_client, kinesis_create_stream, wait_for_stream_ready, wait_for_consumer_ready
    ):
        stream_name = "test-%s" % short_uid()

        def assert_consumers(**kwargs):
            consumer_list = kinesis_client.list_stream_consumers(StreamARN=stream_arn).get(
                "Consumers"
            )
            assert kwargs["count"] == len(consumer_list)
            return consumer_list

        # create stream and assert 0 consumers
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = kinesis_client.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamARN"
        ]
        wait_for_stream_ready(stream_name)

        assert_consumers(count=0)

        # create consumer and assert 1 consumer
        consumer_name = "cons1"
        response = kinesis_client.register_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )
        consumer_arn = response["Consumer"]["ConsumerARN"]
        wait_for_consumer_ready(consumer_arn=consumer_arn)
        assert consumer_name == response["Consumer"]["ConsumerName"]
        # boto3 converts the timestamp to datetime
        assert isinstance(response["Consumer"]["ConsumerCreationTimestamp"], datetime)
        consumers = assert_consumers(count=1)
        consumer_arn = consumers[0]["ConsumerARN"]
        assert consumer_name == consumers[0]["ConsumerName"]
        assert "/%s" % consumer_name in consumer_arn
        assert isinstance(consumers[0]["ConsumerCreationTimestamp"], datetime)

        # lookup stream consumer by describe calls, assert response
        consumer_description_by_arn = kinesis_client.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerARN=consumer_arn
        )["ConsumerDescription"]
        assert consumer_name == consumer_description_by_arn["ConsumerName"]
        assert consumer_arn == consumer_description_by_arn["ConsumerARN"]
        assert stream_arn == consumer_description_by_arn["StreamARN"]
        assert "ACTIVE", consumer_description_by_arn["ConsumerStatus"]
        assert isinstance(consumer_description_by_arn["ConsumerCreationTimestamp"], datetime)

        consumer_description_by_name = kinesis_client.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )["ConsumerDescription"]
        assert consumer_description_by_arn == consumer_description_by_name

        # delete existing consumer and assert 0 remaining consumers
        kinesis_client.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)

        retry(assert_consumers, count=0, retries=6, sleep=3.0)

    def test_subscribe_to_shard(
        self, kinesis_client, kinesis_create_stream, wait_for_stream_ready, wait_for_consumer_ready
    ):
        stream_name = "test-%s" % short_uid()

        # create stream and consumer
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = kinesis_client.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamARN"
        ]
        wait_for_stream_ready(stream_name)

        result = kinesis_client.register_stream_consumer(StreamARN=stream_arn, ConsumerName="c1")[
            "Consumer"
        ]
        consumer_arn = result["ConsumerARN"]
        wait_for_consumer_ready(consumer_arn=consumer_arn)

        # subscribe to shard
        response = kinesis_client.describe_stream(StreamName=stream_name)

        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
        result = kinesis_client.subscribe_to_shard(
            ConsumerARN=result["ConsumerARN"],
            ShardId=shard_id,
            StartingPosition={"Type": "TRIM_HORIZON"},
        )
        stream = result["EventStream"]

        # put records
        num_records = 5
        msg = b"Hello world"
        for i in range(num_records):
            kinesis_client.put_records(
                StreamName=stream_name, Records=[{"Data": msg, "PartitionKey": "1"}]
            )

        # assert results
        results = []
        for entry in stream:
            records = entry["SubscribeToShardEvent"]["Records"]
            continuation_sequence_number = entry["SubscribeToShardEvent"][
                "ContinuationSequenceNumber"
            ]
            # https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShardEvent.html
            assert re.fullmatch("^0|([1-9][0-9]{0,128})$", continuation_sequence_number)
            results.extend(records)
            if len(results) >= num_records:
                break

        # assert results
        assert num_records == len(results)
        for record in results:
            assert msg == record["Data"]

        # clean up
        kinesis_client.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName="c1")

    def test_subscribe_to_shard_with_sequence_number_as_iterator(
        self, kinesis_client, kinesis_create_stream, wait_for_stream_ready, wait_for_consumer_ready
    ):
        stream_name = "test-%s" % short_uid()
        record_data = "Hello world"

        # create stream and consumer
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = kinesis_client.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamARN"
        ]
        wait_for_stream_ready(stream_name)

        result = kinesis_client.register_stream_consumer(StreamARN=stream_arn, ConsumerName="c1")[
            "Consumer"
        ]
        consumer_arn = result["ConsumerARN"]
        wait_for_consumer_ready(consumer_arn=consumer_arn)
        # get starting sequence number
        response = kinesis_client.describe_stream(StreamName=stream_name)
        sequence_number = (
            response.get("StreamDescription")
            .get("Shards")[0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber")
        )
        # subscribe to shard with iterator type as AT_SEQUENCE_NUMBER
        response = kinesis_client.describe_stream(StreamName=stream_name)
        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
        result = kinesis_client.subscribe_to_shard(
            ConsumerARN=result["ConsumerARN"],
            ShardId=shard_id,
            StartingPosition={
                "Type": "AT_SEQUENCE_NUMBER",
                "SequenceNumber": sequence_number,
            },
        )
        stream = result["EventStream"]
        # put records
        num_records = 5
        for i in range(num_records):
            kinesis_client.put_records(
                StreamName=stream_name,
                Records=[{"Data": record_data, "PartitionKey": "1"}],
            )

        results = []
        for entry in stream:
            records = entry["SubscribeToShardEvent"]["Records"]
            results.extend(records)
            if len(results) >= num_records:
                break

        # assert results
        assert num_records == len(results)
        for record in results:
            assert str.encode(record_data) == record["Data"]

        # clean up
        kinesis_client.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName="c1")

    def test_get_records(self, kinesis_client, kinesis_create_stream, wait_for_stream_ready):
        stream_name = "test-%s" % short_uid()

        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name)

        kinesis_client.put_records(
            StreamName=stream_name,
            Records=[{"Data": "SGVsbG8gd29ybGQ=", "PartitionKey": "1"}],
        )

        # get records with JSON encoding
        iterator = get_shard_iterator(stream_name, kinesis_client)
        response = kinesis_client.get_records(ShardIterator=iterator)
        json_records = response.get("Records")
        assert 1 == len(json_records)
        assert "Data" in json_records[0]

        # get records with CBOR encoding
        iterator = get_shard_iterator(stream_name, kinesis_client)
        url = config.get_edge_url()
        headers = aws_stack.mock_aws_request_headers("kinesis")
        headers["Content-Type"] = constants.APPLICATION_AMZ_CBOR_1_1
        headers["X-Amz-Target"] = "Kinesis_20131202.GetRecords"
        data = cbor2.dumps({"ShardIterator": iterator})
        result = requests.post(url, data, headers=headers)
        assert 200 == result.status_code
        result = cbor2.loads(result.content)
        attrs = ("Data", "EncryptionType", "PartitionKey", "SequenceNumber")
        assert select_attributes(json_records[0], attrs) == select_attributes(
            result["Records"][0], attrs
        )

    def test_record_lifecycle_data_integrity(
        self, kinesis_client, kinesis_create_stream, wait_for_stream_ready
    ):
        """
        kinesis records should contain the same data from when they are sent to when they are received
        """
        stream_name = "test-%s" % short_uid()
        records_data = {"test", "ünicödé 统一码 💣💻🔥", "a" * 1000, ""}
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name)

        iterator = get_shard_iterator(stream_name, kinesis_client)

        for record_data in records_data:
            kinesis_client.put_record(
                StreamName=stream_name,
                Data=record_data,
                PartitionKey="1",
            )

        response = kinesis_client.get_records(ShardIterator=iterator)
        response_records = response.get("Records")
        assert len(records_data) == len(response_records)
        for response_record in response_records:
            assert response_record.get("Data").decode("utf-8") in records_data


@pytest.fixture
def wait_for_consumer_ready(kinesis_client):
    def _wait_for_consumer_ready(consumer_arn: str):
        def is_consumer_ready():
            describe_response = kinesis_client.describe_stream_consumer(ConsumerARN=consumer_arn)
            return describe_response["ConsumerDescription"]["ConsumerStatus"] == "ACTIVE"

        poll_condition(is_consumer_ready)

    return _wait_for_consumer_ready


def test_get_records_next_shard_iterator(
    kinesis_client, kinesis_create_stream, wait_for_stream_ready
):
    stream_name = kinesis_create_stream()
    wait_for_stream_ready(stream_name)

    first_stream_shard_data = kinesis_client.describe_stream(StreamName=stream_name)[
        "StreamDescription"
    ]["Shards"][0]
    shard_id = first_stream_shard_data["ShardId"]

    shard_iterator = kinesis_client.get_shard_iterator(
        StreamName=stream_name, ShardIteratorType="LATEST", ShardId=shard_id
    )["ShardIterator"]

    get_records_response = kinesis_client.get_records(ShardIterator=shard_iterator)
    new_shard_iterator = get_records_response["NextShardIterator"]
    assert shard_iterator != new_shard_iterator
    get_records_response = kinesis_client.get_records(ShardIterator=new_shard_iterator)
    assert shard_iterator != get_records_response["NextShardIterator"]
    assert new_shard_iterator != get_records_response["NextShardIterator"]


class TestKinesisPythonClient:
    @pytest.mark.skip_offline
    def test_run_kcl(self):
        result = []

        def process_records(records):
            result.extend(records)

        # start Kinesis client
        stream_name = f"test-foobar-{short_uid()}"
        aws_stack.create_kinesis_stream(stream_name, delete=True)
        kinesis_connector.listen_to_kinesis(
            stream_name=stream_name,
            listener_func=process_records,
            kcl_log_level=logging.INFO,
            wait_until_started=True,
        )

        kinesis = aws_stack.create_external_boto_client("kinesis")

        stream_summary = kinesis.describe_stream_summary(StreamName=stream_name)
        assert 1 == stream_summary["StreamDescriptionSummary"]["OpenShardCount"]

        num_events_kinesis = 10
        kinesis.put_records(
            Records=[
                {"Data": "{}", "PartitionKey": "test_%s" % i} for i in range(0, num_events_kinesis)
            ],
            StreamName=stream_name,
        )

        def check_events():
            assert num_events_kinesis == len(result)

        retry(check_events, retries=4, sleep=2)
