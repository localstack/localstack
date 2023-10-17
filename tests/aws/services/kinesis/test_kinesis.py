import logging
import time
from unittest.mock import patch

import cbor2
import pytest
import requests
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from localstack import config, constants
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_REGION_NAME
from localstack.services.kinesis import provider as kinesis_provider
from localstack.testing.pytest import markers
from localstack.utils.aws import aws_stack, resources
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


@pytest.fixture(autouse=True)
def kinesis_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.kinesis_api())


class TestKinesis:
    @markers.aws.unknown
    def test_create_stream_without_stream_name_raises(self, aws_client_factory):
        boto_config = BotoConfig(parameter_validation=False)
        kinesis_client = aws_client_factory(config=boto_config).kinesis
        with pytest.raises(ClientError) as e:
            kinesis_client.create_stream()
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

    @markers.aws.validated
    def test_create_stream_without_shard_count(
        self, kinesis_create_stream, wait_for_stream_ready, snapshot, aws_client
    ):
        stream_name = kinesis_create_stream()
        wait_for_stream_ready(stream_name)
        describe_stream = aws_client.kinesis.describe_stream(StreamName=stream_name)

        shards = describe_stream["StreamDescription"]["Shards"]
        shards.sort(key=lambda k: k.get("ShardId"))

        snapshot.match("Shards", shards)

    @markers.aws.validated
    def test_stream_consumers(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        wait_for_consumer_ready,
        snapshot,
        aws_client,
    ):
        # create stream and assert 0 consumers
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)

        # no consumer snapshot
        consumer_list = aws_client.kinesis.list_stream_consumers(StreamARN=stream_arn).get(
            "Consumers"
        )
        assert len(consumer_list) == 0

        # create consumer and snapshot 1 consumer by list_stream_consumers
        consumer_name = "consumer"
        response = aws_client.kinesis.register_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )
        consumer_arn = response["Consumer"]["ConsumerARN"]
        wait_for_consumer_ready(consumer_arn=consumer_arn)

        consumer_list = aws_client.kinesis.list_stream_consumers(StreamARN=stream_arn).get(
            "Consumers"
        )
        snapshot.match("One_consumer_by_list_stream", consumer_list)

        # lookup stream consumer by describe_stream_consumer
        consumer_description_by_arn = aws_client.kinesis.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerARN=consumer_arn
        )["ConsumerDescription"]

        snapshot.match("One_consumer_by_describe_stream", consumer_description_by_arn)

        # delete existing consumer and assert 0 remaining consumers
        aws_client.kinesis.deregister_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Records..EncryptionType"])
    def test_subscribe_to_shard(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        wait_for_consumer_ready,
        snapshot,
        aws_client,
    ):
        # create stream and consumer
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)

        result = aws_client.kinesis.register_stream_consumer(
            StreamARN=stream_arn, ConsumerName="c1"
        )["Consumer"]
        consumer_arn = result["ConsumerARN"]
        wait_for_consumer_ready(consumer_arn=consumer_arn)

        # subscribe to shard
        response = aws_client.kinesis.describe_stream(StreamName=stream_name)

        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
        result = aws_client.kinesis.subscribe_to_shard(
            ConsumerARN=result["ConsumerARN"],
            ShardId=shard_id,
            StartingPosition={"Type": "TRIM_HORIZON"},
        )
        stream = result["EventStream"]

        # put records
        num_records = 5
        msg = "Hello world"
        for i in range(num_records):
            aws_client.kinesis.put_records(
                StreamName=stream_name, Records=[{"Data": f"{msg}_{i}", "PartitionKey": "1"}]
            )

        # read out results
        results = []
        for entry in stream:
            records = entry["SubscribeToShardEvent"]["Records"]
            results.extend(records)
            if len(results) >= num_records:
                break

        results.sort(key=lambda k: k.get("Data"))
        snapshot.match("Records", results)

        # clean up
        aws_client.kinesis.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName="c1")

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Records..EncryptionType"])
    def test_subscribe_to_shard_with_sequence_number_as_iterator(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        wait_for_consumer_ready,
        snapshot,
        aws_client,
    ):
        # create stream and consumer
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)

        result = aws_client.kinesis.register_stream_consumer(
            StreamARN=stream_arn, ConsumerName="c1"
        )["Consumer"]
        consumer_arn = result["ConsumerARN"]
        wait_for_consumer_ready(consumer_arn=consumer_arn)
        # get starting sequence number
        response = aws_client.kinesis.describe_stream(StreamName=stream_name)
        sequence_number = (
            response.get("StreamDescription")
            .get("Shards")[0]
            .get("SequenceNumberRange")
            .get("StartingSequenceNumber")
        )
        # subscribe to shard with iterator type as AT_SEQUENCE_NUMBER
        response = aws_client.kinesis.describe_stream(StreamName=stream_name)
        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
        result = aws_client.kinesis.subscribe_to_shard(
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
        msg = "Hello world"
        for i in range(num_records):
            aws_client.kinesis.put_records(
                StreamName=stream_name, Records=[{"Data": f"{msg}_{i}", "PartitionKey": "1"}]
            )

        # read out results
        results = []
        for entry in stream:
            records = entry["SubscribeToShardEvent"]["Records"]
            results.extend(records)
            if len(results) >= num_records:
                break

        results.sort(key=lambda k: k.get("Data"))
        snapshot.match("Records", results)

        # clean up
        aws_client.kinesis.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName="c1")

    @markers.aws.unknown
    def test_get_records(self, kinesis_create_stream, wait_for_stream_ready, aws_client):
        # create stream
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        aws_client.kinesis.put_records(
            StreamName=stream_name,
            Records=[{"Data": "SGVsbG8gd29ybGQ=", "PartitionKey": "1"}],
        )

        # get records with JSON encoding
        iterator = get_shard_iterator(stream_name, aws_client.kinesis)
        response = aws_client.kinesis.get_records(ShardIterator=iterator)
        json_records = response.get("Records")
        assert 1 == len(json_records)
        assert "Data" in json_records[0]

        # get records with CBOR encoding
        iterator = get_shard_iterator(stream_name, aws_client.kinesis)
        url = config.get_edge_url()
        headers = aws_stack.mock_aws_request_headers(
            "kinesis", region_name=TEST_AWS_REGION_NAME, access_key=TEST_AWS_ACCESS_KEY_ID
        )
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
        # ensure that the CBOR datetime format is unix timestamp millis
        assert (
            int(json_records[0]["ApproximateArrivalTimestamp"].timestamp() * 1000)
            == result["Records"][0]["ApproximateArrivalTimestamp"]
        )

    @markers.aws.unknown
    def test_get_records_empty_stream(
        self, kinesis_create_stream, wait_for_stream_ready, aws_client
    ):
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        # empty get records with JSON encoding
        iterator = get_shard_iterator(stream_name, aws_client.kinesis)
        json_response = aws_client.kinesis.get_records(ShardIterator=iterator)
        json_records = json_response.get("Records")
        assert 0 == len(json_records)

        # empty get records with CBOR encoding
        url = config.get_edge_url()
        headers = aws_stack.mock_aws_request_headers(
            "kinesis", region_name=TEST_AWS_REGION_NAME, access_key=TEST_AWS_ACCESS_KEY_ID
        )
        headers["Content-Type"] = constants.APPLICATION_AMZ_CBOR_1_1
        headers["X-Amz-Target"] = "Kinesis_20131202.GetRecords"
        data = cbor2.dumps({"ShardIterator": iterator})
        cbor_response = requests.post(url, data, headers=headers)
        assert 200 == cbor_response.status_code
        cbor_records_content = cbor2.loads(cbor_response.content)
        cbor_records = cbor_records_content.get("Records")
        assert 0 == len(cbor_records)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Records..EncryptionType"])
    def test_record_lifecycle_data_integrity(
        self, kinesis_create_stream, wait_for_stream_ready, snapshot, aws_client
    ):
        """
        kinesis records should contain the same data from when they are sent to when they are received
        """
        records_data = {"test", "ünicödé 统一码 💣💻🔥", "a" * 1000, ""}
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        iterator = get_shard_iterator(stream_name, aws_client.kinesis)

        for record_data in records_data:
            aws_client.kinesis.put_record(
                StreamName=stream_name,
                Data=record_data,
                PartitionKey="1",
            )

        response = aws_client.kinesis.get_records(ShardIterator=iterator)
        response_records = response.get("Records")
        response_records.sort(key=lambda k: k.get("Data"))
        snapshot.match("Records", response_records)

    @markers.aws.validated
    @patch.object(kinesis_provider, "MAX_SUBSCRIPTION_SECONDS", 3)
    def test_subscribe_to_shard_timeout(
        self, kinesis_create_stream, wait_for_stream_ready, wait_for_consumer_ready, aws_client
    ):
        # create stream and consumer
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)
        # create consumer
        result = aws_client.kinesis.register_stream_consumer(
            StreamARN=stream_arn, ConsumerName="c1"
        )["Consumer"]
        consumer_arn = result["ConsumerARN"]
        wait_for_consumer_ready(consumer_arn=consumer_arn)

        # subscribe to shard
        response = aws_client.kinesis.describe_stream(StreamName=stream_name)
        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
        result = aws_client.kinesis.subscribe_to_shard(
            ConsumerARN=result["ConsumerARN"],
            ShardId=shard_id,
            StartingPosition={"Type": "TRIM_HORIZON"},
        )
        stream = result["EventStream"]

        # letting the subscription run out
        time.sleep(5)

        # put records
        msg = b"Hello world"
        aws_client.kinesis.put_records(
            StreamName=stream_name, Records=[{"Data": msg, "PartitionKey": "1"}]
        )

        # due to the subscription being timed out, we should not be able to read out results
        results = []
        for entry in stream:
            records = entry["SubscribeToShardEvent"]["Records"]
            results.extend(records)

        assert len(results) == 0

        # clean up
        aws_client.kinesis.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName="c1")

    @markers.aws.validated
    def test_add_tags_to_stream(
        self, kinesis_create_stream, wait_for_stream_ready, snapshot, aws_client
    ):
        test_tags = {"foo": "bar"}

        # create stream
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        # adding tags
        aws_client.kinesis.add_tags_to_stream(StreamName=stream_name, Tags=test_tags)

        # reading stream tags
        stream_tags_response = aws_client.kinesis.list_tags_for_stream(StreamName=stream_name)

        snapshot.match("Tags", stream_tags_response["Tags"][0])
        assert not stream_tags_response["HasMoreTags"]

    @markers.aws.validated
    def test_get_records_next_shard_iterator(
        self, kinesis_create_stream, wait_for_stream_ready, aws_client
    ):
        stream_name = kinesis_create_stream()
        wait_for_stream_ready(stream_name)

        first_stream_shard_data = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["Shards"][0]
        shard_id = first_stream_shard_data["ShardId"]

        shard_iterator = aws_client.kinesis.get_shard_iterator(
            StreamName=stream_name, ShardIteratorType="LATEST", ShardId=shard_id
        )["ShardIterator"]

        get_records_response = aws_client.kinesis.get_records(ShardIterator=shard_iterator)
        new_shard_iterator = get_records_response["NextShardIterator"]
        assert shard_iterator != new_shard_iterator
        get_records_response = aws_client.kinesis.get_records(ShardIterator=new_shard_iterator)
        assert shard_iterator != get_records_response["NextShardIterator"]
        assert new_shard_iterator != get_records_response["NextShardIterator"]


@pytest.fixture
def wait_for_consumer_ready(aws_client):
    def _wait_for_consumer_ready(consumer_arn: str):
        def is_consumer_ready():
            describe_response = aws_client.kinesis.describe_stream_consumer(
                ConsumerARN=consumer_arn
            )
            return describe_response["ConsumerDescription"]["ConsumerStatus"] == "ACTIVE"

        poll_condition(is_consumer_ready)

    return _wait_for_consumer_ready


class TestKinesisPythonClient:
    @markers.skip_offline
    @markers.aws.unknown
    def test_run_kcl(self, aws_client):
        result = []

        def process_records(records):
            result.extend(records)

        # start Kinesis client
        kinesis = aws_client.kinesis
        stream_name = f"test-foobar-{short_uid()}"
        resources.create_kinesis_stream(kinesis, stream_name, delete=True)
        process = kinesis_connector.listen_to_kinesis(
            stream_name=stream_name,
            listener_func=process_records,
            kcl_log_level=logging.INFO,
            wait_until_started=True,
            region_name=TEST_AWS_REGION_NAME,
        )

        try:
            stream_summary = kinesis.describe_stream_summary(StreamName=stream_name)
            assert 1 == stream_summary["StreamDescriptionSummary"]["OpenShardCount"]

            num_events_kinesis = 10
            kinesis.put_records(
                Records=[
                    {"Data": "{}", "PartitionKey": "test_%s" % i}
                    for i in range(0, num_events_kinesis)
                ],
                StreamName=stream_name,
            )

            def check_events():
                assert num_events_kinesis == len(result)

            retry(check_events, retries=4, sleep=2)
        finally:
            process.stop()
