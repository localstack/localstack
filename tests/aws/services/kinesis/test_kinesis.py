import json
import logging
import os
import subprocess
import time
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from botocore.auth import SigV4Auth
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

# cbor2: explicitly load from private _encoder/_decoder module to avoid using the (non-patched) C-version
from cbor2._decoder import loads as cbor2_loads
from cbor2._encoder import dumps as cbor2_dumps
from requests import Response

from localstack import config, constants
from localstack.aws.api.lambda_ import Runtime
from localstack.aws.client import _patch_cbor2
from localstack.services.kinesis import provider as kinesis_provider
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import resources
from localstack.utils.common import retry, select_attributes, short_uid
from localstack.utils.files import load_file
from localstack.utils.kinesis import kinesis_connector
from tests.aws.services.kinesis.helper_functions import get_shard_iterator
from tests.aws.services.lambda_.test_lambda import THIS_FOLDER as LAMBDA_TEST_FOLDER

LOGGER = logging.getLogger(__name__)

# make sure cbor2 patches are applied
# (for the test-data decoding, usually done as init hook in LocalStack)
_patch_cbor2()


class KinesisHTTPClient:
    """
    Simple HTTP client for making Kinesis requests manually using the CBOR serialization type.

    This serialization type is not available via botocore.
    """

    def __init__(
        self,
        account_id: str,
        region_name: str,
        client_factory,
    ):
        self.account_id = account_id
        self.region_name = region_name
        self._client = client_factory("kinesis", region=self.region_name, signer_factory=SigV4Auth)

    def post_raw(
        self, operation: str, payload: dict, datetime_as_timestamp: bool = True, **kwargs
    ) -> Response:
        """
        Perform a kinesis operation, encoding the request payload with CBOR and returning the raw
        response without any processing or checks.
        """
        response = self._client.post(
            self.endpoint,
            data=cbor2_dumps(payload, datetime_as_timestamp=datetime_as_timestamp),
            headers=self._build_headers(operation),
            **kwargs,
        )
        return response

    def post(self, operation: str, payload: dict, datetime_as_timestamp: bool = True) -> Any:
        """
        Perform a kinesis operation, encoding the request payload with CBOR, checking the response status code
         and decoding the response with CBOR.
        """
        response = self.post_raw(operation, payload, datetime_as_timestamp)
        response_content = response.content
        response_body = cbor2_loads(response_content)
        if response.status_code != 200:
            raise ValueError(f"Bad status: {response.status_code}, response body: {response_body}")
        return response_body

    def _build_headers(self, operation: str) -> dict:
        return {
            "content-type": constants.APPLICATION_AMZ_CBOR_1_1,
            "x-amz-target": f"Kinesis_20131202.{operation}",
            "host": self.endpoint,
        }

    @property
    def endpoint(self) -> str:
        return (
            f"https://{self.account_id}.control-kinesis.{self.region_name}.amazonaws.com"
            if is_aws_cloud()
            else config.internal_service_url()
        )


@pytest.fixture
def kinesis_http_client(account_id, region_name, aws_http_client_factory):
    return KinesisHTTPClient(account_id, region_name, client_factory=aws_http_client_factory)


class TestKinesis:
    @staticmethod
    def _get_endpoint(account_id: str, region_name: str):
        return (
            f"https://{account_id}.control-kinesis.{region_name}.amazonaws.com"
            if is_aws_cloud()
            else config.internal_service_url()
        )

    @markers.aws.validated
    def test_create_stream_without_stream_name_raises(self, aws_client_factory):
        boto_config = BotoConfig(parameter_validation=False)
        kinesis_client = aws_client_factory(config=boto_config).kinesis
        with pytest.raises(ClientError) as e:
            kinesis_client.create_stream()
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        # TODO snapshotting reveals that the Error.Message is different

    @markers.aws.validated
    def test_create_stream_without_shard_count(
        self, kinesis_create_stream, wait_for_stream_ready, snapshot, aws_client, cleanups
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
        kinesis_register_consumer,
        wait_for_kinesis_consumer_ready,
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
        response = kinesis_register_consumer(stream_arn, consumer_name)
        consumer_arn = response["Consumer"]["ConsumerARN"]
        wait_for_kinesis_consumer_ready(consumer_arn=consumer_arn)

        consumer_list = aws_client.kinesis.list_stream_consumers(StreamARN=stream_arn).get(
            "Consumers"
        )
        snapshot.match("One_consumer_by_list_stream", consumer_list)

        # lookup stream consumer by describe_stream_consumer
        consumer_description_by_arn = aws_client.kinesis.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerARN=consumer_arn
        )["ConsumerDescription"]

        snapshot.match("One_consumer_by_describe_stream", consumer_description_by_arn)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Records..EncryptionType"])
    def test_subscribe_to_shard(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        kinesis_register_consumer,
        wait_for_kinesis_consumer_ready,
        snapshot,
        aws_client,
    ):
        # create stream and consumer
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)
        consumer_name = "c1"
        response = kinesis_register_consumer(stream_arn, consumer_name)
        consumer_arn = response["Consumer"]["ConsumerARN"]
        wait_for_kinesis_consumer_ready(consumer_arn=consumer_arn)

        # subscribe to shard
        response = aws_client.kinesis.describe_stream(StreamName=stream_name)

        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
        result = aws_client.kinesis.subscribe_to_shard(
            ConsumerARN=consumer_arn,
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

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Records..EncryptionType"])
    def test_subscribe_to_shard_with_at_timestamp(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        kinesis_register_consumer,
        wait_for_kinesis_consumer_ready,
        snapshot,
        aws_client,
    ):
        # create stream and consumer
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)

        consumer_name = "c1"
        response = kinesis_register_consumer(stream_arn, consumer_name)
        consumer_arn = response["Consumer"]["ConsumerARN"]
        wait_for_kinesis_consumer_ready(consumer_arn=consumer_arn)

        # subscribe to shard with iterator type as AT_TIMESTAMP
        response = aws_client.kinesis.describe_stream(StreamName=stream_name)
        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
        result = aws_client.kinesis.subscribe_to_shard(
            ConsumerARN=consumer_arn,
            ShardId=shard_id,
            StartingPosition={"Type": "AT_TIMESTAMP", "Timestamp": datetime(2015, 1, 1)},
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

    @markers.aws.needs_fixing
    # TODO SubscribeToShard raises a 500 (Internal Server Error) against AWS
    def test_subscribe_to_shard_cbor_at_timestamp(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        aws_client,
        kinesis_register_consumer,
        kinesis_http_client,
        account_id,
        region_name,
        wait_for_kinesis_consumer_ready,
    ):
        # create stream
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        # subscribe to shard with CBOR encoding
        response = aws_client.kinesis.describe_stream(StreamName=stream_name)
        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")

        # create consumer
        consumer_name = "c1"
        response = kinesis_register_consumer(
            response["StreamDescription"]["StreamARN"], consumer_name
        )
        consumer_arn = response["Consumer"]["ConsumerARN"]
        wait_for_kinesis_consumer_ready(consumer_arn=consumer_arn)

        found_record = False
        with kinesis_http_client.post_raw(
            operation="SubscribeToShard",
            payload={
                "ConsumerARN": consumer_arn,
                "ShardId": shard_id,
                "StartingPosition": {
                    "Type": "AT_TIMESTAMP",
                    "Timestamp": datetime.now().astimezone(),
                },
            },
            stream=True,
        ) as result:
            assert 200 == result.status_code

            # put records
            aws_client.kinesis.put_records(
                StreamName=stream_name, Records=[{"Data": "--RECORD--", "PartitionKey": "1"}]
            )

            # botocore does not support parsing CBOR responses
            # just check for the presence of the record marker
            for chunk in result.iter_lines(delimiter=b"\00"):
                if b"--RECORD--" in chunk:
                    found_record = True
                    break

        assert found_record

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Records..EncryptionType"])
    def test_subscribe_to_shard_with_sequence_number_as_iterator(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        kinesis_register_consumer,
        wait_for_kinesis_consumer_ready,
        snapshot,
        aws_client,
    ):
        # create stream and consumer
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)

        consumer_name = "c1"
        response = kinesis_register_consumer(stream_arn, consumer_name)
        consumer_arn = response["Consumer"]["ConsumerARN"]
        wait_for_kinesis_consumer_ready(consumer_arn=consumer_arn)

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
            ConsumerARN=consumer_arn,
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

    @markers.aws.validated
    def test_get_records(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        aws_client,
        kinesis_http_client,
        account_id,
        region_name,
        kinesis_register_consumer,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("StreamName"))

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
        result = kinesis_http_client.post(
            operation="GetRecords", payload={"ShardIterator": iterator}
        )
        attrs = ("Data", "EncryptionType", "PartitionKey", "SequenceNumber")
        assert select_attributes(json_records[0], attrs) == select_attributes(
            result["Records"][0], attrs
        )
        # ensure that the CBOR datetime format is parsed the same way
        assert (
            json_records[0]["ApproximateArrivalTimestamp"]
            == result["Records"][0]["ApproximateArrivalTimestamp"]
        )

    @markers.aws.validated
    def test_get_records_empty_stream(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        aws_client,
        kinesis_http_client,
        account_id,
        region_name,
    ):
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        # empty get records with JSON encoding
        iterator = get_shard_iterator(stream_name, aws_client.kinesis)
        json_response = aws_client.kinesis.get_records(ShardIterator=iterator)
        json_records = json_response.get("Records")
        assert 0 == len(json_records)

        # empty get records with CBOR encoding
        cbor_records_content = kinesis_http_client.post(
            operation="GetRecords", payload={"ShardIterator": iterator}
        )
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
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        kinesis_register_consumer,
        wait_for_kinesis_consumer_ready,
        aws_client,
    ):
        # create stream and consumer
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)

        # create consumer
        consumer_name = "c1"
        response = kinesis_register_consumer(stream_arn, consumer_name)
        consumer_arn = response["Consumer"]["ConsumerARN"]
        wait_for_kinesis_consumer_ready(consumer_arn=consumer_arn)

        # subscribe to shard
        response = aws_client.kinesis.describe_stream(StreamName=stream_name)
        shard_id = response.get("StreamDescription").get("Shards")[0].get("ShardId")
        result = aws_client.kinesis.subscribe_to_shard(
            ConsumerARN=consumer_arn,
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

    @markers.aws.validated
    def test_get_records_shard_iterator_with_surrounding_quotes(
        self, kinesis_create_stream, wait_for_stream_ready, aws_client
    ):
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        aws_client.kinesis.put_records(
            StreamName=stream_name, Records=[{"Data": b"Hello world", "PartitionKey": "1"}]
        )

        first_stream_shard_data = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["Shards"][0]
        shard_id = first_stream_shard_data["ShardId"]

        shard_iterator = aws_client.kinesis.get_shard_iterator(
            StreamName=stream_name, ShardIteratorType="TRIM_HORIZON", ShardId=shard_id
        )["ShardIterator"]

        assert aws_client.kinesis.get_records(ShardIterator=f'"{shard_iterator}"')["Records"]

    @markers.aws.validated
    def test_subscribe_to_shard_with_at_timestamp_cbor(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        aws_client,
        kinesis_http_client,
    ):
        # create stream
        pre_create_timestamp = (datetime.now() - timedelta(hours=0, minutes=1)).astimezone()
        stream_name = kinesis_create_stream(ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name)
        post_create_timestamp = (datetime.now() + timedelta(hours=0, minutes=1)).astimezone()

        # perform a raw DescribeStream request to test the datetime serialization by LocalStack
        describe_response_raw = kinesis_http_client.post_raw(
            operation="DescribeStream",
            payload={"StreamARN": stream_arn},
        )
        assert 200 == describe_response_raw.status_code
        cbor_content = describe_response_raw.content

        # Ensure that the timestamp is in an integer and not a floating point (AWS SDKs can't handle that)
        # Assert via testing the binary stream for the CBOR tag types according to RFC 7049:
        # - Byte 1: 0xc1 -> 11000001
        #   - first 3 bit (110) are major type -> 6 -> "Semantic Tag"
        #   - the next 5 bit (00001) are the tag type -> 1 -> "numerical representation of seconds relative to epoch"
        # - Byte 2: 0xfb -> 11111011
        #   - declares for deterministic encoding that the floating point is encoded as binary 64 (section 4.2.2)

        assert b"StreamCreationTimestamp\xc1\xfb" not in cbor_content
        describe_response_data = cbor2_loads(cbor_content)

        # verify that the request can be properly parsed, and that the timestamp is within the
        # boundaries
        assert (
            pre_create_timestamp
            <= describe_response_data["StreamDescription"]["StreamCreationTimestamp"]
            <= post_create_timestamp
        )

        shard_id = describe_response_data["StreamDescription"]["Shards"][0]["ShardId"]
        shard_iterator_response_data = kinesis_http_client.post(
            "GetShardIterator",
            payload={
                "StreamARN": stream_arn,
                "ShardId": shard_id,
                "ShardIteratorType": "AT_TIMESTAMP",
                "Timestamp": datetime.now().astimezone(),
            },
        )
        assert "ShardIterator" in shard_iterator_response_data

    @markers.aws.validated
    def test_cbor_blob_handling(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        aws_client,
        kinesis_http_client,
    ):
        # create stream
        stream_name = kinesis_create_stream(ShardCount=1)
        wait_for_stream_ready(stream_name)

        test_data = f"hello world {short_uid()}"

        # put a record on to the stream
        kinesis_http_client.post(
            operation="PutRecord",
            payload={
                "Data": test_data.encode("utf-8"),
                "PartitionKey": f"key-{short_uid()}",
                "StreamName": stream_name,
            },
        )

        # don't need to get shard iterator manually, so use the SDK
        shard_iterator: str | None = get_shard_iterator(stream_name, aws_client.kinesis)
        assert shard_iterator is not None

        def _get_record():
            # send get records request via the http client
            get_records_response = kinesis_http_client.post(
                operation="GetRecords",
                payload={
                    "ShardIterator": shard_iterator,
                },
            )
            assert len(get_records_response["Records"]) == 1
            return get_records_response["Records"][0]

        record = retry(_get_record, sleep=1, retries=5)
        assert record["Data"].decode("utf-8") == test_data


class TestKinesisJavaSDK:
    # the lambda function is stored in the lambda common functions folder to re-use existing caching in CI
    TEST_LAMBDA_KINESIS_SDK_V2 = os.path.join(
        LAMBDA_TEST_FOLDER,
        "functions/common/kinesis_sdkv2/java17/handler.zip",
    )

    @markers.aws.validated
    def test_subscribe_to_shard_with_java_sdk_v2_lambda(
        self,
        kinesis_create_stream,
        wait_for_stream_ready,
        create_lambda_function,
        lambda_su_role,
        aws_client,
    ):
        # lazily build the lambda if it's not there yet
        if not os.path.exists(self.TEST_LAMBDA_KINESIS_SDK_V2) or not os.path.isfile(
            self.TEST_LAMBDA_KINESIS_SDK_V2
        ):
            build_cmd = ["make", "build"]
            LOGGER.info("Building Java Lambda for Kinesis AWS SDK v2 test.")
            result = subprocess.run(build_cmd, cwd=os.path.dirname(self.TEST_LAMBDA_KINESIS_SDK_V2))
            if result.returncode != 0:
                raise Exception("Failed to build lambda for Kinesis Java AWS SDK v2 test.")

        stream_name = kinesis_create_stream()
        wait_for_stream_ready(stream_name)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        lambda_name = f"test-{short_uid()}"
        zip_file = load_file(self.TEST_LAMBDA_KINESIS_SDK_V2, mode="rb")
        create_lambda_function(
            zip_file=zip_file,
            runtime=Runtime.java17,
            handler="kinesis.Handler",
            func_name=lambda_name,
            role=lambda_su_role,
        )
        result = aws_client.lambda_.invoke(
            FunctionName=lambda_name, Payload=json.dumps({"StreamARN": stream_arn})
        )
        response_content = json.load(result["Payload"])
        assert response_content == "ok"


class TestKinesisPythonClient:
    @markers.skip_offline
    @markers.aws.only_localstack
    def test_run_kcl(self, aws_client, account_id, region_name):
        result = []

        def process_records(records):
            result.extend(records)

        # start Kinesis client
        kinesis = aws_client.kinesis
        stream_name = f"test-foobar-{short_uid()}"
        resources.create_kinesis_stream(kinesis, stream_name, delete=True)
        process = kinesis_connector.listen_to_kinesis(
            stream_name=stream_name,
            account_id=account_id,
            region_name=region_name,
            listener_func=process_records,
            wait_until_started=True,
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
