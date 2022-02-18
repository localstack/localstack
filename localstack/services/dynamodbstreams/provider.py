import json
import logging

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.dynamodbstreams import (
    DescribeStreamOutput,
    DynamodbstreamsApi,
    ExpiredIteratorException,
    GetRecordsInput,
    GetRecordsOutput,
    GetShardIteratorOutput,
    ListStreamsOutput,
    PositiveIntegerObject,
    ResourceNotFoundException,
    SequenceNumber,
    ShardId,
    ShardIteratorType,
    StreamArn,
    TableName,
)
from localstack.services.dynamodbstreams.dynamodbstreams_api import (
    DynamoDBStreamsBackend,
    get_kinesis_stream_name,
    kinesis_shard_id,
    shard_id,
    stream_name_from_stream_arn,
    table_name_from_stream_arn,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str

LOG = logging.getLogger(__name__)


class DynamoDBStreamsProvider(DynamodbstreamsApi, ServiceLifecycleHook):
    def describe_stream(
        self,
        context: RequestContext,
        stream_arn: StreamArn,
        limit: PositiveIntegerObject = None,
        exclusive_start_shard_id: ShardId = None,
    ) -> DescribeStreamOutput:
        region = DynamoDBStreamsBackend.get()
        kinesis = aws_stack.connect_to_service("kinesis")
        result = {}
        for stream in region.ddb_streams.values():
            if stream["StreamArn"] == stream_arn:
                result = {"StreamDescription": stream}
                # get stream details
                dynamodb = aws_stack.connect_to_service("dynamodb")
                table_name = table_name_from_stream_arn(stream["StreamArn"])
                stream_name = get_kinesis_stream_name(table_name)
                stream_details = kinesis.describe_stream(StreamName=stream_name)
                table_details = dynamodb.describe_table(TableName=table_name)
                stream["KeySchema"] = table_details["Table"]["KeySchema"]

                # Replace Kinesis ShardIDs with ones that mimic actual
                # DynamoDBStream ShardIDs.
                stream_shards = stream_details["StreamDescription"]["Shards"]
                for shard in stream_shards:
                    shard["ShardId"] = shard_id(stream_name, shard["ShardId"])
                stream["Shards"] = stream_shards
                return DescribeStreamOutput(**result)
        if not result:
            raise ResourceNotFoundException(f"Stream {stream_arn} was not found.")

    @handler("GetRecords", expand=False)
    def get_records(self, context: RequestContext, payload: GetRecordsInput) -> GetRecordsOutput:
        kinesis = aws_stack.connect_to_service("kinesis")
        try:
            kinesis_records = kinesis.get_records(**payload)
        except kinesis.exceptions.ExpiredIteratorException:
            LOG.debug("Shard iterator for underlying kinesis stream expired")
            raise ExpiredIteratorException("Shard iterator has expired")
        result = {
            "Records": [],
            "NextShardIterator": kinesis_records.get("NextShardIterator"),
        }
        for record in kinesis_records["Records"]:
            record_data = json.loads(to_str(record["Data"]))
            record_data["dynamodb"]["SequenceNumber"] = record["SequenceNumber"]
            result["Records"].append(record_data)
        return GetRecordsOutput(**result)

    def get_shard_iterator(
        self,
        context: RequestContext,
        stream_arn: StreamArn,
        shard_id: ShardId,
        shard_iterator_type: ShardIteratorType,
        sequence_number: SequenceNumber = None,
    ) -> GetShardIteratorOutput:
        stream_name = stream_name_from_stream_arn(stream_arn)
        stream_shard_id = kinesis_shard_id(shard_id)
        kinesis = aws_stack.connect_to_service("kinesis")

        kwargs = {"StartingSequenceNumber": sequence_number} if sequence_number else {}
        result = kinesis.get_shard_iterator(
            StreamName=stream_name,
            ShardId=stream_shard_id,
            ShardIteratorType=shard_iterator_type,
            **kwargs,
        )
        del result["ResponseMetadata"]
        return GetShardIteratorOutput(**result)

    def list_streams(
        self,
        context: RequestContext,
        table_name: TableName = None,
        limit: PositiveIntegerObject = None,
        exclusive_start_stream_arn: StreamArn = None,
    ) -> ListStreamsOutput:
        region = DynamoDBStreamsBackend.get()
        return ListStreamsOutput(Streams=list(region.ddb_streams.values()))
