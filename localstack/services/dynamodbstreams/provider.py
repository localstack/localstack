import copy
import logging

from bson.json_util import loads

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
    Stream,
    StreamArn,
    StreamDescription,
    StreamStatus,
    TableName,
)
from localstack.aws.connect import connect_to
from localstack.services.dynamodbstreams.dynamodbstreams_api import (
    get_dynamodbstreams_store,
    get_kinesis_stream_name,
    get_shard_id,
    kinesis_shard_id,
    stream_name_from_stream_arn,
    table_name_from_stream_arn,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.collections import select_from_typed_dict

LOG = logging.getLogger(__name__)

STREAM_STATUS_MAP = {
    "ACTIVE": StreamStatus.ENABLED,
    "CREATING": StreamStatus.ENABLING,
    "DELETING": StreamStatus.DISABLING,
    "UPDATING": StreamStatus.ENABLING,
}


class DynamoDBStreamsProvider(DynamodbstreamsApi, ServiceLifecycleHook):
    def describe_stream(
        self,
        context: RequestContext,
        stream_arn: StreamArn,
        limit: PositiveIntegerObject = None,
        exclusive_start_shard_id: ShardId = None,
    ) -> DescribeStreamOutput:
        store = get_dynamodbstreams_store(context.account_id, context.region)
        kinesis = connect_to().kinesis
        for stream in store.ddb_streams.values():
            if stream["StreamArn"] == stream_arn:
                # get stream details
                dynamodb = connect_to().dynamodb
                table_name = table_name_from_stream_arn(stream["StreamArn"])
                stream_name = get_kinesis_stream_name(table_name)
                stream_details = kinesis.describe_stream(StreamName=stream_name)
                table_details = dynamodb.describe_table(TableName=table_name)
                stream["KeySchema"] = table_details["Table"]["KeySchema"]
                stream["StreamStatus"] = STREAM_STATUS_MAP.get(
                    stream_details["StreamDescription"]["StreamStatus"]
                )

                # Replace Kinesis ShardIDs with ones that mimic actual
                # DynamoDBStream ShardIDs.
                stream_shards = copy.deepcopy(stream_details["StreamDescription"]["Shards"])
                start_index = 0
                for index, shard in enumerate(stream_shards):
                    shard["ShardId"] = get_shard_id(stream, shard["ShardId"])
                    shard.pop("HashKeyRange", None)
                    # we want to ignore the shards before exclusive_start_shard_id parameters
                    # we store the index where we encounter then slice the shards
                    if exclusive_start_shard_id and exclusive_start_shard_id == shard["ShardId"]:
                        start_index = index

                if exclusive_start_shard_id:
                    # slicing the resulting shards after the exclusive_start_shard_id parameters
                    stream_shards = stream_shards[start_index + 1 :]

                stream["Shards"] = stream_shards
                stream_description = select_from_typed_dict(StreamDescription, stream)
                return DescribeStreamOutput(StreamDescription=stream_description)

        raise ResourceNotFoundException(f"Stream {stream_arn} was not found.")

    @handler("GetRecords", expand=False)
    def get_records(self, context: RequestContext, payload: GetRecordsInput) -> GetRecordsOutput:
        kinesis = connect_to().kinesis
        prefix, _, payload["ShardIterator"] = payload["ShardIterator"].rpartition("|")
        try:
            kinesis_records = kinesis.get_records(**payload)
        except kinesis.exceptions.ExpiredIteratorException:
            LOG.debug("Shard iterator for underlying kinesis stream expired")
            raise ExpiredIteratorException("Shard iterator has expired")
        result = {
            "Records": [],
            "NextShardIterator": f"{prefix}|{kinesis_records.get('NextShardIterator')}",
        }
        for record in kinesis_records["Records"]:
            record_data = loads(record["Data"])
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
        kinesis = connect_to().kinesis

        kwargs = {"StartingSequenceNumber": sequence_number} if sequence_number else {}
        result = kinesis.get_shard_iterator(
            StreamName=stream_name,
            ShardId=stream_shard_id,
            ShardIteratorType=shard_iterator_type,
            **kwargs,
        )
        del result["ResponseMetadata"]
        # TODO not quite clear what the |1| exactly denotes, because at AWS it's sometimes other numbers
        result["ShardIterator"] = f"{stream_arn}|1|{result['ShardIterator']}"
        return GetShardIteratorOutput(**result)

    def list_streams(
        self,
        context: RequestContext,
        table_name: TableName = None,
        limit: PositiveIntegerObject = None,
        exclusive_start_stream_arn: StreamArn = None,
    ) -> ListStreamsOutput:
        store = get_dynamodbstreams_store(context.account_id, context.region)
        result = [select_from_typed_dict(Stream, res) for res in store.ddb_streams.values()]
        return ListStreamsOutput(Streams=result)
