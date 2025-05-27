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
from localstack.services.dynamodb.utils import change_region_in_ddb_stream_arn
from localstack.services.dynamodbstreams.dynamodbstreams_api import (
    get_dynamodbstreams_store,
    get_kinesis_client,
    get_kinesis_stream_name,
    get_original_region,
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
    shard_to_region: dict[str, str]
    """Map a shard iterator to the originating region. This is used in case of replica tables, as LocalStack keeps the
    data in one region only, redirecting all the requests from replica regions."""

    def __init__(self):
        self.shard_to_region = {}

    def describe_stream(
        self,
        context: RequestContext,
        stream_arn: StreamArn,
        limit: PositiveIntegerObject = None,
        exclusive_start_shard_id: ShardId = None,
        **kwargs,
    ) -> DescribeStreamOutput:
        og_region = get_original_region(context=context, stream_arn=stream_arn)
        store = get_dynamodbstreams_store(context.account_id, og_region)
        kinesis = get_kinesis_client(account_id=context.account_id, region_name=og_region)
        for stream in store.ddb_streams.values():
            _stream_arn = stream_arn
            if context.region != og_region:
                _stream_arn = change_region_in_ddb_stream_arn(_stream_arn, og_region)
            if stream["StreamArn"] == _stream_arn:
                # get stream details
                dynamodb = connect_to(
                    aws_access_key_id=context.account_id, region_name=og_region
                ).dynamodb
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
                stream_description["StreamArn"] = _stream_arn
                return DescribeStreamOutput(StreamDescription=stream_description)

        raise ResourceNotFoundException(
            f"Requested resource not found: Stream: {stream_arn} not found"
        )

    @handler("GetRecords", expand=False)
    def get_records(self, context: RequestContext, payload: GetRecordsInput) -> GetRecordsOutput:
        _shard_iterator = payload["ShardIterator"]
        region_name = context.region
        if payload["ShardIterator"] in self.shard_to_region:
            region_name = self.shard_to_region[_shard_iterator]

        kinesis = get_kinesis_client(account_id=context.account_id, region_name=region_name)
        prefix, _, payload["ShardIterator"] = _shard_iterator.rpartition("|")
        try:
            kinesis_records = kinesis.get_records(**payload)
        except kinesis.exceptions.ExpiredIteratorException:
            self.shard_to_region.pop(_shard_iterator, None)
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

        # Similar as the logic in GetShardIterator, we need to track the originating region when we get the
        # NextShardIterator in the results.
        if region_name != context.region and "NextShardIterator" in result:
            self.shard_to_region[result["NextShardIterator"]] = region_name
        return GetRecordsOutput(**result)

    def get_shard_iterator(
        self,
        context: RequestContext,
        stream_arn: StreamArn,
        shard_id: ShardId,
        shard_iterator_type: ShardIteratorType,
        sequence_number: SequenceNumber = None,
        **kwargs,
    ) -> GetShardIteratorOutput:
        stream_name = stream_name_from_stream_arn(stream_arn)
        og_region = get_original_region(context=context, stream_arn=stream_arn)
        stream_shard_id = kinesis_shard_id(shard_id)
        kinesis = get_kinesis_client(account_id=context.account_id, region_name=og_region)

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

        # In case of a replica table, we need to keep track of the real region originating the shard iterator.
        # This region will be later used in GetRecords to redirect to the originating region, holding the data.
        if og_region != context.region:
            self.shard_to_region[result["ShardIterator"]] = og_region
        return GetShardIteratorOutput(**result)

    def list_streams(
        self,
        context: RequestContext,
        table_name: TableName = None,
        limit: PositiveIntegerObject = None,
        exclusive_start_stream_arn: StreamArn = None,
        **kwargs,
    ) -> ListStreamsOutput:
        og_region = get_original_region(context=context, table_name=table_name)
        store = get_dynamodbstreams_store(context.account_id, og_region)
        result = [select_from_typed_dict(Stream, res) for res in store.ddb_streams.values()]
        if table_name:
            result: list[Stream] = [res for res in result if res["TableName"] == table_name]
            # If this is a stream from a table replica, we need to change the region in the stream ARN, as LocalStack
            # keeps a stream only in the originating region.
            if context.region != og_region:
                for stream in result:
                    stream["StreamArn"] = change_region_in_ddb_stream_arn(
                        stream["StreamArn"], context.region
                    )

        return ListStreamsOutput(Streams=result)
