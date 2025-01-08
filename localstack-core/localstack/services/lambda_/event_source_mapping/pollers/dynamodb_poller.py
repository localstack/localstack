import logging
from datetime import datetime

from botocore.client import BaseClient

from localstack.aws.api.dynamodbstreams import StreamStatus
from localstack.services.lambda_.event_source_mapping.event_processor import (
    EventProcessor,
)
from localstack.services.lambda_.event_source_mapping.pollers.stream_poller import StreamPoller

LOG = logging.getLogger(__name__)


class DynamoDBPoller(StreamPoller):
    def __init__(
        self,
        source_arn: str,
        source_parameters: dict | None = None,
        source_client: BaseClient | None = None,
        processor: EventProcessor | None = None,
        partner_resource_arn: str | None = None,
        esm_uuid: str | None = None,
    ):
        super().__init__(
            source_arn,
            source_parameters,
            source_client,
            processor,
            esm_uuid=esm_uuid,
            partner_resource_arn=partner_resource_arn,
        )

    @property
    def stream_parameters(self) -> dict:
        return self.source_parameters["DynamoDBStreamParameters"]

    def initialize_shards(self):
        # TODO: update upon re-sharding, maybe using a cache and call every time?!
        stream_info = self.source_client.describe_stream(StreamArn=self.source_arn)
        stream_status = stream_info["StreamDescription"]["StreamStatus"]
        if stream_status != StreamStatus.ENABLED:
            LOG.warning(
                "DynamoDB stream %s is not enabled. Current status: %s",
                self.source_arn,
                stream_status,
            )
            return {}

        # NOTICE: re-sharding might require updating this periodically (unknown how Pipes does it!?)
        # Mapping of shard id => shard iterator
        shards = {}
        for shard in stream_info["StreamDescription"]["Shards"]:
            shard_id = shard["ShardId"]
            starting_position = self.stream_parameters["StartingPosition"]
            kwargs = {}
            get_shard_iterator_response = self.source_client.get_shard_iterator(
                StreamArn=self.source_arn,
                ShardId=shard_id,
                ShardIteratorType=starting_position,
                **kwargs,
            )
            shards[shard_id] = get_shard_iterator_response["ShardIterator"]
        return shards

    def stream_arn_param(self) -> dict:
        # Not supported for GetRecords:
        # https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_GetRecords.html
        return {}

    def event_source(self) -> str:
        return "aws:dynamodb"

    def extra_metadata(self) -> dict:
        return {
            "eventVersion": "1.1",
        }

    def transform_into_events(self, records: list[dict], shard_id) -> list[dict]:
        events = []
        for record in records:
            # TODO: consolidate with DynamoDB event source listener:
            #  localstack.services.lambda_.event_source_listeners.dynamodb_event_source_listener.DynamoDBEventSourceListener._create_lambda_event_payload
            dynamodb = record["dynamodb"]

            if creation_time := dynamodb.get("ApproximateCreationDateTime"):
                # Float conversion validated by TestDynamoDBEventSourceMapping.test_dynamodb_event_filter
                dynamodb["ApproximateCreationDateTime"] = float(creation_time.timestamp())
            event = {
                # TODO: add this metadata after filtering (these are based on the original record!)
                #  This requires some design adjustment because the eventId and eventName depend on the record.
                "eventID": record["eventID"],
                "eventName": record["eventName"],
                # record content
                "dynamodb": dynamodb,
            }
            events.append(event)
        return events

    def failure_payload_details_field_name(self) -> str:
        return "DDBStreamBatchInfo"

    def get_approximate_arrival_time(self, record: dict) -> float:
        # TODO: validate whether the default should be now
        # Optional according to AWS docs:
        # https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_StreamRecord.html
        # TODO: parse float properly if present from ApproximateCreationDateTime -> now works, compare via debug!
        return record["dynamodb"].get("todo", datetime.utcnow().timestamp())

    def format_datetime(self, time: datetime) -> str:
        return f"{time.isoformat(timespec='seconds')}Z"

    def get_sequence_number(self, record: dict) -> str:
        return record["dynamodb"]["SequenceNumber"]
