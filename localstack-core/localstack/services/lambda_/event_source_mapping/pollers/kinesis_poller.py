import base64
import logging

from botocore.client import BaseClient

from localstack.aws.api.kinesis import StreamStatus
from localstack.aws.api.pipes import (
    KinesisStreamStartPosition,
)
from localstack.services.lambda_.event_source_mapping.event_processor import EventProcessor
from localstack.services.lambda_.event_source_mapping.pollers.stream_poller import StreamPoller
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)


class KinesisPoller(StreamPoller):
    # The role ARN of the processor (e.g., role ARN of the Pipe)
    invoke_identity_arn: str | None

    def __init__(
        self,
        source_arn: str,
        source_parameters: dict | None = None,
        source_client: BaseClient | None = None,
        processor: EventProcessor | None = None,
        partner_resource_arn: str | None = None,
        invoke_identity_arn: str | None = None,
    ):
        super().__init__(
            source_arn,
            source_parameters,
            source_client,
            processor,
            partner_resource_arn=partner_resource_arn,
        )
        self.invoke_identity_arn = invoke_identity_arn

    @property
    def stream_parameters(self) -> dict:
        return self.source_parameters["KinesisStreamParameters"]

    def initialize_shards(self) -> dict[str, str]:
        # TODO: cache this and update/re-try upon failures
        stream_info = self.source_client.describe_stream(StreamARN=self.source_arn)
        stream_status = stream_info["StreamDescription"]["StreamStatus"]
        if stream_status != StreamStatus.ACTIVE:
            LOG.warning(
                "Stream %s is not active. Current status: %s",
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
            # TODO: test StartingPosition=AT_TIMESTAMP (only supported for Kinesis!)
            if starting_position == KinesisStreamStartPosition.AT_TIMESTAMP:
                kwargs["StartingSequenceNumber"] = self.stream_parameters[
                    "StartingPositionTimestamp"
                ]
            get_shard_iterator_response = self.source_client.get_shard_iterator(
                StreamARN=self.source_arn,
                ShardId=shard_id,
                ShardIteratorType=starting_position,
                **kwargs,
            )
            shards[shard_id] = get_shard_iterator_response["ShardIterator"]
        return shards

    def event_source(self) -> str:
        return "aws:kinesis"

    def extra_metadata(self) -> dict:
        return {
            "eventVersion": "1.0",
            "eventName": "aws:kinesis:record",
            "invokeIdentityArn": self.invoke_identity_arn,
        }

    def transform_into_events(self, records: list[dict], shard_id) -> list[dict]:
        events = []
        for record in records:
            # TODO: consolidate with Kinesis event source listener:
            #  localstack.services.lambda_.event_source_listeners.kinesis_event_source_listener.KinesisEventSourceListener._create_lambda_event_payload
            sequence_number = record["SequenceNumber"]
            event = {
                # TODO: add this metadata after filtering
                "eventID": f"{shard_id}:{sequence_number}",
                # record content
                "kinesisSchemaVersion": "1.0",
                "partitionKey": record["PartitionKey"],
                "sequenceNumber": sequence_number,
                # TODO: implement heuristic based on content type: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html#pipes-filter-sqs
                # boto3 automatically decodes records in get_records(), so we must re-encode
                "data": to_str(base64.b64encode(record["Data"])),
                "approximateArrivalTimestamp": record["ApproximateArrivalTimestamp"].timestamp(),
            }
            events.append(event)
        return events
