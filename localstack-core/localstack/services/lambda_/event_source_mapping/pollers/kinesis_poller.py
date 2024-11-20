import base64
import json
import logging
from copy import deepcopy
from datetime import datetime

from botocore.client import BaseClient

from localstack.aws.api.kinesis import StreamStatus
from localstack.aws.api.pipes import (
    KinesisStreamStartPosition,
)
from localstack.services.lambda_.event_source_mapping.event_processor import (
    EventProcessor,
)
from localstack.services.lambda_.event_source_mapping.pollers.stream_poller import StreamPoller
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)


class KinesisPoller(StreamPoller):
    # The role ARN of the processor (e.g., role ARN of the Pipe)
    invoke_identity_arn: str | None
    # Flag to enable nested kinesis namespace when formatting events to support the nested `kinesis` field structure
    # used for Lambda ESM: https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html#services-kinesis-event-example
    # EventBridge Pipes uses no nesting: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-kinesis.html
    kinesis_namespace: bool

    def __init__(
        self,
        source_arn: str,
        source_parameters: dict | None = None,
        source_client: BaseClient | None = None,
        processor: EventProcessor | None = None,
        partner_resource_arn: str | None = None,
        invoke_identity_arn: str | None = None,
        kinesis_namespace: bool = False,
    ):
        super().__init__(
            source_arn,
            source_parameters,
            source_client,
            processor,
            partner_resource_arn=partner_resource_arn,
        )
        self.invoke_identity_arn = invoke_identity_arn
        self.kinesis_namespace = kinesis_namespace

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

    def stream_arn_param(self) -> dict:
        return {"StreamARN": self.source_arn}

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
            #  check `encryptionType` leading to serialization errors by Dotnet Lambdas
            sequence_number = record["SequenceNumber"]
            event = {
                # TODO: add this metadata after filtering.
                #  This requires some design adjustment because the sequence number depends on the record.
                "eventID": f"{shard_id}:{sequence_number}",
            }
            kinesis_fields = {
                "kinesisSchemaVersion": "1.0",
                "partitionKey": record["PartitionKey"],
                "sequenceNumber": sequence_number,
                # TODO: implement heuristic based on content type: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html#pipes-filter-sqs
                # boto3 automatically decodes records in get_records(), so we must re-encode
                "data": to_str(base64.b64encode(record["Data"])),
                "approximateArrivalTimestamp": record["ApproximateArrivalTimestamp"].timestamp(),
            }
            if self.kinesis_namespace:
                event["kinesis"] = kinesis_fields
            else:
                event.update(kinesis_fields)
            events.append(event)
        return events

    def failure_payload_details_field_name(self) -> str:
        return "KinesisBatchInfo"

    def get_approximate_arrival_time(self, record: dict) -> float:
        if self.kinesis_namespace:
            return record["kinesis"]["approximateArrivalTimestamp"]
        else:
            return record["approximateArrivalTimestamp"]

    def format_datetime(self, time: datetime) -> str:
        return f"{time.isoformat(timespec='milliseconds')}Z"

    def get_sequence_number(self, record: dict) -> str:
        if self.kinesis_namespace:
            return record["kinesis"]["sequenceNumber"]
        else:
            return record["sequenceNumber"]

    def pre_filter(self, events: list[dict]) -> list[dict]:
        # TODO: test what happens with a mixture of data and non-data filters?
        if has_data_filter_criteria_parsed(self.filter_patterns):
            parsed_events = []
            for event in events:
                raw_data = self.get_data(event)
                try:
                    data = self.parse_data(raw_data)
                    # TODO: test "data" key remapping
                    # Filtering remaps "kinesis.data" in ESM to "data (idempotent for Pipes using "data" directly)
                    # ESM: https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis-filtering.html
                    # Pipes: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-kinesis.html
                    # Pipes filtering: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html
                    parsed_event = deepcopy(event)
                    parsed_event["data"] = data

                    parsed_events.append(parsed_event)
                except json.JSONDecodeError:
                    LOG.warning(
                        "Unable to convert event data '%s' to json... Record will be dropped.",
                        raw_data,
                        exc_info=LOG.isEnabledFor(logging.DEBUG),
                    )
            return parsed_events
        else:
            return events

    def post_filter(self, events: list[dict]) -> list[dict]:
        if has_data_filter_criteria_parsed(self.filter_patterns):
            # convert them back (HACK for fixing parity with v1 and getting regression tests passing)
            for event in events:
                parsed_data = event.pop("data")
                encoded_data = self.encode_data(parsed_data)
                self.set_data(event, encoded_data)
        return events

    def get_data(self, event: dict) -> str:
        if self.kinesis_namespace:
            return event["kinesis"]["data"]
        else:
            return event["data"]

    def set_data(self, event: dict, data: bytes) -> None:
        if self.kinesis_namespace:
            event["kinesis"]["data"] = data
        else:
            event["data"] = data

    def parse_data(self, raw_data: str) -> dict | str:
        decoded_data = base64.b64decode(raw_data)
        return json.loads(decoded_data)

    def encode_data(self, parsed_data: dict) -> str:
        return base64.b64encode(json.dumps(parsed_data).encode()).decode()


def has_data_filter_criteria_parsed(parsed_filters: list[dict]) -> bool:
    for filter in parsed_filters:
        if "data" in filter:
            return True
    return False
