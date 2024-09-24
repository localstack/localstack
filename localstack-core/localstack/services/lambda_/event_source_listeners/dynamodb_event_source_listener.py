import datetime
from typing import Dict, List, Optional

from localstack.services.lambda_.event_source_listeners.stream_event_source_listener import (
    StreamEventSourceListener,
)
from localstack.services.lambda_.event_source_listeners.utils import filter_stream_records
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.threads import FuncThread


class DynamoDBEventSourceListener(StreamEventSourceListener):
    _FAILURE_PAYLOAD_DETAILS_FIELD_NAME = "DDBStreamBatchInfo"
    _COORDINATOR_THREAD: Optional[FuncThread] = (
        None  # Thread for monitoring state of event source mappings
    )
    _STREAM_LISTENER_THREADS: Dict[
        str, FuncThread
    ] = {}  # Threads for listening to stream shards and forwarding data to mapped Lambdas

    @staticmethod
    def source_type() -> Optional[str]:
        return "dynamodb"

    def _get_matching_event_sources(self) -> List[Dict]:
        event_sources = self._invoke_adapter.get_event_sources(source_arn=r".*:dynamodb:.*")
        return [source for source in event_sources if source["State"] == "Enabled"]

    def _get_stream_client(self, function_arn: str, region_name: str):
        return self._invoke_adapter.get_client_factory(
            function_arn=function_arn, region_name=region_name
        ).dynamodbstreams.request_metadata(source_arn=function_arn)

    def _get_stream_description(self, stream_client, stream_arn):
        return stream_client.describe_stream(StreamArn=stream_arn)["StreamDescription"]

    def _get_shard_iterator(self, stream_client, stream_arn, shard_id, iterator_type):
        return stream_client.get_shard_iterator(
            StreamArn=stream_arn, ShardId=shard_id, ShardIteratorType=iterator_type
        )["ShardIterator"]

    def _filter_records(
        self, records: List[Dict], event_filter_criterias: List[Dict]
    ) -> List[Dict]:
        if len(event_filter_criterias) == 0:
            return records

        return filter_stream_records(records, event_filter_criterias)

    def _create_lambda_event_payload(self, stream_arn, records, shard_id=None):
        record_payloads = []
        for record in records:
            record_payloads.append(
                {
                    "eventID": record["eventID"],
                    "eventVersion": "1.0",
                    "awsRegion": extract_region_from_arn(stream_arn),
                    "eventName": record["eventName"],
                    "eventSourceARN": stream_arn,
                    "eventSource": "aws:dynamodb",
                    "dynamodb": record["dynamodb"],
                }
            )
        return {"Records": record_payloads}

    def _get_starting_and_ending_sequence_numbers(self, first_record, last_record):
        return first_record["dynamodb"]["SequenceNumber"], last_record["dynamodb"]["SequenceNumber"]

    def _get_first_and_last_arrival_time(self, first_record, last_record):
        return (
            first_record.get("ApproximateArrivalTimestamp", datetime.datetime.utcnow()).isoformat()
            + "Z",
            last_record.get("ApproximateArrivalTimestamp", datetime.datetime.utcnow()).isoformat()
            + "Z",
        )

    def _transform_records(self, raw_records: list[dict]) -> list[dict]:
        """Convert dynamodb.ApproximateCreationDateTime datetime to float"""
        records_new = []
        for record in raw_records:
            record_new = record.copy()
            if creation_time := record.get("dynamodb", {}).get("ApproximateCreationDateTime"):
                # convert datetime object to float timestamp
                record_new["dynamodb"]["ApproximateCreationDateTime"] = creation_time.timestamp()
            records_new.append(record_new)
        return records_new
