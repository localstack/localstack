import base64
from typing import Dict, List, Optional

from localstack.aws.accounts import get_aws_account_id
from localstack.services.lambda_.event_source_listeners.stream_event_source_listener import (
    StreamEventSourceListener,
)
from localstack.utils.aws import aws_stack
from localstack.utils.common import first_char_to_lower, to_str
from localstack.utils.threads import FuncThread


class KinesisEventSourceListener(StreamEventSourceListener):
    _FAILURE_PAYLOAD_DETAILS_FIELD_NAME = "KinesisBatchInfo"
    _COORDINATOR_THREAD: Optional[
        FuncThread
    ] = None  # Thread for monitoring state of event source mappings
    _STREAM_LISTENER_THREADS: Dict[
        str, FuncThread
    ] = {}  # Threads for listening to stream shards and forwarding data to mapped Lambdas

    @staticmethod
    def source_type() -> Optional[str]:
        return "kinesis"

    def _get_matching_event_sources(self) -> List[Dict]:
        event_sources = self._invoke_adapter.get_event_sources(source_arn=r".*:kinesis:.*")
        return [source for source in event_sources if source["State"] == "Enabled"]

    def _get_stream_client(self, function_arn: str, region_name: str):
        return self._invoke_adapter.get_client_factory(
            function_arn=function_arn, region_name=region_name
        ).kinesis.request_metadata(source_arn=function_arn)

    def _get_stream_description(self, stream_client, stream_arn):
        stream_name = stream_arn.split("/")[-1]
        return stream_client.describe_stream(StreamName=stream_name)["StreamDescription"]

    def _get_shard_iterator(self, stream_client, stream_arn, shard_id, iterator_type):
        stream_name = stream_arn.split("/")[-1]
        return stream_client.get_shard_iterator(
            StreamName=stream_name, ShardId=shard_id, ShardIteratorType=iterator_type
        )["ShardIterator"]

    def _create_lambda_event_payload(self, stream_arn, records, shard_id=None):
        record_payloads = []
        for record in records:
            record_payload = {}
            for key, val in record.items():
                record_payload[first_char_to_lower(key)] = val
            # boto3 automatically decodes records in get_records(), so we must re-encode
            record_payload["data"] = to_str(base64.b64encode(record_payload["data"]))
            # convert datetime obj to timestamp
            # AWS requires millisecond precision, but the timestamp has to be in seconds with the milliseconds
            # represented by the fraction part of the float
            record_payload["approximateArrivalTimestamp"] = record_payload[
                "approximateArrivalTimestamp"
            ].timestamp()
            # this record should not be present in the payload. Cannot be deserialized by dotnet lambdas, for example
            # FIXME remove once it is clear if kinesis should not return this value in the first place
            record_payload.pop("encryptionType", None)
            record_payloads.append(
                {
                    "eventID": "{0}:{1}".format(shard_id, record_payload["sequenceNumber"]),
                    "eventSourceARN": stream_arn,
                    "eventSource": "aws:kinesis",
                    "eventVersion": "1.0",
                    "eventName": "aws:kinesis:record",
                    "invokeIdentityArn": f"arn:aws:iam::{get_aws_account_id()}:role/lambda-role",
                    "awsRegion": aws_stack.get_region(),
                    "kinesis": record_payload,
                }
            )
        return {"Records": record_payloads}

    def _get_starting_and_ending_sequence_numbers(self, first_record, last_record):
        return first_record["SequenceNumber"], last_record["SequenceNumber"]

    def _get_first_and_last_arrival_time(self, first_record, last_record):
        return (
            first_record["ApproximateArrivalTimestamp"].isoformat() + "Z",
            last_record["ApproximateArrivalTimestamp"].isoformat() + "Z",
        )
