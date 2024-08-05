import base64
import datetime
import json
import logging
from copy import deepcopy
from typing import Dict, List, Optional

from localstack.services.lambda_.event_source_listeners.stream_event_source_listener import (
    StreamEventSourceListener,
)
from localstack.services.lambda_.event_source_listeners.utils import (
    filter_stream_records,
    has_data_filter_criteria,
)
from localstack.utils.aws.arns import (
    extract_account_id_from_arn,
    extract_region_from_arn,
    get_partition,
)
from localstack.utils.common import first_char_to_lower, to_str
from localstack.utils.threads import FuncThread

LOG = logging.getLogger(__name__)


class KinesisEventSourceListener(StreamEventSourceListener):
    _FAILURE_PAYLOAD_DETAILS_FIELD_NAME = "KinesisBatchInfo"
    _COORDINATOR_THREAD: Optional[FuncThread] = (
        None  # Thread for monitoring state of event source mappings
    )
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

    def _filter_records(
        self, records: List[Dict], event_filter_criterias: List[Dict]
    ) -> List[Dict]:
        """
        https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html
        - Parse data as json if any data filter pattern present.
        - Drop record if unable to parse.
        - When filtering, the key has to be "data"
        """
        if len(records) == 0:
            return []

        if len(event_filter_criterias) == 0:
            return records

        if not has_data_filter_criteria(event_filter_criterias):
            # Lambda filters (on the other metadata properties only) based on your filter criteria.
            return filter_stream_records(records, event_filter_criterias)

        parsed_records = []
        for record in records:
            raw_data = record["data"]
            try:
                # filters expect dict
                parsed_data = json.loads(raw_data)

                # remap "data" key for filtering
                parsed_record = deepcopy(record)
                parsed_record["data"] = parsed_data

                parsed_records.append(parsed_record)
            except json.JSONDecodeError:
                LOG.warning(
                    f"Unable to convert record '{raw_data}' to json... Record will be dropped.",
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )

        filtered_records = filter_stream_records(parsed_records, event_filter_criterias)

        # convert data back to bytes and remap key  (why remap???)
        for filtered_record in filtered_records:
            parsed_data = filtered_record.pop("data")
            encoded_data = json.dumps(parsed_data).encode()
            filtered_record["data"] = encoded_data

        return filtered_records

    def _create_lambda_event_payload(
        self, stream_arn: str, record_payloads: list[dict], shard_id: Optional[str] = None
    ) -> dict:
        records = []
        account_id = extract_account_id_from_arn(stream_arn)
        region = extract_region_from_arn(stream_arn)
        partition = get_partition(region)
        for record_payload in record_payloads:
            records.append(
                {
                    "eventID": "{0}:{1}".format(shard_id, record_payload["sequenceNumber"]),
                    "eventSourceARN": stream_arn,
                    "eventSource": "aws:kinesis",
                    "eventVersion": "1.0",
                    "eventName": "aws:kinesis:record",
                    "invokeIdentityArn": f"arn:{partition}:iam::{account_id}:role/lambda-role",
                    "awsRegion": region,
                    "kinesis": {
                        **record_payload,
                        # boto3 automatically decodes records in get_records(), so we must re-encode
                        "data": to_str(base64.b64encode(record_payload["data"])),
                        "kinesisSchemaVersion": "1.0",
                    },
                }
            )
        return {"Records": records}

    def _get_starting_and_ending_sequence_numbers(self, first_record, last_record):
        return first_record["sequenceNumber"], last_record["sequenceNumber"]

    def _get_first_and_last_arrival_time(self, first_record, last_record):
        return (
            datetime.datetime.fromtimestamp(first_record["approximateArrivalTimestamp"]).isoformat()
            + "Z",
            datetime.datetime.fromtimestamp(last_record["approximateArrivalTimestamp"]).isoformat()
            + "Z",
        )

    def _transform_records(self, raw_records: list[dict]) -> list[dict]:
        """some, e.g. kinesis have to transform the incoming records (e.g. lowercasing of keys)"""
        record_payloads = []
        for record in raw_records:
            record_payload = {}
            for key, val in record.items():
                record_payload[first_char_to_lower(key)] = val
            # convert datetime obj to timestamp
            # AWS requires millisecond precision, but the timestamp has to be in seconds with the milliseconds
            # represented by the fraction part of the float
            record_payload["approximateArrivalTimestamp"] = record_payload[
                "approximateArrivalTimestamp"
            ].timestamp()
            # this record should not be present in the payload. Cannot be deserialized by dotnet lambdas, for example
            # FIXME remove once it is clear if kinesis should not return this value in the first place
            record_payload.pop("encryptionType", None)
            record_payloads.append(record_payload)
        return record_payloads
