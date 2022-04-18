from typing import Any, Dict, List

from localstack.services.awslambda.event_source_listeners.stream_event_source_listener import (
    StreamEventSourceListener,
)
from localstack.services.awslambda.lambda_api import get_event_sources
from localstack.utils.aws import aws_stack
from localstack.utils.common import first_char_to_lower


class DynamoDBEventSourceListener(StreamEventSourceListener):
    _FAILURE_PAYLOAD_DETAILS_FIELD_NAME = "DDBStreamBatchInfo"

    @staticmethod
    def source_type() -> str:
        return "dynamodb"

    def _get_matching_event_sources(self) -> List[Dict]:
        event_sources = get_event_sources(source_arn=r".*:dynamodb:.*")
        return [source for source in event_sources if source["State"] == "Enabled"]

    def _get_stream_client(self, region_name):
        return aws_stack.connect_to_service("dynamodbstreams", region_name=region_name)

    def _create_lambda_event_payload(self, stream_arn, records):
        record_payloads = []
        for record in records:
            record_payload = {}
            for key, val in record.items():
                record_payload[first_char_to_lower(key)] = val
            creation_time = record_payload.get("dynamodb", {}).get(
                "ApproximateCreationDateTime", None
            )
            if creation_time is not None:
                record_payload["dynamodb"]["ApproximateCreationDateTime"] = (
                    creation_time.timestamp() * 1000
                )
            record_payloads.append(
                {
                    "eventID": record_payload.pop("eventID"),
                    "eventVersion": "1.0",
                    "awsRegion": aws_stack.get_region(),
                    "eventName": record_payload.pop("eventName"),
                    "eventSourceARN": stream_arn,
                    "eventSource": "aws:dynamodb",
                    "dynamodb": record_payload,
                }
            )
        return {"Records": record_payloads}

    def process_event(self, event: Any):
        raise NotImplementedError
