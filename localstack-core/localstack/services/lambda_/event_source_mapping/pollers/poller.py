import json
import logging
from abc import ABC, abstractmethod
from typing import Any

from botocore.client import BaseClient

from localstack import config
from localstack.aws.api.pipes import PipeStateReason
from localstack.services.events.event_ruler import matches_rule

# TODO remove when we switch to Java rule engine
from localstack.services.events.v1.utils import matches_event
from localstack.services.lambda_.event_source_mapping.event_processor import EventProcessor
from localstack.services.lambda_.event_source_mapping.noops_event_processor import (
    NoOpsEventProcessor,
)
from localstack.services.lambda_.event_source_mapping.pipe_utils import get_internal_client
from localstack.utils.aws.arns import parse_arn


class PipeStateReasonValues(PipeStateReason):
    USER_INITIATED = "USER_INITIATED"
    NO_RECORDS_PROCESSED = "No records processed"
    # TODO: add others (e.g., failure)


POLL_INTERVAL_SEC: float = 1

LOG = logging.getLogger(__name__)


class Poller(ABC):
    source_arn: str | None
    aws_region: str | None
    source_parameters: dict
    filter_patterns: list[dict[str, Any]]
    source_client: BaseClient

    # Target processor (e.g., Pipe, EventSourceMapping)
    processor: EventProcessor

    def __init__(
        self,
        source_arn: str | None = None,
        source_parameters: dict | None = None,
        source_client: BaseClient | None = None,
        processor: EventProcessor | None = None,
    ):
        # TODO: handle pollers without an ARN (e.g., Apache Kafka)
        if source_arn:
            self.source_arn = source_arn
            self.aws_region = parse_arn(source_arn)["region"]
            self.source_client = source_client or get_internal_client(source_arn)

        self.source_parameters = source_parameters or {}
        filters = self.source_parameters.get("FilterCriteria", {}).get("Filters", [])
        self.filter_patterns = [json.loads(event_filter["Pattern"]) for event_filter in filters]

        # Target processor
        self.processor = processor or NoOpsEventProcessor()

    @abstractmethod
    def event_source(self) -> str:
        """Return the event source metadata (e.g., aws:sqs)"""
        pass

    @abstractmethod
    def poll_events(self) -> None:
        """Poll events polled from the event source and matching at least one filter criteria and invoke the target processor."""
        pass

    def close(self) -> None:
        """Closes a target poller alongside all associated internal polling/consuming clients.
        Only implemented for supported pollers. Therefore, the default implementation is empty."""
        pass

    def send_events_to_dlq(self, events, context) -> None:
        """Send failed events to a DLQ configured on the source.
        Only implemented for supported pollers. Therefore, the default implementation is empty."""
        pass

    def filter_events(self, events: list[dict]) -> list[dict]:
        """Filter events using the EventBridge event patterns:
        https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html"""
        if len(self.filter_patterns) == 0:
            return events

        filtered_events = []
        for event in events:
            # TODO: add try/catch with default discard and error log for extra resilience
            if any(_matches_event(pattern, event) for pattern in self.filter_patterns):
                filtered_events.append(event)
        return filtered_events

    def add_source_metadata(self, events: list[dict], extra_metadata=None) -> list[dict]:
        """Add event source metadata to each event for eventSource, eventSourceARN, and awsRegion.
        This metadata is added after filtering: https://repost.aws/knowledge-center/eventbridge-filter-events-with-pipes
        See "The following fields can't be used in event patterns":
        https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html
        """
        for event in events:
            event["eventSourceARN"] = self.source_arn
            event["eventSource"] = self.event_source()
            event["awsRegion"] = self.aws_region
            event.update(self.extra_metadata())
        return events

    def extra_metadata(self) -> dict:
        """Default implementation that subclasses can override to customize"""
        return {}


def _matches_event(event_pattern: dict, event: dict) -> bool:
    if config.EVENT_RULE_ENGINE == "java":
        event_str = json.dumps(event)
        event_pattern_str = json.dumps(event_pattern)
        return matches_rule(event_str, event_pattern_str)
    else:
        return matches_event(event_pattern, event)


def has_batch_item_failures(
    result: dict | str | None, valid_item_ids: set[str] | None = None
) -> bool:
    """Returns False if no batch item failures are present and True otherwise (i.e., including parse exceptions)."""
    # TODO: validate correct behavior upon exceptions
    try:
        failed_items_ids = parse_batch_item_failures(result, valid_item_ids)
        return len(failed_items_ids) > 0
    except (KeyError, ValueError):
        return True


def get_batch_item_failures(
    result: dict | str | None, valid_item_ids: set[str] | None = None
) -> list[str] | None:
    """
    Returns a list of failed batch item IDs. If an empty list is returned, then the batch should be considered as a complete success.

    If `None` is returned, the batch should be considered a complete failure.
    """
    try:
        failed_items_ids = parse_batch_item_failures(result, valid_item_ids)
        return failed_items_ids
    except (KeyError, ValueError):
        return None


def parse_batch_item_failures(
    result: dict | str | None, valid_item_ids: set[str] | None = None
) -> list[str]:
    """
    Parses a partial batch failure response, that looks like this: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html

        {
          "batchItemFailures": [
                {
                    "itemIdentifier": "id2"
                },
                {
                    "itemIdentifier": "id4"
                }
            ]
        }

    If the response returns an empty list, then the batch should be considered as a complete success. If an exception
    is raised, the batch should be considered a complete failure.

    Pipes partial batch failure: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html
    Lambda ESM with SQS: https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-errorhandling.html
    Special cases: https://repost.aws/knowledge-center/lambda-sqs-report-batch-item-failures
    Kinesis: https://docs.aws.amazon.com/lambda/latest/dg/services-kinesis-batchfailurereporting.html

    :param result: the process status (e.g., invocation result from Lambda)
    :param valid_item_ids: the set of valid item ids in the batch
    :raises KeyError: if the itemIdentifier value is missing or not in the batch
    :raises Exception: any other exception related to parsing (e.g., JSON parser error)
    :return: a list of item IDs that failed
    """
    if not result:
        return []

    if isinstance(result, dict):
        partial_batch_failure = result
    else:
        partial_batch_failure = json.loads(result)

    if not partial_batch_failure:
        return []

    batch_item_failures = partial_batch_failure.get("batchItemFailures")

    if not batch_item_failures:
        return []

    failed_items = []
    for item in batch_item_failures:
        if "itemIdentifier" not in item:
            raise KeyError(f"missing itemIdentifier in batchItemFailure record {item}")

        item_identifier = item["itemIdentifier"]
        if not item_identifier:
            raise ValueError("itemIdentifier cannot be empty or null")

        # Optionally validate whether the item_identifier is part of the batch
        if valid_item_ids and item_identifier not in valid_item_ids:
            raise KeyError(f"itemIdentifier '{item_identifier}' not in the batch")

        failed_items.append(item_identifier)

    return failed_items
