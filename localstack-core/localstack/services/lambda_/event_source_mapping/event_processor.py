from abc import ABC, abstractmethod
from typing import TypedDict


class EventProcessorError(Exception):
    pass


class BatchFailureError(EventProcessorError):
    """The entire batch failed."""

    pass


class PartialFailurePayload(TypedDict, total=False):
    """Following the partial failure payload structure defined by AWS:
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html
    Special cases: https://repost.aws/knowledge-center/lambda-sqs-report-batch-item-failures
    """

    batchItemFailures: list[dict[str, str]]


class PartialBatchFailureError(EventProcessorError):
    """A part of the batch failed."""

    def __init__(
        self,
        partial_failure_payload: PartialFailurePayload | None = None,
    ) -> None:
        self.partial_failure_payload = partial_failure_payload


class EventProcessor(ABC):
    """Interface for event processors such as Event Source Mapping or Pipes that process batches of events."""

    @abstractmethod
    def process_events_batch(self, input_events: list[dict]) -> None:
        """Processes a batch of `input_events`.
        Throws an error upon full or partial batch failure.
        """
