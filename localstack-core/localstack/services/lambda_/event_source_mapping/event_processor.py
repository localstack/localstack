from abc import ABC, abstractmethod
from typing import TypedDict


class EventProcessorError(Exception):
    pass


class PipeInternalError(EventProcessorError):
    """Errors caused by an internal event processor implementation such as Pipes or Lambda ESM.
    Examples: connection error to target service, transient availability issue, implementation error
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-error-troubleshooting.html#eb-pipes-error-invoke
    """

    pass


class CustomerInvocationError(EventProcessorError):
    """Errors caused by customers due to configuration or code errors.
    Examples: insufficient permissions, logic error in synchronously invoked Lambda target.
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-error-troubleshooting.html#eb-pipes-error-invoke
    """

    pass


class BatchFailureError(EventProcessorError):
    """The entire batch failed."""

    def __init__(self, error=None) -> None:
        self.error = error


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
        error=None,
    ) -> None:
        self.error = error
        self.partial_failure_payload = partial_failure_payload


class EventProcessor(ABC):
    """Interface for event processors such as Event Source Mapping or Pipes that process batches of events."""

    @abstractmethod
    def process_events_batch(self, input_events: list[dict]) -> None:
        """Processes a batch of `input_events`.
        Throws an error upon full or partial batch failure.
        """

    @abstractmethod
    def generate_event_failure_context(self, abort_condition: str, **kwargs) -> dict:
        """
        Generates a context object for a failed event processing invocation.

        This method is used to create a standardized failure context for both
        event source mapping and pipes processing scenarios. The resulting
        context will be passed to a Dead Letter Queue (DLQ).
        """
        pass
