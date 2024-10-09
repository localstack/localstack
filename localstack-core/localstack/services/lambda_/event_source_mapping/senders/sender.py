from abc import abstractmethod

from botocore.client import BaseClient

from localstack.services.lambda_.event_source_mapping.pipe_utils import get_internal_client


class SenderError(Exception):
    def __init__(self, message=None, error=None) -> None:
        self.message = message or "Error during sending events"
        self.error = error


class PartialFailureSenderError(SenderError):
    def __init__(self, message=None, error=None, partial_failure_payload=None) -> None:
        self.message = message or "Target invocation failed partially."
        self.error = error
        # Following the partial failure payload structure:
        # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html
        self.partial_failure_payload = partial_failure_payload


class Sender:
    target_arn: str
    target_parameters: dict
    target_client: BaseClient

    def __init__(
        self,
        target_arn: str,
        target_parameters: dict | None = None,
        target_client: BaseClient | None = None,
    ) -> None:
        self.target_arn = target_arn
        self.target_parameters = target_parameters or {}
        self.target_client = target_client or get_internal_client(target_arn)

    # TODO: Can an event also be of type `bytes`?
    @abstractmethod
    def send_events(self, events: list[dict | str]) -> dict | None:
        """Send the given `events` to the target.
        Returns an optional payload with a list of "batchItemFailures" if only part of the batch succeeds.
        """
        pass
