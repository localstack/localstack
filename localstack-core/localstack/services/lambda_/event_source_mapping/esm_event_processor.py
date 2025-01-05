import json
import logging
import uuid

from localstack.aws.api.pipes import LogLevel
from localstack.services.lambda_.event_source_mapping.event_processor import (
    BatchFailureError,
    EventProcessor,
    PartialBatchFailureError,
)
from localstack.services.lambda_.event_source_mapping.pipe_loggers.pipe_logger import PipeLogger
from localstack.services.lambda_.event_source_mapping.pipe_utils import to_json_str
from localstack.services.lambda_.event_source_mapping.senders.sender import (
    PartialFailureSenderError,
    Sender,
    SenderError,
)
from localstack.services.lambda_.usage import esm_error, esm_invocation

LOG = logging.getLogger(__name__)


class EsmEventProcessor(EventProcessor):
    sender: Sender
    logger: PipeLogger

    def __init__(self, sender, logger):
        self.sender = sender
        self.logger = logger

    def process_events_batch(self, input_events: list[dict] | dict) -> None:
        # analytics
        if isinstance(input_events, list) and input_events:
            first_event = input_events[0]
        elif input_events:
            first_event = input_events
        else:
            first_event = {}
        event_source = first_event.get("eventSource")
        esm_invocation.record(event_source)

        execution_id = uuid.uuid4()
        # Create a copy of the original input events
        events = input_events.copy()
        try:
            self.logger.set_fields(executionId=str(execution_id))
            self.logger.log(
                messageType="ExecutionStarted",
                logLevel=LogLevel.INFO,
                payload=to_json_str(events),
            )
            # An execution is only triggered upon successful polling. Therefore, `PollingStageStarted` never occurs.
            self.logger.log(
                messageType="PollingStageSucceeded",
                logLevel=LogLevel.TRACE,
            )
            # Target Stage
            self.process_target_stage(events)
            self.logger.log(
                messageType="ExecutionSucceeded",
                logLevel=LogLevel.INFO,
            )
        except PartialFailureSenderError as e:
            self.logger.log(
                messageType="ExecutionFailed",
                logLevel=LogLevel.ERROR,
                error=e.error,
            )
            # TODO: check whether partial batch item failures is enabled by default or need to be explicitly enabled
            #  using --function-response-types "ReportBatchItemFailures"
            #  https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-errorhandling.html
            raise PartialBatchFailureError(
                partial_failure_payload=e.partial_failure_payload, error=e.error
            ) from e
        except SenderError as e:
            self.logger.log(
                messageType="ExecutionFailed",
                logLevel=LogLevel.ERROR,
                error=e.error,
            )
            raise BatchFailureError(error=e.error) from e
        except Exception as e:
            esm_error.record(event_source)
            LOG.error(
                "Unhandled exception while processing Lambda event source mapping (ESM) events %s for ESM with execution id %s",
                events,
                execution_id,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            raise e

    def process_target_stage(self, events: list[dict]) -> None:
        try:
            self.logger.log(
                messageType="TargetStageEntered",
                logLevel=LogLevel.INFO,
            )
            # 2) Deliver to target in batches
            try:
                self.logger.log(
                    messageType="TargetInvocationStarted",
                    logLevel=LogLevel.TRACE,
                )
                # TODO: handle and log target invocation + stage skipped (when no records present)
                payload = self.sender.send_events(events)
                if payload:
                    # TODO: test unserializable content (e.g., byte strings)
                    payload = json.dumps(payload)
                else:
                    payload = ""
                self.logger.log(
                    messageType="TargetInvocationSucceeded",
                    logLevel=LogLevel.TRACE,
                )
            except PartialFailureSenderError as e:
                self.logger.log(
                    messageType="TargetInvocationPartiallyFailed",
                    logLevel=LogLevel.ERROR,
                    error=e.error,
                )
                raise e
            except SenderError as e:
                self.logger.log(
                    messageType="TargetInvocationFailed",
                    logLevel=LogLevel.ERROR,
                    error=e.error,
                )
                raise e
            self.logger.log(
                messageType="TargetStageSucceeded",
                logLevel=LogLevel.INFO,
                payload=payload,
            )
        except PartialFailureSenderError as e:
            self.logger.log(
                messageType="TargetStagePartiallyFailed",
                logLevel=LogLevel.ERROR,
                error=e.error,
            )
            raise e
        except SenderError as e:
            self.logger.log(
                messageType="TargetStageFailed",
                logLevel=LogLevel.ERROR,
                error=e.error,
            )
            raise e

    def generate_event_failure_context(self, abort_condition: str, **kwargs) -> dict:
        error_payload: dict = kwargs.get("error")
        if not error_payload:
            return {}
        # TODO: Should 'requestContext' and 'responseContext' be defined as models?
        context = {
            "requestContext": {
                "requestId": error_payload.get("requestId"),
                "functionArn": self.sender.target_arn,  # get the target ARN from the sender (always LambdaSender)
                "condition": abort_condition,
                "approximateInvokeCount": kwargs.get("attempts_count"),
            },
            "responseContext": {
                "statusCode": error_payload.get("httpStatusCode"),
                "executedVersion": error_payload.get("executedVersion"),
                "functionError": error_payload.get("functionError"),
            },
        }

        return context
