import json
import logging
import uuid

from localstack_ext.aws.api.pipes import LogLevel
from localstack_ext.services.pipes.enrichers.enricher import EnricherException
from localstack_ext.services.pipes.pipe_loggers.pipe_logger import PipeLogger
from localstack_ext.services.pipes.processor import Processor
from localstack_ext.services.pipes.senders.sender import (
    PartialFailureSenderException,
    Sender,
    SenderException,
)

LOG = logging.getLogger(__name__)


class EventSourceMappingProcessor(Processor):
    sender: Sender
    logger: PipeLogger

    def __init__(self, sender, logger):
        self.sender = sender
        self.logger = logger

    def process_events_batch(self, input_events: list[dict]) -> list[dict]:
        execution_id = uuid.uuid4()
        # Create a copy of the original input events
        events = input_events.copy()
        try:
            self.logger.set_fields(executionId=str(execution_id))
            self.logger.log(
                messageType="ExecutionStarted",
                logLevel=LogLevel.INFO,
                payload=json.dumps(events),
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
            return []
        except PartialFailureSenderException as e:
            self.logger.log(
                messageType="ExecutionFailed",
                logLevel=LogLevel.ERROR,
                # TODO: add awsRequest and awsResponse if `IncludeExecutionData` is enabled
                error=e.error,
            )
            return e.partial_failure_payload
        except (EnricherException, SenderException) as e:
            self.logger.log(
                messageType="ExecutionFailed",
                logLevel=LogLevel.ERROR,
                # TODO: add awsRequest and awsResponse if `IncludeExecutionData` is enabled
                error=e.error,
            )
            raise e
        except Exception as e:
            LOG.error(
                "Error while handling Lambda event source mapping (ESM) events %s for ESM with execution id %s",
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
                    payload = json.dumps(payload)
                else:
                    payload = ""
                self.logger.log(
                    messageType="TargetInvocationSucceeded",
                    logLevel=LogLevel.TRACE,
                    # TODO: add awsRequest and awsResponse if `IncludeExecutionData` is enabled
                )
            except PartialFailureSenderException as e:
                self.logger.log(
                    messageType="TargetInvocationPartiallyFailed",
                    logLevel=LogLevel.ERROR,
                    # TODO: add awsRequest and awsResponse if `IncludeExecutionData` is enabled
                    error=e.error,
                )
                raise e
            except SenderException as e:
                self.logger.log(
                    messageType="TargetInvocationFailed",
                    logLevel=LogLevel.ERROR,
                    # TODO: add awsRequest and awsResponse if `IncludeExecutionData` is enabled
                    error=e.error,
                )
                raise e
            self.logger.log(
                messageType="TargetStageSucceeded",
                logLevel=LogLevel.INFO,
                payload=payload,
            )
        except PartialFailureSenderException as e:
            self.logger.log(
                messageType="TargetStagePartiallyFailed",
                logLevel=LogLevel.ERROR,
                # TODO: add awsRequest and awsResponse if `IncludeExecutionData` is enabled
                error=e.error,
            )
            raise e
        except SenderException as e:
            self.logger.log(
                messageType="TargetStageFailed",
                logLevel=LogLevel.ERROR,
                # TODO: add awsRequest and awsResponse if `IncludeExecutionData` is enabled
                error=e.error,
            )
            raise e
