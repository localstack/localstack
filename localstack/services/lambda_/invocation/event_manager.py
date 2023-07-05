import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from math import ceil
from typing import Optional

from localstack import config
from localstack.services.lambda_.invocation.lambda_models import Invocation, InvocationResult
from localstack.services.lambda_.invocation.version_manager import LambdaVersionManager
from localstack.services.lambda_.lambda_executors import InvocationException
from localstack.utils.aws import dead_letter_queue
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.strings import to_str
from localstack.utils.time import timestamp_millis

LOG = logging.getLogger(__name__)


class LambdaEventManager:
    version_manager: LambdaVersionManager

    def __init__(self, version_manager: LambdaVersionManager):
        self.version_manager = version_manager
        self.event_threads = ThreadPoolExecutor()

    def process_event_destinations(
        self,
        invocation_result: InvocationResult,
        invocation: Invocation,
        last_invoke_time: Optional[datetime],
        original_payload: bytes,
        retries: int,
    ) -> None:
        """TODO refactor"""
        LOG.debug("Got event invocation with id %s", invocation_result.request_id)

        # 1. Handle DLQ routing
        if invocation_result.is_error and self.function_version.config.dead_letter_arn:
            try:
                dead_letter_queue._send_to_dead_letter_queue(
                    source_arn=self.version_manager.function_arn,
                    dlq_arn=self.version_manager.function_version.config.dead_letter_arn,
                    event=json.loads(to_str(original_payload)),
                    error=InvocationException(
                        message="hi", result=to_str(invocation_result.payload)
                    ),  # TODO: check message
                    role=self.version_manager.function_version.config.role,
                )
            except Exception as e:
                LOG.warning(
                    "Error sending to DLQ %s: %s",
                    self.version_manager.function_version.config.dead_letter_arn,
                    e,
                )

        # 2. Handle actual destination setup
        event_invoke_config = self.version_manager.function.event_invoke_configs.get(
            self.version_manager.function_version.id.qualifier
        )

        if event_invoke_config is None:
            return

        if not invocation_result.is_error:
            LOG.debug("Handling success destination for %s", self.version_manager.function_arn)
            success_destination = event_invoke_config.destination_config.get("OnSuccess", {}).get(
                "Destination"
            )
            if success_destination is None:
                return
            destination_payload = {
                "version": "1.0",
                "timestamp": timestamp_millis(),
                "requestContext": {
                    "requestId": invocation_result.request_id,
                    "functionArn": self.version_manager.function_version.qualified_arn,
                    "condition": "Success",
                    "approximateInvokeCount": retries + 1,
                },
                "requestPayload": json.loads(to_str(original_payload)),
                "responseContext": {
                    "statusCode": 200,
                    "executedVersion": self.version_manager.function_version.id.qualifier,
                },
                "responsePayload": json.loads(to_str(invocation_result.payload or {})),
            }

            target_arn = event_invoke_config.destination_config["OnSuccess"]["Destination"]
            try:
                send_event_to_target(
                    target_arn=target_arn,
                    event=destination_payload,
                    role=self.version_manager.function_version.config.role,
                    source_arn=self.version_manager.function_version.id.unqualified_arn(),
                    source_service="lambda",
                )
            except Exception as e:
                LOG.warning("Error sending invocation result to %s: %s", target_arn, e)

        else:
            LOG.debug("Handling error destination for %s", self.version_manager.function_arn)

            failure_destination = event_invoke_config.destination_config.get("OnFailure", {}).get(
                "Destination"
            )

            max_retry_attempts = event_invoke_config.maximum_retry_attempts
            if max_retry_attempts is None:
                max_retry_attempts = 2  # default
            previous_retry_attempts = retries

            if self.version_manager.function.reserved_concurrent_executions == 0:
                failure_cause = "ZeroReservedConcurrency"
                response_payload = None
                response_context = None
                approx_invoke_count = 0
            else:
                if max_retry_attempts > 0 and max_retry_attempts > previous_retry_attempts:
                    # delay_queue_invoke_seconds = config.LAMBDA_RETRY_BASE_DELAY_SECONDS * (
                    #     previous_retry_attempts + 1
                    # )

                    # time_passed = datetime.now() - last_invoke_time
                    # enough_time_for_retry = (
                    #     event_invoke_config.maximum_event_age_in_seconds
                    #     and ceil(time_passed.total_seconds()) + delay_queue_invoke_seconds
                    #     <= event_invoke_config.maximum_event_age_in_seconds
                    # )

                    # if (
                    #     event_invoke_config.maximum_event_age_in_seconds is None
                    #     or enough_time_for_retry
                    # ):
                    #     time.sleep(delay_queue_invoke_seconds)
                    #     LOG.debug("Retrying lambda invocation for %s", self.version_manager.function_arn)
                    #     self.invoke(
                    #         invocation=invocation,
                    #         current_retry=previous_retry_attempts + 1,
                    #     )
                    #     return

                    failure_cause = "EventAgeExceeded"
                else:
                    failure_cause = "RetriesExhausted"

                response_payload = json.loads(to_str(invocation_result.payload))
                response_context = {
                    "statusCode": 200,
                    "executedVersion": self.version_manager.function_version.id.qualifier,
                    "functionError": "Unhandled",
                }
                approx_invoke_count = previous_retry_attempts + 1

            if failure_destination is None:
                return

            destination_payload = {
                "version": "1.0",
                "timestamp": timestamp_millis(),
                "requestContext": {
                    "requestId": invocation_result.request_id,
                    "functionArn": self.version_manager.function_version.qualified_arn,
                    "condition": failure_cause,
                    "approximateInvokeCount": approx_invoke_count,
                },
                "requestPayload": json.loads(to_str(original_payload)),
            }

            if response_context:
                destination_payload["responseContext"] = response_context
            if response_payload:
                destination_payload["responsePayload"] = response_payload

            target_arn = event_invoke_config.destination_config["OnFailure"]["Destination"]
            try:
                send_event_to_target(
                    target_arn=target_arn,
                    event=destination_payload,
                    role=self.version_manager.function_version.config.role,
                    source_arn=self.version_manager.function_version.id.unqualified_arn(),
                    source_service="lambda",
                )
            except Exception as e:
                LOG.warning("Error sending invocation result to %s: %s", target_arn, e)

    def invoke(self, invocation: Invocation):
        for retry in range(3):
            invocation_result = self.version_manager.invoke(invocation=invocation)
            # TODO destinations
            if not invocation_result.is_error:
                return
            if retry != 2:
                time.sleep((retry + 1) * 60)

    def enqueue_event(self, invocation: Invocation) -> None:
        self.event_threads.submit(self.invoke, invocation)

    def stop(self) -> None:
        pass
