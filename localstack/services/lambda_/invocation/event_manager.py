import base64
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

from localstack import config
from localstack.aws.connect import connect_to
from localstack.services.lambda_.invocation.lambda_models import (
    INTERNAL_RESOURCE_ACCOUNT,
    Invocation,
    InvocationResult,
)
from localstack.services.lambda_.invocation.version_manager import LambdaVersionManager
from localstack.services.lambda_.lambda_executors import InvocationException
from localstack.utils.aws import dead_letter_queue
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.strings import md5, to_str
from localstack.utils.time import timestamp_millis

LOG = logging.getLogger(__name__)


def encode_invocation(invocation: Invocation) -> str:
    return json.dumps(
        {
            "payload": to_str(base64.b64encode(invocation.payload)),
            "invoked_arn": invocation.invoked_arn,
            "client_context": invocation.client_context,
            "invocation_type": invocation.invocation_type,
            "invoke_time": invocation.invoke_time.isoformat(),
            # = invocation_id
            "request_id": invocation.request_id,
        }
    )


def decode_invocation(message: str) -> Invocation:
    invocation_dict = json.loads(message)
    return Invocation(
        payload=base64.b64decode(invocation_dict["payload"]),
        invoked_arn=invocation_dict["invoked_arn"],
        client_context=invocation_dict["client_context"],
        invocation_type=invocation_dict["invocation_type"],
        invoke_time=datetime.fromisoformat(invocation_dict["invoke_time"]),
        request_id=invocation_dict["request_id"],
    )


class Poller:
    version_manager: LambdaVersionManager
    event_queue_url: str
    _shutdown_event: threading.Event

    def __init__(self, version_manager: LambdaVersionManager, event_queue_url: str):
        self.version_manager = version_manager
        self.event_queue_url = event_queue_url
        self._shutdown_event = threading.Event()

    def run(self):
        sqs_client = connect_to(aws_access_key_id=INTERNAL_RESOURCE_ACCOUNT).sqs
        function_timeout = self.version_manager.function_version.config.timeout
        while not self._shutdown_event.is_set():
            messages = sqs_client.receive_message(
                QueueUrl=self.event_queue_url,
                WaitTimeSeconds=2,
                MaxNumberOfMessages=1,
                VisibilityTimeout=function_timeout + 60,
            )
            if not messages["Messages"]:
                continue
            message = messages["Messages"][0]
            invocation = decode_invocation(message["Body"])
            invocation_result = self.version_manager.invoke(invocation=invocation)
            LOG.debug(invocation_result)

            sqs_client.delete_message(
                QueueUrl=self.event_queue_url, ReceiptHandle=message["ReceiptHandle"]
            )

            # TODO: handle destinations
            # if not invocation_result.is_error:
            #     # success_destination(invocation_result)
            #     continue

            # TODO: handle different error cases. Behavior depends on error type:
            # https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
            # if retry < 2:
            #     time.sleep((retry + 1) * config.LAMBDA_RETRY_BASE_DELAY_SECONDS)
            # else:
            #     # TODO: failure destination
            #     self.process_failure_destination(invocation, invocation_result)
            #     return

    def stop(self):
        self._shutdown_event.set()


class LambdaEventManager:
    version_manager: LambdaVersionManager
    event_queue_url: str | None

    def __init__(self, version_manager: LambdaVersionManager):
        self.version_manager = version_manager
        # event threads perform the synchronous invocation
        self.event_threads = ThreadPoolExecutor()
        self.event_queue_url = None

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

    def process_success_destination(self):
        # TODO: implement this (i.e., logic from process_event_destinations)
        pass

    def process_failure_destination(
        self, invocation: Invocation, invocation_result: InvocationResult
    ):
        try:
            dead_letter_queue._send_to_dead_letter_queue(
                source_arn=self.version_manager.function_arn,
                dlq_arn=self.version_manager.function_version.config.dead_letter_arn,
                event=json.loads(to_str(invocation.payload)),
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

    def invoke(self, invocation: Invocation):
        # TODO: decouple this => will be replaced with queue-based architecture
        # TODO: this can block for quite a long time if there's no available capacity
        for retry in range(3):
            # TODO: check max event age before invocation
            invocation_result = self.version_manager.invoke(invocation=invocation)

            # TODO destinations
            if not invocation_result.is_error:
                # TODO: success destination
                # success_destination(invocation_result)
                return

            if retry < 2:
                time.sleep((retry + 1) * config.LAMBDA_RETRY_BASE_DELAY_SECONDS)
            else:
                # TODO: failure destination
                self.process_failure_destination(invocation, invocation_result)
                return

    def enqueue_event(self, invocation: Invocation) -> None:
        # NOTE: something goes wrong with the custom encoder; infinite loop?
        message = encode_invocation(invocation)
        sqs_client = connect_to(aws_access_key_id=INTERNAL_RESOURCE_ACCOUNT).sqs
        sqs_client.send_message(QueueUrl=self.event_queue_url, MessageBody=message)
        # TODO: remove this old threads impl.
        # self.event_threads.submit(self.invoke, invocation)

    def start(self) -> None:
        sqs_client = connect_to(aws_access_key_id=INTERNAL_RESOURCE_ACCOUNT).sqs
        fn_version_id = self.version_manager.function_version.id
        # Truncate function name to ensure queue name limit of max 80 characters
        function_name_short = fn_version_id.function_name[:47]
        queue_name = f"{function_name_short}-{md5(fn_version_id.qualified_arn())}"
        create_queue_response = sqs_client.create_queue(QueueName=queue_name)
        self.event_queue_url = create_queue_response["QueueUrl"]

        # TODO: start poller thread + implement poller
        poller = Poller(self.version_manager, self.event_queue_url)
        self.event_threads.submit(poller.run)

    #     Set a limit for now, think about scaling later (because of sync invoke!)

    def stop(self) -> None:
        # TODO: shut down event threads + delete queue
        pass
