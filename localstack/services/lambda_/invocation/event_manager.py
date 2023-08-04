import base64
import dataclasses
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from math import ceil

from localstack import config
from localstack.aws.api.lambda_ import TooManyRequestsException
from localstack.aws.connect import connect_to
from localstack.services.lambda_.invocation.lambda_models import (
    INTERNAL_RESOURCE_ACCOUNT,
    EventInvokeConfig,
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


@dataclasses.dataclass
class SQSInvocation:
    invocation: Invocation
    retries: int = 0

    def encode(self) -> str:
        return json.dumps(
            {
                "payload": to_str(base64.b64encode(self.invocation.payload)),
                "invoked_arn": self.invocation.invoked_arn,
                "client_context": self.invocation.client_context,
                "invocation_type": self.invocation.invocation_type,
                "invoke_time": self.invocation.invoke_time.isoformat(),
                # = invocation_id
                "request_id": self.invocation.request_id,
                "retries": self.retries,
            }
        )

    @classmethod
    def decode(cls, message: str) -> "SQSInvocation":
        invocation_dict = json.loads(message)
        invocation = Invocation(
            payload=base64.b64decode(invocation_dict["payload"]),
            invoked_arn=invocation_dict["invoked_arn"],
            client_context=invocation_dict["client_context"],
            invocation_type=invocation_dict["invocation_type"],
            invoke_time=datetime.fromisoformat(invocation_dict["invoke_time"]),
            request_id=invocation_dict["request_id"],
        )
        return cls(invocation, invocation_dict["retries"])


def has_enough_time_for_retry(
    sqs_invocation: SQSInvocation, event_invoke_config: EventInvokeConfig
) -> bool:
    time_passed = datetime.now() - sqs_invocation.invocation.invoke_time
    delay_queue_invoke_seconds = (
        sqs_invocation.retries + 1
    ) * config.LAMBDA_RETRY_BASE_DELAY_SECONDS
    # TODO: test what is the default for maximum_event_age_in_seconds?
    # 6 hours is a guess based on these AWS blogs:
    # https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
    # https://aws.amazon.com/about-aws/whats-new/2019/11/aws-lambda-supports-max-retry-attempts-event-age-asynchronous-invocations/
    # Good summary blogpost: https://haithai91.medium.com/aws-lambdas-retry-behaviors-edff90e1cf1b
    maximum_event_age_in_seconds = 6 * 60 * 60
    if event_invoke_config and event_invoke_config.maximum_event_age_in_seconds is not None:
        maximum_event_age_in_seconds = event_invoke_config.maximum_event_age_in_seconds
    return (
        maximum_event_age_in_seconds
        and ceil(time_passed.total_seconds()) + delay_queue_invoke_seconds
        <= maximum_event_age_in_seconds
    )


class Poller:
    version_manager: LambdaVersionManager
    event_queue_url: str
    _shutdown_event: threading.Event
    invoker_pool: ThreadPoolExecutor

    def __init__(self, version_manager: LambdaVersionManager, event_queue_url: str):
        self.version_manager = version_manager
        self.event_queue_url = event_queue_url
        self._shutdown_event = threading.Event()
        function_id = self.version_manager.function_version.id
        # TODO: think about scaling, test it?!
        self.invoker_pool = ThreadPoolExecutor(
            thread_name_prefix=f"lambda-invoker-{function_id.function_name}:{function_id.qualifier}"
        )

    def run(self):
        try:
            sqs_client = connect_to(aws_access_key_id=INTERNAL_RESOURCE_ACCOUNT).sqs
            function_timeout = self.version_manager.function_version.config.timeout
            while not self._shutdown_event.is_set():
                messages = sqs_client.receive_message(
                    QueueUrl=self.event_queue_url,
                    WaitTimeSeconds=2,
                    # MAYBE: increase number of messages if single thread schedules invocations
                    MaxNumberOfMessages=1,
                    VisibilityTimeout=function_timeout + 60,
                )
                if not messages.get("Messages"):
                    continue
                message = messages["Messages"][0]

                self.invoker_pool.submit(self.handle_message, message)
        except Exception as e:
            LOG.error(
                "Error while polling lambda events %s", e, exc_info=LOG.isEnabledFor(logging.DEBUG)
            )

    def handle_message(self, message: dict) -> None:
        try:
            sqs_invocation = SQSInvocation.decode(message["Body"])
            invocation = sqs_invocation.invocation
            try:
                invocation_result = self.version_manager.invoke(invocation=invocation)
            except TooManyRequestsException as e:  # Throttles 429
                # TODO: handle throttling and internal errors differently as described here:
                #  https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
                # Idea: can reset visibility when re-scheduling necessary (e.g., when hitting concurrency limit)
                # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html#terminating-message-visibility-timeout
                # TODO: differentiate between reserved concurrency = 0 and other throttling errors
                LOG.debug("Throttled lambda %s: %s", self.version_manager.function_arn, e)
                invocation_result = InvocationResult(
                    is_error=True, request_id=invocation.request_id, payload=None, logs=None
                )
            except Exception as e:  # System errors 5xx
                LOG.debug(
                    "Service exception in lambda %s: %s", self.version_manager.function_arn, e
                )
                # TODO: handle this
                invocation_result = InvocationResult(
                    is_error=True, request_id=invocation.request_id, payload=None, logs=None
                )
            finally:
                sqs_client = connect_to(aws_access_key_id=INTERNAL_RESOURCE_ACCOUNT).sqs
                sqs_client.delete_message(
                    QueueUrl=self.event_queue_url, ReceiptHandle=message["ReceiptHandle"]
                )

            # Asynchronous invocation handling: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
            # https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
            max_retry_attempts = 2
            qualifier = self.version_manager.function_version.id.qualifier
            event_invoke_config = self.version_manager.function.event_invoke_configs.get(qualifier)
            if event_invoke_config and event_invoke_config.maximum_retry_attempts is not None:
                max_retry_attempts = event_invoke_config.maximum_retry_attempts

            # An invocation error either leads to a terminal failure or to a scheduled retry
            if invocation_result.is_error:  # invocation error
                failure_cause = None
                # Reserved concurrency == 0
                # TODO: maybe we should not send the invoke at all; testing?!
                if self.version_manager.function.reserved_concurrent_executions == 0:
                    # TODO: replace with constants from spec/model
                    failure_cause = "ZeroReservedConcurrency"
                # Maximum retries exhausted
                elif sqs_invocation.retries >= max_retry_attempts:
                    failure_cause = "RetriesExhausted"
                # TODO: test what happens if max event age expired before it gets scheduled the first time?!
                # Maximum event age expired (lookahead for next retry)
                elif not has_enough_time_for_retry(sqs_invocation, event_invoke_config):
                    failure_cause = "EventAgeExceeded"

                if failure_cause:  # handle failure destination and DLQ
                    self.process_failure_destination(
                        sqs_invocation, invocation_result, event_invoke_config, failure_cause
                    )
                    self.process_dead_letter_queue(sqs_invocation, invocation_result)
                    return
                else:  # schedule retry
                    sqs_invocation.retries += 1
                    # TODO: max delay is 15 minutes! specify max 300 limit in docs
                    #   https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html
                    delay_seconds = sqs_invocation.retries * config.LAMBDA_RETRY_BASE_DELAY_SECONDS
                    sqs_client.send_message(
                        QueueUrl=self.event_queue_url,
                        MessageBody=sqs_invocation.encode(),
                        DelaySeconds=delay_seconds,
                    )
                    return
            else:  # invocation success
                self.process_success_destination(
                    sqs_invocation, invocation_result, event_invoke_config
                )
        except Exception as e:
            LOG.error(
                "Error handling lambda invoke %s", e, exc_info=LOG.isEnabledFor(logging.DEBUG)
            )

    def process_success_destination(
        self,
        sqs_invocation: SQSInvocation,
        invocation_result: InvocationResult,
        event_invoke_config: EventInvokeConfig,
    ):
        LOG.debug("Handling success destination for %s", self.version_manager.function_arn)
        success_destination = event_invoke_config.destination_config.get("OnSuccess", {}).get(
            "Destination"
        )
        if success_destination is None:
            return

        original_payload = sqs_invocation.invocation.payload
        destination_payload = {
            "version": "1.0",
            "timestamp": timestamp_millis(),
            "requestContext": {
                "requestId": invocation_result.request_id,
                "functionArn": self.version_manager.function_version.qualified_arn,
                "condition": "Success",
                "approximateInvokeCount": sqs_invocation.retries + 1,
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

    def process_failure_destination(
        self,
        sqs_invocation: SQSInvocation,
        invocation_result: InvocationResult,
        event_invoke_config: EventInvokeConfig,
        failure_cause: str,
    ):
        LOG.debug("Handling failure destination for %s", self.version_manager.function_arn)
        failure_destination = event_invoke_config.destination_config.get("OnFailure", {}).get(
            "Destination"
        )
        if failure_destination is None:
            return

        original_payload = sqs_invocation.invocation.payload
        destination_payload = {
            "version": "1.0",
            "timestamp": timestamp_millis(),
            "requestContext": {
                "requestId": invocation_result.request_id,
                "functionArn": self.version_manager.function_version.qualified_arn,
                "condition": failure_cause,
                "approximateInvokeCount": sqs_invocation.retries + 1,
            },
            "requestPayload": json.loads(to_str(original_payload)),
        }
        # TODO: should this conditional be based on invocation_result?
        if failure_cause != "ZeroReservedConcurrency":
            destination_payload["responseContext"] = {
                "statusCode": 200,
                "executedVersion": self.version_manager.function_version.id.qualifier,
                "functionError": "Unhandled",
            }
            destination_payload["responsePayload"] = json.loads(to_str(invocation_result.payload))

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

    def process_dead_letter_queue(
        self,
        sqs_invocation: SQSInvocation,
        invocation_result: InvocationResult,
    ):
        LOG.debug("Handling dead letter queue for %s", self.version_manager.function_arn)
        try:
            dead_letter_queue._send_to_dead_letter_queue(
                source_arn=self.version_manager.function_arn,
                dlq_arn=self.version_manager.function_version.config.dead_letter_arn,
                event=json.loads(to_str(sqs_invocation.invocation.payload)),
                error=InvocationException(
                    message="hi", result=to_str(invocation_result.payload)
                ),  # TODO: check message
                role=self.version_manager.function_version.config.role,
            )
        except Exception as e:
            LOG.warning(
                "Error sending invocation result to DLQ %s: %s",
                self.version_manager.function_version.config.dead_letter_arn,
                e,
            )

    def stop(self):
        self._shutdown_event.set()


class LambdaEventManager:
    version_manager: LambdaVersionManager
    event_queue_url: str | None

    def __init__(self, version_manager: LambdaVersionManager):
        self.version_manager = version_manager
        # Poller threads perform the synchronous invocation
        self.poller_threads = ThreadPoolExecutor()
        self.event_queue_url = None

    def enqueue_event(self, invocation: Invocation) -> None:
        message_body = SQSInvocation(invocation).encode()
        sqs_client = connect_to(aws_access_key_id=INTERNAL_RESOURCE_ACCOUNT).sqs
        sqs_client.send_message(QueueUrl=self.event_queue_url, MessageBody=message_body)

    def start(self) -> None:
        sqs_client = connect_to(aws_access_key_id=INTERNAL_RESOURCE_ACCOUNT).sqs
        fn_version_id = self.version_manager.function_version.id
        # Truncate function name to ensure queue name limit of max 80 characters
        function_name_short = fn_version_id.function_name[:47]
        queue_name = f"{function_name_short}-{md5(fn_version_id.qualified_arn())}"
        create_queue_response = sqs_client.create_queue(QueueName=queue_name)
        self.event_queue_url = create_queue_response["QueueUrl"]
        # Ensure no events are in new queues due to persistence and cloud pods
        sqs_client.purge_queue(QueueUrl=self.event_queue_url)

        poller = Poller(self.version_manager, self.event_queue_url)
        # TODO: think about scaling pollers or just run the synchronous invoke in a thread.
        #  Currently we only have one poller per function version and therefore at most 1 concurrent async invocation.
        self.poller_threads.submit(poller.run)

    def stop(self) -> None:
        # TODO: shut down event threads + delete queue
        # TODO: delete queue and test with persistence
        pass
