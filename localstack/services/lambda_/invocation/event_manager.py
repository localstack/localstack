import base64
import dataclasses
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from math import ceil

from botocore.config import Config

from localstack import config
from localstack.aws.api.lambda_ import TooManyRequestsException
from localstack.aws.connect import connect_to
from localstack.services.lambda_.invocation.lambda_models import (
    EventInvokeConfig,
    Invocation,
    InvocationResult,
)
from localstack.services.lambda_.invocation.version_manager import LambdaVersionManager
from localstack.services.lambda_.legacy.lambda_executors import InvocationException
from localstack.utils.aws import dead_letter_queue
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.strings import md5, to_str
from localstack.utils.threads import FuncThread
from localstack.utils.time import timestamp_millis

LOG = logging.getLogger(__name__)


def get_sqs_client(function_version, client_config=None):
    region_name = function_version.id.region
    return connect_to(
        aws_access_key_id=config.INTERNAL_RESOURCE_ACCOUNT,
        region_name=region_name,
        config=client_config,
    ).sqs


@dataclasses.dataclass
class SQSInvocation:
    invocation: Invocation
    retries: int = 0
    exception_retries: int = 0

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
                "exception_retries": self.exception_retries,
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
        return cls(
            invocation=invocation,
            retries=invocation_dict["retries"],
            exception_retries=invocation_dict["exception_retries"],
        )


def has_enough_time_for_retry(
    sqs_invocation: SQSInvocation, event_invoke_config: EventInvokeConfig
) -> bool:
    time_passed = datetime.now() - sqs_invocation.invocation.invoke_time
    delay_queue_invoke_seconds = (
        sqs_invocation.retries + 1
    ) * config.LAMBDA_RETRY_BASE_DELAY_SECONDS
    # 6 hours is the default based on these AWS sources:
    # https://repost.aws/questions/QUd214DdOQRkKWr7D8IuSMIw/why-is-aws-lambda-eventinvokeconfig-s-limit-for-maximumretryattempts-2
    # https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
    # https://aws.amazon.com/about-aws/whats-new/2019/11/aws-lambda-supports-max-retry-attempts-event-age-asynchronous-invocations/
    maximum_event_age_in_seconds = 6 * 60 * 60
    if event_invoke_config and event_invoke_config.maximum_event_age_in_seconds is not None:
        maximum_event_age_in_seconds = event_invoke_config.maximum_event_age_in_seconds
    return (
        maximum_event_age_in_seconds
        and ceil(time_passed.total_seconds()) + delay_queue_invoke_seconds
        <= maximum_event_age_in_seconds
    )


CLIENT_CONFIG = Config(
    connect_timeout=1,
    read_timeout=5,
    retries={"max_attempts": 0},
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
        # TODO: think about scaling, test it, make it configurable?!
        self.invoker_pool = ThreadPoolExecutor(
            thread_name_prefix=f"lambda-invoker-{function_id.function_name}:{function_id.qualifier}"
        )

    def run(self, *args, **kwargs):
        try:
            sqs_client = get_sqs_client(
                self.version_manager.function_version, client_config=CLIENT_CONFIG
            )
            function_timeout = self.version_manager.function_version.config.timeout
            while not self._shutdown_event.is_set():
                # TODO: Fix proper shutdown causing EndpointConnectionError
                # https://app.circleci.com/pipelines/github/localstack/localstack/17428/workflows/391fc320-0cec-4dd1-9e3b-d7511de61d12/jobs/132663/parallel-runs/2
                # Test case (happens not every time!):
                # tests.aws.services.cloudformation.resources.test_legacy.TestCloudFormation.test_updating_stack_with_iam_role
                messages = sqs_client.receive_message(
                    QueueUrl=self.event_queue_url,
                    WaitTimeSeconds=2,
                    # TODO: MAYBE: increase number of messages if single thread schedules invocations
                    MaxNumberOfMessages=1,
                    VisibilityTimeout=function_timeout + 60,
                )
                if not messages.get("Messages"):
                    continue
                message = messages["Messages"][0]

                # NOTE: queueing within the thread pool executor could lead to double executions
                #  due to the visibility timeout
                self.invoker_pool.submit(self.handle_message, message)
        except Exception as e:
            # TODO gateway shuts down before shutdown event even is set, so this log message might be sent regardless
            if isinstance(e, ConnectionRefusedError) and self._shutdown_event.is_set():
                return
            # TODO: investigate what causes ReadTimeoutError (fixed with increasing read timeout?)
            LOG.error(
                "Error while polling lambda events for function %s: %s",
                self.version_manager.function_version.qualified_arn,
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )

    def stop(self):
        LOG.debug(
            "Stopping event poller %s %s",
            self.version_manager.function_version.qualified_arn,
            id(self),
        )
        self._shutdown_event.set()
        self.invoker_pool.shutdown(cancel_futures=True, wait=False)

    def handle_message(self, message: dict) -> None:
        failure_cause = None
        qualifier = self.version_manager.function_version.id.qualifier
        event_invoke_config = self.version_manager.function.event_invoke_configs.get(qualifier)
        try:
            sqs_invocation = SQSInvocation.decode(message["Body"])
            invocation = sqs_invocation.invocation
            try:
                invocation_result = self.version_manager.invoke(invocation=invocation)
            except Exception as e:
                # Reserved concurrency == 0
                if self.version_manager.function.reserved_concurrent_executions == 0:
                    failure_cause = "ZeroReservedConcurrency"
                # Maximum event age expired (lookahead for next retry)
                elif not has_enough_time_for_retry(sqs_invocation, event_invoke_config):
                    failure_cause = "EventAgeExceeded"
                if failure_cause:
                    invocation_result = InvocationResult(
                        is_error=True, request_id=invocation.request_id, payload=None, logs=None
                    )
                    self.process_failure_destination(
                        sqs_invocation, invocation_result, event_invoke_config, failure_cause
                    )
                    self.process_dead_letter_queue(sqs_invocation, invocation_result)
                    return
                # 3) Otherwise, retry without increasing counter

                # If the function doesn't have enough concurrency available to process all events, additional
                # requests are throttled. For throttling errors (429) and system errors (500-series), Lambda returns
                # the event to the queue and attempts to run the function again for up to 6 hours. The retry interval
                # increases exponentially from 1 second after the first attempt to a maximum of 5 minutes. If the
                # queue contains many entries, Lambda increases the retry interval and reduces the rate at which it
                # reads events from the queue. Source:
                # https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
                # Difference depending on error cause:
                # https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
                # Troubleshooting 500 errors:
                # https://repost.aws/knowledge-center/lambda-troubleshoot-invoke-error-502-500
                if isinstance(e, TooManyRequestsException):  # Throttles 429
                    LOG.debug("Throttled lambda %s: %s", self.version_manager.function_arn, e)
                else:  # System errors 5xx
                    LOG.debug(
                        "Service exception in lambda %s: %s", self.version_manager.function_arn, e
                    )

                maximum_exception_retry_delay_seconds = 5 * 60
                delay_seconds = min(
                    2**sqs_invocation.exception_retries, maximum_exception_retry_delay_seconds
                )
                # TODO: calculate delay seconds into max event age handling
                sqs_client = get_sqs_client(self.version_manager.function_version)
                sqs_client.send_message(
                    QueueUrl=self.event_queue_url,
                    MessageBody=sqs_invocation.encode(),
                    DelaySeconds=delay_seconds,
                )
                return
            finally:
                sqs_client = get_sqs_client(self.version_manager.function_version)
                sqs_client.delete_message(
                    QueueUrl=self.event_queue_url, ReceiptHandle=message["ReceiptHandle"]
                )

            # Good summary blogpost: https://haithai91.medium.com/aws-lambdas-retry-behaviors-edff90e1cf1b
            # Asynchronous invocation handling: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
            # https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
            max_retry_attempts = 2
            if event_invoke_config and event_invoke_config.maximum_retry_attempts is not None:
                max_retry_attempts = event_invoke_config.maximum_retry_attempts

            # An invocation error either leads to a terminal failure or to a scheduled retry
            if invocation_result.is_error:  # invocation error
                failure_cause = None
                # Reserved concurrency == 0
                if self.version_manager.function.reserved_concurrent_executions == 0:
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
                    # Assumption: We assume that the internal exception retries counter is reset after
                    #  an invocation that does not throw an exception
                    sqs_invocation.exception_retries = 0
                    # LAMBDA_RETRY_BASE_DELAY_SECONDS has a limit of 300s because the maximum SQS DelaySeconds
                    # is 15 minutes (900s) and the maximum retry count is 3. SQS quota for "Message timer":
                    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html
                    delay_seconds = sqs_invocation.retries * config.LAMBDA_RETRY_BASE_DELAY_SECONDS
                    # TODO: max SQS message size limit could break parity with AWS because
                    #  our SQSInvocation contains additional fields! 256kb is max for both Lambda payload + SQS
                    # TODO: write test with max SQS message size
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
        event_invoke_config: EventInvokeConfig | None,
    ) -> None:
        if event_invoke_config is None:
            return
        success_destination = event_invoke_config.destination_config.get("OnSuccess", {}).get(
            "Destination"
        )
        if success_destination is None:
            return
        LOG.debug("Handling success destination for %s", self.version_manager.function_arn)

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
        event_invoke_config: EventInvokeConfig | None,
        failure_cause: str,
    ):
        if event_invoke_config is None:
            return
        failure_destination = event_invoke_config.destination_config.get("OnFailure", {}).get(
            "Destination"
        )
        if failure_destination is None:
            return
        LOG.debug("Handling failure destination for %s", self.version_manager.function_arn)

        original_payload = sqs_invocation.invocation.payload
        if failure_cause == "ZeroReservedConcurrency":
            approximate_invoke_count = sqs_invocation.retries
        else:
            approximate_invoke_count = sqs_invocation.retries + 1
        destination_payload = {
            "version": "1.0",
            "timestamp": timestamp_millis(),
            "requestContext": {
                "requestId": invocation_result.request_id,
                "functionArn": self.version_manager.function_version.qualified_arn,
                "condition": failure_cause,
                "approximateInvokeCount": approximate_invoke_count,
            },
            "requestPayload": json.loads(to_str(original_payload)),
        }
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
                # TODO: Check message. Possibly remove because it is not used in the DLQ message?!
                # TODO: Remove InvocationException import dependency to old provider.
                error=InvocationException(message="hi", result=to_str(invocation_result.payload)),
                role=self.version_manager.function_version.config.role,
            )
        except Exception as e:
            LOG.warning(
                "Error sending invocation result to DLQ %s: %s",
                self.version_manager.function_version.config.dead_letter_arn,
                e,
            )


class LambdaEventManager:
    version_manager: LambdaVersionManager
    poller: Poller | None
    poller_thread: FuncThread | None
    event_queue_url: str | None
    lifecycle_lock: threading.RLock
    stopped: threading.Event

    def __init__(self, version_manager: LambdaVersionManager):
        self.version_manager = version_manager
        self.poller = None
        self.poller_thread = None
        self.event_queue_url = None
        self.lifecycle_lock = threading.RLock()
        self.stopped = threading.Event()

    def enqueue_event(self, invocation: Invocation) -> None:
        message_body = SQSInvocation(invocation).encode()
        sqs_client = get_sqs_client(self.version_manager.function_version)
        try:
            sqs_client.send_message(QueueUrl=self.event_queue_url, MessageBody=message_body)
        except Exception:
            LOG.error(
                f"Failed to enqueue Lambda event into queue {self.event_queue_url}."
                f" Invocation: request_id={invocation.request_id}, invoked_arn={invocation.invoked_arn}",
            )
            raise

    def start(self) -> None:
        LOG.debug(
            "Starting event manager %s id %s",
            self.version_manager.function_version.id.qualified_arn(),
            id(self),
        )
        with self.lifecycle_lock:
            if self.stopped.is_set():
                LOG.debug("Event manager already stopped before started.")
                return
            sqs_client = get_sqs_client(self.version_manager.function_version)
            function_id = self.version_manager.function_version.id
            # Truncate function name to ensure queue name limit of max 80 characters
            function_name_short = function_id.function_name[:47]
            queue_name = f"{function_name_short}-{md5(function_id.qualified_arn())}"
            create_queue_response = sqs_client.create_queue(QueueName=queue_name)
            self.event_queue_url = create_queue_response["QueueUrl"]
            # Ensure no events are in new queues due to persistence and cloud pods
            sqs_client.purge_queue(QueueUrl=self.event_queue_url)

            self.poller = Poller(self.version_manager, self.event_queue_url)
            self.poller_thread = FuncThread(
                self.poller.run,
                name=f"lambda-poller-{function_id.function_name}:{function_id.qualifier}",
            )
            self.poller_thread.start()

    def stop_for_update(self) -> None:
        LOG.debug(
            "Stopping event manager but keep queue %s id %s",
            self.version_manager.function_version.qualified_arn,
            id(self),
        )
        with self.lifecycle_lock:
            if self.stopped.is_set():
                LOG.debug("Event manager already stopped!")
                return
            self.stopped.set()
            if self.poller:
                self.poller.stop()
                self.poller_thread.join(timeout=3)
                LOG.debug("Waited for poller thread %s", self.poller_thread)
                if self.poller_thread.is_alive():
                    LOG.error("Poller did not shutdown %s", self.poller_thread)
                self.poller = None

    def stop(self) -> None:
        LOG.debug(
            "Stopping event manager %s: %s id %s",
            self.version_manager.function_version.qualified_arn,
            self.poller,
            id(self),
        )
        with self.lifecycle_lock:
            if self.stopped.is_set():
                LOG.debug("Event manager already stopped!")
                return
            self.stopped.set()
            if self.poller:
                self.poller.stop()
                self.poller_thread.join(timeout=3)
                LOG.debug("Waited for poller thread %s", self.poller_thread)
                if self.poller_thread.is_alive():
                    LOG.error("Poller did not shutdown %s", self.poller_thread)
                self.poller = None
            if self.event_queue_url:
                sqs_client = get_sqs_client(
                    self.version_manager.function_version, client_config=CLIENT_CONFIG
                )
                sqs_client.delete_queue(QueueUrl=self.event_queue_url)
                self.event_queue_url = None
