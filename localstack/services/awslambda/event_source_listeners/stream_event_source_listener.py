import datetime
import math
import threading
import time
from typing import Any, Dict, List, Optional

from localstack import config
from localstack.services.awslambda import lambda_executors
from localstack.services.awslambda.event_source_listeners.event_source_listener import (
    EventSourceListener,
)
from localstack.services.awslambda.lambda_api import LOG, run_lambda
from localstack.services.awslambda.lambda_executors import InvocationResult
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.common import long_uid, timestamp_millis
from localstack.utils.threads import FuncThread


class StreamEventSourceListener(EventSourceListener):
    _COORDINATOR_THREAD: Optional[
        FuncThread
    ] = None  # Thread for monitoring state of event source mappings
    _STREAM_LISTENER_THREADS: Dict[
        str, FuncThread
    ] = {}  # Threads for listening to stream shards and forwarding data to mapped Lambdas
    _POLL_INTERVAL_SEC: float = 1
    _FAILURE_PAYLOAD_DETAILS_FIELD_NAME = ""  # To be defined by inheriting classes

    @staticmethod
    def source_type() -> str:
        # to be implemented by inheriting classes
        raise NotImplementedError

    def _get_matching_event_sources(self) -> List[Dict]:
        # to be implemented by inheriting classes
        raise NotImplementedError

    def _get_stream_client(self, region_name: str):
        # to be implemented by inheriting classes
        raise NotImplementedError

    def _create_lambda_event_payload(self, stream_arn, records):
        # to be implemented by inheriting classes
        raise NotImplementedError

    def _get_starting_and_ending_sequence_numbers(self, first_record, last_record):
        return first_record["dynamodb"]["SequenceNumber"], last_record["dynamodb"]["SequenceNumber"]

    def _get_first_and_last_arrival_time(self, first_record, last_record):
        return (
            first_record.get("ApproximateArrivalTimestamp", datetime.datetime.utcnow()),
            last_record.get("ApproximateArrivalTimestamp", datetime.datetime.utcnow()),
        )

    def process_event(self, event: Any):
        # to be (optionally) implemented by inheriting classes
        raise NotImplementedError

    def start(self):
        if self._COORDINATOR_THREAD is not None:
            return

        LOG.debug(f"Starting {self.source_type()} event source listener coordinator thread")
        self._COORDINATOR_THREAD = FuncThread(self._monitor_stream_event_sources)
        self._COORDINATOR_THREAD.start()

    def _invoke_lambda(self, function_arn, payload, lock_discriminator, parallelization_factor):
        if not config.SYNCHRONOUS_KINESIS_EVENTS:
            lambda_executors.LAMBDA_ASYNC_LOCKS.assure_lock_present(
                lock_discriminator, threading.BoundedSemaphore(parallelization_factor)
            )
        else:
            lock_discriminator = None

        result = run_lambda(
            func_arn=function_arn,
            event=payload,
            context={},
            asynchronous=not config.SYNCHRONOUS_KINESIS_EVENTS,
            lock_discriminator=lock_discriminator,
        )
        if isinstance(result, InvocationResult):
            status_code = getattr(result.result, "status_code", 0)
            if status_code >= 400:
                return False, status_code
            return True, status_code
        return False, 500

    def _listen_to_shard_and_invoke_lambda(self, params):
        # TODO: These values will never get updated if the event source mapping configuration changes :(
        function_arn = params["function_arn"]
        stream_arn = params["stream_arn"]
        batch_size = params["batch_size"]
        parallelization_factor = params["parallelization_factor"]
        lock_discriminator = params["lock_discriminator"]
        shard_id = params["shard_id"]
        stream_client = params["stream_client"]
        shard_iterator = params["shard_iterator"]
        failure_destination = params["failure_destination"]
        max_num_retries = params["max_num_retries"]
        num_invocation_failures = 0

        while lock_discriminator in self._STREAM_LISTENER_THREADS:
            records_response = stream_client.get_records(
                ShardIterator=shard_iterator, Limit=batch_size
            )
            records = records_response.get("Records")
            should_get_next_batch = True
            if records:
                payload = self._create_lambda_event_payload(stream_arn, records)
                is_invocation_successful, status_code = self._invoke_lambda(
                    function_arn, payload, lock_discriminator, parallelization_factor
                )
                if is_invocation_successful:
                    should_get_next_batch = True
                else:
                    num_invocation_failures += 1
                    if num_invocation_failures >= max_num_retries:
                        should_get_next_batch = True
                        if failure_destination:
                            first_rec = records[0]
                            last_rec = records[-1]
                            (
                                first_seq_num,
                                last_seq_num,
                            ) = self._get_starting_and_ending_sequence_numbers(first_rec, last_rec)
                            (
                                first_arrival_time,
                                last_arrival_time,
                            ) = self._get_first_and_last_arrival_time(first_rec, last_rec)
                            self._send_to_failure_destination(
                                shard_id,
                                first_seq_num,
                                last_seq_num,
                                stream_arn,
                                function_arn,
                                num_invocation_failures,
                                status_code,
                                batch_size,
                                first_arrival_time,
                                last_arrival_time,
                                failure_destination,
                            )
                    else:
                        should_get_next_batch = False
            if should_get_next_batch:
                shard_iterator = records_response["NextShardIterator"]
                num_invocation_failures = 0
            time.sleep(self._POLL_INTERVAL_SEC)

    def _send_to_failure_destination(
        self,
        shard_id,
        start_sequence_num,
        end_sequence_num,
        source_arn,
        func_arn,
        invoke_count,
        status_code,
        batch_size,
        first_record_arrival_time,
        last_record_arrival_time,
        destination,
    ):
        payload = {
            "version": "1.0",
            "timestamp": timestamp_millis(),
            "requestContext": {
                "requestId": long_uid(),
                "functionArn": func_arn,
                "condition": "RetryAttemptsExhausted",
                "approximateInvokeCount": invoke_count,
            },
            "responseContext": {
                "statusCode": status_code,
                "executedVersion": "$LATEST",  # TODO: don't hardcode these fields
                "functionError": "Unhandled",
            },
        }
        details = {
            "shardId": shard_id,
            "startSequenceNumber": start_sequence_num,
            "endSequenceNumber": end_sequence_num,
            "approximateArrivalOfFirstRecord": first_record_arrival_time.isoformat() + "Z",
            "approximateArrivalOfLastRecord": last_record_arrival_time.isoformat() + "Z",
            "batchSize": batch_size,
            "streamArn": source_arn,
        }
        payload[self._FAILURE_PAYLOAD_DETAILS_FIELD_NAME] = details
        send_event_to_target(destination, payload)

    def _monitor_stream_event_sources(self, *args):
        while True:
            try:
                # current set of streams + shard IDs that should be feeding Lambda functions based on event sources
                mapped_shard_ids = set()
                sources = self._get_matching_event_sources()
                if not sources:
                    # Temporarily disable polling if no event sources are configured
                    # anymore. The loop will get restarted next time a record
                    # arrives and if an event source is configured.
                    self._COORDINATOR_THREAD = None
                    for thread_id in self._STREAM_LISTENER_THREADS:
                        self._STREAM_LISTENER_THREADS.pop(thread_id)
                    return

                # make sure each event source dynamodb stream has a lambda listening on each of its shards
                for source in sources:
                    stream_arn = source["EventSourceArn"]
                    region_name = stream_arn.split(":")[3]
                    stream_client = self._get_stream_client(region_name)
                    batch_size = max(min(source.get("BatchSize", 1), 10), 1)
                    failure_destination = (
                        source.get("DestinationConfig", {})
                        .get("OnFailure", {})
                        .get("Destination", None)
                    )
                    max_num_retries = source.get("MaximumRetryAttempts", -1)
                    if max_num_retries < 0:
                        max_num_retries = math.inf
                    stream_description = stream_client.describe_stream(StreamArn=stream_arn)[
                        "StreamDescription"
                    ]
                    if stream_description["StreamStatus"] not in {"ENABLED", "ACTIVE"}:
                        continue
                    shard_ids = [shard["ShardId"] for shard in stream_description["Shards"]]

                    for shard_id in shard_ids:
                        lock_discriminator = f"{stream_arn}/{shard_id}"
                        mapped_shard_ids.add(lock_discriminator)
                        if lock_discriminator not in self._STREAM_LISTENER_THREADS:
                            shard_iterator = stream_client.get_shard_iterator(
                                StreamArn=stream_arn,
                                ShardId=shard_id,
                                ShardIteratorType=source["StartingPosition"],
                            )["ShardIterator"]
                            listener_thread = FuncThread(
                                self._listen_to_shard_and_invoke_lambda,
                                {
                                    "function_arn": source["FunctionArn"],
                                    "stream_arn": stream_arn,
                                    "batch_size": batch_size,
                                    "parallelization_factor": source["ParallelizationFactor"],
                                    "lock_discriminator": lock_discriminator,
                                    "shard_id": shard_id,
                                    "stream_client": stream_client,
                                    "shard_iterator": shard_iterator,
                                    "failure_destination": failure_destination,
                                    "max_num_retries": max_num_retries,
                                },
                            )
                            self._STREAM_LISTENER_THREADS[lock_discriminator] = listener_thread
                            listener_thread.start()

                # stop any threads that are listening to a previously defined event source that no longer exists
                orphaned_threads = set(self._STREAM_LISTENER_THREADS.keys()) - mapped_shard_ids
                for thread_id in orphaned_threads:
                    self._STREAM_LISTENER_THREADS.pop(thread_id)

            except Exception as e:
                LOG.error(e)
            time.sleep(self._POLL_INTERVAL_SEC)
