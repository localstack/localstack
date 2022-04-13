import base64
import math
import threading
import time
from typing import Any, Dict, List, Optional

from localstack import config, constants
from localstack.services.awslambda import lambda_executors
from localstack.services.awslambda.event_source_listeners.event_source_listener import (
    EventSourceListener,
)
from localstack.services.awslambda.lambda_api import LOG, get_event_sources, run_lambda
from localstack.services.awslambda.lambda_executors import InvocationResult
from localstack.utils.aws import aws_stack
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.common import first_char_to_lower, long_uid, timestamp_millis, to_str
from localstack.utils.threads import FuncThread


class EventSourceListenerKinesis(EventSourceListener):
    # Kinesis listener thread settings
    COORDINATOR_THREAD: Optional[
        FuncThread
    ] = None  # Thread for monitoring state of event source mappings
    KINESIS_LISTENER_THREADS: Dict[
        str, FuncThread
    ] = {}  # Threads for listening to stream shards and forwarding data to mapped Lambdas
    KINESIS_POLL_INTERVAL_SEC: float = 1

    @staticmethod
    def source_type() -> str:
        return "kinesis"

    def start(self):
        if self.COORDINATOR_THREAD is not None:
            return

        LOG.debug("Starting Kinesis coordinator thread for Lambda API")
        self.COORDINATOR_THREAD = FuncThread(self._monitor_kinesis_event_sources)
        self.COORDINATOR_THREAD.start()

    def get_matching_event_sources(self) -> List[Dict]:
        event_sources = get_event_sources(source_arn=r".*:kinesis:.*")
        return [source for source in event_sources if source["State"] == "Enabled"]

    def process_event(self, event: Any):
        raise NotImplementedError

    def _create_lambda_event_payload(self, stream_arn, shard_id, records):
        record_payloads = []
        for record in records:
            record_payload = {}
            for key, val in record.items():
                record_payload[first_char_to_lower(key)] = val
            # boto3 automatically decodes records in get_records(), so we must re-encode
            record_payload["data"] = to_str(base64.b64encode(record_payload["data"]))
            # convert datetime obj to timestamp
            record_payload["approximateArrivalTimestamp"] = (
                record_payload["approximateArrivalTimestamp"].timestamp() * 1000
            )
            record_payloads.append(
                {
                    "eventID": "{0}:{1}".format(shard_id, record_payload["sequenceNumber"]),
                    "eventSourceARN": stream_arn,
                    "eventSource": "aws:kinesis",
                    "eventVersion": "1.0",
                    "eventName": "aws:kinesis:record",
                    "invokeIdentityArn": "arn:aws:iam::{0}:role/lambda-role".format(
                        constants.TEST_AWS_ACCOUNT_ID
                    ),  # TODO: is this the correct value to use?
                    "awsRegion": aws_stack.get_region(),
                    "kinesis": record_payload,
                }
            )
        return {"Records": record_payloads}

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
        kinesis_client = params["kinesis_client"]
        shard_iterator = params["shard_iterator"]
        failure_destination = params["failure_destination"]
        max_num_retries = params["max_num_retries"]
        num_invocation_failures = 0

        while lock_discriminator in self.KINESIS_LISTENER_THREADS:
            records_response = kinesis_client.get_records(
                ShardIterator=shard_iterator, Limit=batch_size
            )
            records = records_response.get("Records")
            should_get_next_batch = True
            if records:
                payload = self._create_lambda_event_payload(stream_arn, shard_id, records)
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
                            self._send_to_failure_destination(
                                shard_id,
                                first_rec["SequenceNumber"],
                                last_rec["SequenceNumber"],
                                stream_arn,
                                function_arn,
                                num_invocation_failures,
                                status_code,
                                batch_size,
                                first_rec["ApproximateArrivalTimestamp"],
                                last_rec["ApproximateArrivalTimestamp"],
                                failure_destination,
                            )
                    else:
                        should_get_next_batch = False
            if should_get_next_batch:
                shard_iterator = records_response["NextShardIterator"]
                num_invocation_failures = 0
            time.sleep(self.KINESIS_POLL_INTERVAL_SEC)

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
            "approximateArrivalOfFirstRecord": timestamp_millis(first_record_arrival_time),
            "approximateArrivalOfLastRecord": timestamp_millis(last_record_arrival_time),
            "batchSize": batch_size,
            "streamArn": source_arn,
        }
        payload["KinesisBatchInfo"] = details
        send_event_to_target(destination, payload)

    def _monitor_kinesis_event_sources(self, *args):
        while True:
            try:
                # current set of streams + shard IDs that should be feeding Lambda functions based on event sources
                mapped_shard_ids = set()
                sources = self.get_matching_event_sources()
                if not sources:
                    # Temporarily disable polling if no event sources are configured
                    # anymore. The loop will get restarted next time a record
                    # arrives and if an event source is configured.
                    self.COORDINATOR_THREAD = None
                    for thread_id in self.KINESIS_LISTENER_THREADS:
                        self.KINESIS_LISTENER_THREADS.pop(thread_id)
                    return

                # make sure each event source kinesis stream has a lambda listening on each of its shards
                for source in sources:
                    stream_arn = source["EventSourceArn"]
                    stream_name = aws_stack.kinesis_stream_name(stream_arn)
                    region_name = stream_arn.split(":")[3]
                    kinesis_client = aws_stack.connect_to_service(
                        "kinesis", region_name=region_name
                    )
                    batch_size = max(min(source.get("BatchSize", 1), 10), 1)
                    failure_destination = (
                        source.get("DestinationConfig", {})
                        .get("OnFailure", {})
                        .get("Destination", None)
                    )
                    max_num_retries = source.get("MaximumRetryAttempts", -1)
                    if max_num_retries < 0:
                        max_num_retries = math.inf
                    shard_ids = [
                        shard["ShardId"]
                        for shard in kinesis_client.describe_stream(StreamName=stream_name)[
                            "StreamDescription"
                        ]["Shards"]
                    ]

                    for shard_id in shard_ids:
                        lock_discriminator = f"{stream_arn}/{shard_id}"
                        mapped_shard_ids.add(lock_discriminator)
                        if lock_discriminator not in self.KINESIS_LISTENER_THREADS:
                            shard_iterator = kinesis_client.get_shard_iterator(
                                StreamName=stream_name,
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
                                    "kinesis_client": kinesis_client,
                                    "shard_iterator": shard_iterator,
                                    "failure_destination": failure_destination,
                                    "max_num_retries": max_num_retries,
                                },
                            )
                            self.KINESIS_LISTENER_THREADS[lock_discriminator] = listener_thread
                            listener_thread.start()

                # stop any lambda threads that are listening to a previously defined event source that no longer exists
                orphaned_threads = set(self.KINESIS_LISTENER_THREADS.keys()) - mapped_shard_ids
                for thread_id in orphaned_threads:
                    self.KINESIS_LISTENER_THREADS.pop(thread_id)

            except Exception as e:
                # TODO
                LOG.error(e)
                raise e

            time.sleep(self.KINESIS_POLL_INTERVAL_SEC)
