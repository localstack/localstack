import logging
import math
import time
from typing import Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import InvocationType
from localstack.services.awslambda.event_source_listeners.adapters import (
    EventSourceAdapter,
    EventSourceLegacyAdapter,
)
from localstack.services.awslambda.event_source_listeners.event_source_listener import (
    EventSourceListener,
)
from localstack.services.awslambda.lambda_utils import filter_stream_records
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.common import long_uid, timestamp_millis
from localstack.utils.threads import FuncThread

LOG = logging.getLogger(__name__)

monitor_counter = 0
counter = 0


class StreamEventSourceListener(EventSourceListener):
    """
    Abstract class for listening to streams associated with event source mappings, batching data from those streams,
    and invoking the appropriate Lambda functions with those data batches.
    Because DynamoDB Streams and Kinesis Streams have similar but different APIs, this abstract class is useful for
    reducing repeated code. The various methods that must be implemented by inheriting subclasses essentially wrap
    client API methods or middleware-style operations on data payloads to compensate for the minor differences between
    these two services.
    """

    _COORDINATOR_THREAD: Optional[
        FuncThread
    ] = None  # Thread for monitoring state of event source mappings
    _STREAM_LISTENER_THREADS: Dict[
        str, FuncThread
    ] = {}  # Threads for listening to stream shards and forwarding data to mapped Lambdas
    _POLL_INTERVAL_SEC: float = 1
    _FAILURE_PAYLOAD_DETAILS_FIELD_NAME = ""  # To be defined by inheriting classes
    _invoke_adapter: EventSourceAdapter

    @staticmethod
    def source_type() -> Optional[str]:
        """
        to be implemented by subclasses
        :returns: The type of event source this listener is associated with
        """
        # to be implemented by inheriting classes
        return None

    def _get_matching_event_sources(self) -> List[Dict]:
        """
        to be implemented by subclasses
        :returns: A list of active Event Source Mapping objects (as dicts) that match the listener type
        """
        raise NotImplementedError

    def _get_stream_client(self, function_arn: str, region_name: str):
        """
        to be implemented by subclasses
        :returns: An AWS service client instance for communicating with the appropriate API
        """
        raise NotImplementedError

    def _get_stream_description(self, stream_client, stream_arn):
        """
        to be implemented by subclasses
        :returns: The stream description object returned by the client's describe_stream method
        """
        raise NotImplementedError

    def _get_shard_iterator(self, stream_client, stream_arn, shard_id, iterator_type):
        """
        to be implemented by subclasses
        :returns: The shard iterator object returned by the client's get_shard_iterator method
        """
        raise NotImplementedError

    def _create_lambda_event_payload(
        self, stream_arn: str, records: List[Dict], shard_id: Optional[str] = None
    ) -> Dict:
        """
        to be implemented by subclasses
        Get an event payload for invoking a Lambda function using the given records and stream metadata
        :param stream_arn: ARN of the event source stream
        :param records: Batch of records to include in the payload, obtained from the source stream
        :param shard_id: ID of the shard the records came from. This is only needed for Kinesis event payloads.
        :returns: An event payload suitable for invoking a Lambda function
        """
        raise NotImplementedError

    def _get_starting_and_ending_sequence_numbers(
        self, first_record: Dict, last_record: Dict
    ) -> Tuple[str, str]:
        """
        to be implemented by subclasses
        :returns: the SequenceNumber field values from the given records
        """
        raise NotImplementedError

    def _get_first_and_last_arrival_time(
        self, first_record: Dict, last_record: Dict
    ) -> Tuple[str, str]:
        """
        to be implemented by subclasses
        :returns: the timestamps the given records were created/entered the source stream in iso8601 format
        """
        raise NotImplementedError

    def start(self, invoke_adapter: Optional[EventSourceAdapter] = None):
        """
        Spawn coordinator thread for listening to relevant new/removed event source mappings
        """
        global counter
        if self._COORDINATOR_THREAD is not None:
            return

        LOG.debug(f"Starting {self.source_type()} event source listener coordinator thread")
        self._invoke_adapter = invoke_adapter or EventSourceLegacyAdapter()
        counter += 1
        self._COORDINATOR_THREAD = FuncThread(
            self._monitor_stream_event_sources, name=f"stream-listener-{counter}"
        )
        self._COORDINATOR_THREAD.start()

    # TODO: remove lock_discriminator and parallelization_factor old lambda provider is gone
    def _invoke_lambda(
        self, function_arn, payload, lock_discriminator, parallelization_factor
    ) -> Tuple[bool, int]:
        """
        invoke a given lambda function
        :returns: True if the invocation was successful (False otherwise) and the status code of the invocation result

        # TODO: rework this to properly invoke a lambda through the API. Needs additional restructuring upstream of this function as well.
        """

        status_code = self._invoke_adapter.invoke_with_statuscode(
            function_arn=function_arn,
            payload=payload,
            invocation_type=InvocationType.RequestResponse,
            context={},
            lock_discriminator=lock_discriminator,
            parallelization_factor=parallelization_factor,
        )

        if status_code >= 400:
            return False, status_code
        return True, status_code

    def _get_lambda_event_filters_for_arn(self, function_arn: str, queue_arn: str):
        result = []
        sources = self._invoke_adapter.get_event_sources(queue_arn)
        filtered_sources = [s for s in sources if s["FunctionArn"] == function_arn]

        for fs in filtered_sources:
            fc = fs.get("FilterCriteria")
            if fc:
                result.append(fc)
        return result

    def _listen_to_shard_and_invoke_lambda(self, params: Dict):
        """
        Continuously listens to a stream's shard. Divides records read from the shard into batches and use them to
        invoke a Lambda.
        This function is intended to be invoked as a FuncThread. Because FuncThreads can only take a single argument,
        we pack the numerous arguments needed to invoke this method into a single dictionary.
        :param params: Dictionary containing the following elements needed to execute this method:
            * function_arn: ARN of the Lambda function to invoke
            * stream_arn: ARN of the stream associated with the shard to listen on
            * batch_size: number of records to pass to the Lambda function per invocation
            * parallelization_factor: parallelization factor for executing lambda funcs asynchronously
            * lock_discriminator: discriminator for checking semaphore on lambda function execution. Also used for
                                  checking if this listener loops should continue to run.
            * shard_id: ID of the shard to listen on
            * stream_client: AWS service client for communicating with the stream API
            * shard_iterator: shard iterator object for iterating over records in stream
            * max_num_retries: maximum number of times to attempt invoking a batch against the Lambda before giving up
                               and moving on
            * failure_destination: Optional destination config for sending record metadata to if Lambda invocation fails
                                   more than max_num_retries
        """
        # TODO: These values will never get updated if the event source mapping configuration changes :(
        try:
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
                try:
                    records_response = stream_client.get_records(
                        ShardIterator=shard_iterator, Limit=batch_size
                    )
                except ClientError as e:
                    if "AccessDeniedException" in str(e):
                        LOG.warning(
                            "Insufficient permissions to get records from stream %s: %s",
                            stream_arn,
                            e,
                        )
                    else:
                        raise
                else:
                    records = records_response.get("Records")
                    event_filter_criterias = self._get_lambda_event_filters_for_arn(
                        function_arn, stream_arn
                    )
                    if len(event_filter_criterias) > 0:
                        records = filter_stream_records(records, event_filter_criterias)

                    should_get_next_batch = True
                    if records:
                        payload = self._create_lambda_event_payload(
                            stream_arn, records, shard_id=shard_id
                        )
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
                                    ) = self._get_starting_and_ending_sequence_numbers(
                                        first_rec, last_rec
                                    )
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
        except Exception as e:
            LOG.error(
                "Error while listening to shard / executing lambda with params %s: %s",
                params,
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            raise

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
        """
        Creates a metadata payload relating to a failed Lambda invocation and delivers it to the given destination
        """
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
            "approximateArrivalOfFirstRecord": first_record_arrival_time,
            "approximateArrivalOfLastRecord": last_record_arrival_time,
            "batchSize": batch_size,
            "streamArn": source_arn,
        }
        payload[self._FAILURE_PAYLOAD_DETAILS_FIELD_NAME] = details
        send_event_to_target(destination, payload)

    def _monitor_stream_event_sources(self, *args):
        """
        Continuously monitors event source mappings. When a new event source for the relevant stream type is created,
        spawns listener threads for each shard in the stream. When an event source is deleted, stops the associated
        child threads.
        """
        global monitor_counter
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
                    self._STREAM_LISTENER_THREADS = {}
                    return

                # make sure each event source stream has a lambda listening on each of its shards
                for source in sources:
                    mapping_uuid = source["UUID"]
                    stream_arn = source["EventSourceArn"]
                    region_name = extract_region_from_arn(stream_arn)
                    stream_client = self._get_stream_client(source["FunctionArn"], region_name)
                    batch_size = source.get("BatchSize", 10)
                    failure_destination = (
                        source.get("DestinationConfig", {})
                        .get("OnFailure", {})
                        .get("Destination", None)
                    )
                    max_num_retries = source.get("MaximumRetryAttempts", -1)
                    if max_num_retries < 0:
                        max_num_retries = math.inf
                    try:
                        stream_description = self._get_stream_description(stream_client, stream_arn)
                    except Exception as e:
                        LOG.error(
                            "Cannot describe target stream %s of event source mapping %s: %s",
                            stream_arn,
                            mapping_uuid,
                            e,
                        )
                        continue
                    if stream_description["StreamStatus"] not in {"ENABLED", "ACTIVE"}:
                        continue
                    shard_ids = [shard["ShardId"] for shard in stream_description["Shards"]]

                    for shard_id in shard_ids:
                        lock_discriminator = f"{mapping_uuid}/{stream_arn}/{shard_id}"
                        mapped_shard_ids.add(lock_discriminator)
                        if lock_discriminator not in self._STREAM_LISTENER_THREADS:
                            shard_iterator = self._get_shard_iterator(
                                stream_client,
                                stream_arn,
                                shard_id,
                                source["StartingPosition"],
                            )
                            monitor_counter += 1

                            listener_thread = FuncThread(
                                self._listen_to_shard_and_invoke_lambda,
                                {
                                    "function_arn": source["FunctionArn"],
                                    "stream_arn": stream_arn,
                                    "batch_size": batch_size,
                                    "parallelization_factor": source.get(
                                        "ParallelizationFactor", 1
                                    ),
                                    "lock_discriminator": lock_discriminator,
                                    "shard_id": shard_id,
                                    "stream_client": stream_client,
                                    "shard_iterator": shard_iterator,
                                    "failure_destination": failure_destination,
                                    "max_num_retries": max_num_retries,
                                },
                                name=f"monitor-stream-thread-{monitor_counter}",
                            )
                            self._STREAM_LISTENER_THREADS[lock_discriminator] = listener_thread
                            listener_thread.start()

                # stop any threads that are listening to a previously defined event source that no longer exists
                orphaned_threads = set(self._STREAM_LISTENER_THREADS.keys()) - mapped_shard_ids
                for thread_id in orphaned_threads:
                    self._STREAM_LISTENER_THREADS.pop(thread_id)

            except Exception as e:
                LOG.exception(e)
            time.sleep(self._POLL_INTERVAL_SEC)
