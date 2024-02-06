import base64
import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional

import botocore

from localstack.aws.api.firehose import Record
from localstack.aws.connect import connect_to
from localstack.utils.aws.arns import parse_arn
from localstack.utils.threads import TMP_THREADS, FuncThread

# set up local logger
LOG = logging.getLogger(__name__)

ListenerFunction = Callable[[list], Any]

SHARD_SLEEP_TIME = 60
POLL_STREAM_SLEEP_TIME = 1
SHARD_LEASE_TIME = 300


def listen_to_kinesis(
    stream_name: str,
    stream_arn: str,
    account_id: str,
    region_name: str,
    listener_func: ListenerFunction,
    wait_for_client_ready: bool = True,
):
    """
    High-level function that allows to subscribe to a Kinesis stream
    and receive events in a listener function.
    """
    process = KinesisClient(stream_name, stream_arn, account_id, region_name, listener_func)
    process.start()
    TMP_THREADS.append(process)
    if wait_for_client_ready:
        process.initialized(timeout=10)
    return process


@dataclass
class ShardData:
    # TODO: deal with persisting shard data to not re-read all events on restart if persistence is enabled
    shard_id: str
    stream_arn: str
    shard_iterator: str
    last_sequence_number: str
    lock: threading.Lock
    parent_shard_id: Optional[str] = None
    worker_thread: Optional[FuncThread] = None


class KinesisClient(FuncThread):
    """
    Listens to a Kinesis stream, prepares shard iterators and regularly updates
    adds new shard iterators and spawns a worker thread for each shard.
    """

    def __init__(
        self,
        stream_name: str,
        stream_arn: str,
        account_id: str,
        region_name: str,
        callback: ListenerFunction,
    ):
        self.stream_name = stream_name
        self.stream_arn = stream_arn
        self.account_id = account_id
        self.region_name = region_name
        self.callback = callback
        self.kinesis_client = self._get_kinesis_client(stream_arn)
        self.initialization_completed = threading.Event()
        self.shards: dict[str, ShardData] = dict()  # key = shard_id
        self.lease_time = SHARD_LEASE_TIME
        self.sleep_time = SHARD_SLEEP_TIME
        super().__init__(self.process_shards_loop, None, name="kinesis-client")

    def process_shards_loop(self, params):
        while self.running:
            LOG.debug("run process_shards_loop")
            self.process_shards()
            self._stop_event.wait(self.sleep_time)

    def process_shards(self) -> str:
        stream_info = self.kinesis_client.describe_stream(StreamARN=self.stream_arn)

        for shard_description in stream_info["StreamDescription"]["Shards"]:
            shard_id = shard_description["ShardId"]
            self.lock_shard(shard_id)

            kwargs = self._get_iterator_args(shard_id, shard_description)
            response = self.kinesis_client.get_shard_iterator(
                StreamARN=self.stream_arn,
                ShardId=shard_id,
                **kwargs,
            )
            shard_iterator = response["ShardIterator"]

            # TODO add logic to only update if shard iterator changed (parent child, hash key range) or lease run out
            shard = self.update_shard(
                shard_id=shard_id,
                shard_iterator=shard_iterator,
                shard_description=shard_description,
            )

            self.unlock_shard(shard_id)

            # start worker thread if not already running
            if not shard.worker_thread or not shard.worker_thread.is_alive():
                shard.worker_thread = KinesisWorker(shard, self.callback, self.kinesis_client)
                shard.worker_thread.start()
                TMP_THREADS.append(shard.worker_thread)

            self.initialization_completed.set()

    def lock_shard(self, shard_id):
        try:
            self.shards[shard_id].lock.acquire()
        except KeyError:
            pass
        except Exception as e:
            LOG.warning("Unable to lock shard %s: %s", shard_id, e)

    def unlock_shard(self, shard_id):
        try:
            self.shards[shard_id].lock.release()
        except KeyError:
            pass
        except Exception as e:
            LOG.warning("Unable to unlock shard %s: %s", shard_id, e)

    def initialized(self, timeout: int | None = None) -> bool:
        return self.initialization_completed.wait(timeout=timeout)

    def start(self) -> None:
        LOG.debug("Starting kinesis client for stream: %s", self.stream_name)
        self.initialization_completed.clear()
        super().start()

    def stop(self, quiet: bool = False):
        LOG.debug("Stopping kinesis client for stream: %s", self.stream_name)
        super().stop()
        for shard_id, shard in self.shards.items():
            try:
                shard.worker_thread.stop()
            except Exception as e:
                LOG.warning("Unable to stop worker thread for shard %s: %s", shard_id, e)

    def update_shard(self, shard_id, shard_iterator, shard_description):
        if shard_id not in self.shards:
            lock = threading.Lock()
            lock.acquire()
            self.shards[shard_id] = ShardData(
                shard_id=shard_id,
                stream_arn=self.stream_arn,
                shard_iterator=shard_iterator,
                # TODO: how to deal with worker not read event associated with current sequence number while shard updates before
                last_sequence_number=shard_description["SequenceNumberRange"][
                    "StartingSequenceNumber"
                ],
                parent_shard_id=shard_description.get("ParentShardId"),
                lock=lock,
            )
        else:
            self.shards[shard_id].shard_iterator = shard_iterator
        return self.shards[shard_id]

    def _get_kinesis_client(self, stream_arn: str, client_config: botocore.config.Config = None):
        parsed_arn = parse_arn(stream_arn)
        kinesis_client = connect_to(
            aws_access_key_id=parsed_arn["account"],
            region_name=parsed_arn["region"],
            config=client_config,
        ).kinesis
        return kinesis_client

    def _get_iterator_args(self, shard_id, shard_description):
        try:
            return dict(
                ShardIteratorType="AFTER_SEQUENCE_NUMBER",
                StartingSequenceNumber=self.shards[shard_id].last_sequence_number,
            )
        except KeyError:
            return dict(
                ShardIteratorType="AT_SEQUENCE_NUMBER",
                StartingSequenceNumber=shard_description["SequenceNumberRange"][
                    "StartingSequenceNumber"
                ],
            )


class KinesisWorker(FuncThread):
    """
    Listens to a specific shard in a separate thread,
    applies the callback function to all received events from polled kinesis stream.
    """

    def __init__(
        self,
        shard: ShardData,
        callback: ListenerFunction,
        kinesis_client: botocore.client.BaseClient,
        sleep_time: int = POLL_STREAM_SLEEP_TIME,
    ):
        self.shard = shard
        self.callback = callback
        self.kinesis_client = kinesis_client
        self.sleep_time = sleep_time
        super().__init__(self.poll_stream_loop, None, name="kinesis-worker")

    def poll_stream_loop(self, params):
        logging.getLogger().setLevel(logging.ERROR)  # supress spamming the logs
        while self.running:
            LOG.debug("run poll_stream_loop\n")
            self.shard.lock.acquire()
            records = self.poll_events()
            if records:
                self.callback(records)
                # update sequence number
                self.shard.last_sequence_number = records[-1]["SequenceNumber"]
            self.shard.lock.release()
            self._stop_event.wait(self.sleep_time)

    def poll_events(self) -> list[Record]:
        get_records_response = self.kinesis_client.get_records(
            StreamARN=self.shard.stream_arn,
            ShardIterator=self.shard.shard_iterator,
        )
        self.shard.shard_iterator = get_records_response["NextShardIterator"]
        records = get_records_response["Records"]
        # logic in kinesis consumers expect Base64-encoded string
        for record in records:
            record["Data"] = base64.b64encode(record["Data"])

        return records

    def start(self) -> None:
        LOG.debug("Starting kinesis worker for shard: %s", self.shard.shard_id)
        return super().start()

    def stop(self, quiet: bool = False):
        LOG.debug("Stopping kinesis worker for shard: %s", self.shard.shard_id)
        self.running = False
        super().stop()
        self.shard.lock.release()
