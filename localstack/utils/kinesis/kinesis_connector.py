#!/usr/bin/env python
import json
import logging
import os
import re
import socket
import tempfile
import threading
from typing import Any, Callable

from amazon_kclpy import kcl
from amazon_kclpy.v2 import processor

from localstack import config
from localstack.constants import LOCALSTACK_ROOT_FOLDER, LOCALSTACK_VENV_FOLDER
from localstack.utils.aws import arns
from localstack.utils.files import TMP_FILES, chmod_r, save_file
from localstack.utils.kinesis import kclipy_helper
from localstack.utils.run import ShellCommandThread
from localstack.utils.strings import short_uid, truncate
from localstack.utils.sync import retry
from localstack.utils.threads import TMP_THREADS, FuncThread
from localstack.utils.time import now

DEFAULT_DDB_LEASE_TABLE_SUFFIX = "-kclapp"

# define Java class names
MULTI_LANG_DAEMON_CLASS = "software.amazon.kinesis.multilang.MultiLangDaemon"

# set up local logger
LOG = logging.getLogger(__name__)

INITIALIZATION_REGEX = re.compile(r".*Initialization complete.*")
SUBPROCESS_INITIALIZED_REGEX = re.compile(r".*Received response .* for initialize.*")

# checkpointing settings
CHECKPOINT_RETRIES = 5
CHECKPOINT_SLEEP_SECS = 5
CHECKPOINT_FREQ_SECS = 60

ListenerFunction = Callable[[list], Any]


class EventFileReaderThread(FuncThread):
    def __init__(self, events_file, callback: Callable[[list], Any]):
        super().__init__(
            self.retrieve_loop, None, name="kinesis-event-file-reader", on_stop=self._on_stop
        )
        self.events_file = events_file
        self.callback = callback
        self.is_ready = threading.Event()
        self.sock = None

    def retrieve_loop(self, params):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.events_file)
        self.sock.listen(1)
        self.is_ready.set()
        with self.sock as sock:
            while self.running:
                try:
                    conn, client_addr = sock.accept()
                    thread = FuncThread(
                        self.handle_connection,
                        conn,
                        name="kinesis-event-file-reader-connectionhandler",
                    )
                    thread.start()
                except Exception as e:
                    # ignore any errors happening during shutdown
                    if self.running:
                        LOG.error(
                            "Error dispatching client request: %s",
                            e,
                            exc_info=LOG.isEnabledFor(logging.DEBUG),
                        )
        LOG.debug("Stopping retrieve loop for event file %s", self.events_file)

    def wait_for_ready(self):
        self.is_ready.wait()

    def _on_stop(self, *args, **kwargs):
        if self.sock:
            LOG.debug("Shutting down event file reader for event file %s", self.events_file)
            # shutdown is needed to unblock sock.accept. However, it will raise a OSError: [Errno 22] Invalid argument
            # in the retrieve loop
            # still, the easiest way to shut down the accept call without setting socket timeout for now
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()

    def handle_connection(self, conn: socket):
        socket_file = conn.makefile()
        with socket_file as sock:
            while self.running:
                line = ""
                try:
                    line = sock.readline()
                    line = line.strip()
                    if not line:
                        # end of socket input stream
                        break
                    event = json.loads(line)
                    records = event["records"]
                    self.callback(records)
                except Exception as e:
                    LOG.warning(
                        "Unable to process JSON line: '%s': %s. Callback: %s",
                        truncate(line),
                        e,
                        self.callback,
                        exc_info=LOG.isEnabledFor(logging.DEBUG),
                    )
        LOG.debug("Shutting down connection handler for events file %s", self.events_file)


# needed by the processor script farther down
class KinesisProcessor(processor.RecordProcessorBase):
    def __init__(self, log_file=None, processor_func=None, auto_checkpoint=True):
        self.log_file = log_file
        self.processor_func = processor_func
        self.shard_id = None
        self.auto_checkpoint = auto_checkpoint
        self.last_checkpoint_time = 0
        self._largest_seq = (None, None)

    def initialize(self, initialize_input):
        self.shard_id = initialize_input.shard_id
        if self.log_file:
            self.log(f"initialize '{self.shard_id}'")
        self.shard_id = initialize_input.shard_id

    def process_records(self, process_records_input):
        if self.processor_func:
            records = process_records_input.records
            checkpointer = process_records_input.checkpointer
            self.processor_func(records=records, checkpointer=checkpointer, shard_id=self.shard_id)
            for record in records:
                seq = int(record.sequence_number)
                sub_seq = record.sub_sequence_number
                if self.should_update_sequence(seq, sub_seq):
                    self._largest_seq = (seq, sub_seq)
            if self.auto_checkpoint:
                time_now = now()
                if (time_now - CHECKPOINT_FREQ_SECS) > self.last_checkpoint_time:
                    self.checkpoint(checkpointer, str(self._largest_seq[0]), self._largest_seq[1])
                    self.last_checkpoint_time = time_now

    def shutdown_requested(self, shutdown_requested_input):
        if self.log_file:
            self.log(f"Shutdown processor for shard '{self.shard_id}'")
        if shutdown_requested_input.action == "TERMINATE":
            self.checkpoint(shutdown_requested_input.checkpointer)

    def checkpoint(self, checkpointer, sequence_number=None, sub_sequence_number=None):
        def do_checkpoint():
            checkpointer.checkpoint(sequence_number, sub_sequence_number)

        try:
            retry(do_checkpoint, retries=CHECKPOINT_RETRIES, sleep=CHECKPOINT_SLEEP_SECS)
        except Exception as e:
            LOG.warning("Unable to checkpoint Kinesis after retries: %s", e)

    def should_update_sequence(self, sequence_number, sub_sequence_number):
        return (
            self._largest_seq == (None, None)
            or sequence_number > self._largest_seq[0]
            or (
                sequence_number == self._largest_seq[0]
                and sub_sequence_number > self._largest_seq[1]
            )
        )

    def log(self, s):
        if self.log_file:
            save_file(self.log_file, f"{s}\n", append=True)

    @staticmethod
    def run_processor(log_file=None, processor_func=None):
        proc = kcl.KCLProcess(KinesisProcessor(log_file, processor_func))
        proc.run()


class KinesisProcessorThread(ShellCommandThread):
    def __init__(
        self,
        stream_name: str,
        properties_file: str,
        env_vars: dict[str, str],
        listener_function: ListenerFunction,
        events_file: str,
    ):
        self.initialization_completed = threading.Event()
        self.subprocesses_initialized = threading.Event()
        self.event_reader = EventFileReaderThread(events_file, listener_function)
        self.stream_name = stream_name
        cmd = kclipy_helper.get_kcl_app_command("java", MULTI_LANG_DAEMON_CLASS, properties_file)
        super().__init__(
            cmd,
            log_listener=self._startup_listener,
            env_vars=env_vars,
            quiet=False,
            name="kinesis-processor",
        )

    def start(self):
        self.event_reader.start()
        # Wait until the event reader thread is ready (to avoid 'Connection refused' error on the UNIX socket)
        self.event_reader.wait_for_ready()
        super().start()

    def stop(self, quiet: bool = False):
        if self.stopped:
            LOG.debug("Kinesis connector for stream %s already stopped.", self.stream_name)
        else:
            LOG.debug("Stopping kinesis connector for stream: %s", self.stream_name)
            self.event_reader.stop()
            super().stop(quiet)

    def _startup_listener(self, line: str, **kwargs):
        line = line.strip()
        # LOG.debug("KCLPY: %s", line)
        if not self.initialization_completed.is_set() and INITIALIZATION_REGEX.match(line):
            self.initialization_completed.set()
        if not self.subprocesses_initialized.is_set() and SUBPROCESS_INITIALIZED_REGEX.match(line):
            self.subprocesses_initialized.set()

    def wait_is_up(self, timeout: int | None = None) -> bool:
        return self.initialization_completed.wait(timeout=timeout)

    def wait_subprocesses_initialized(self, timeout: int | None = None) -> bool:
        return self.subprocesses_initialized.wait(timeout=timeout)


def _start_kcl_client_process(
    stream_name: str,
    account_id: str,
    region_name: str,
    listener_function: ListenerFunction,
    ddb_lease_table_suffix=None,
):
    # make sure to convert stream ARN to stream name
    stream_name = arns.kinesis_stream_name(stream_name)
    # disable CBOR protocol, enforce use of plain JSON
    # TODO evaluate why?
    env_vars = {
        "AWS_CBOR_DISABLE": "true",
        "AWS_ACCESS_KEY_ID": account_id,
        "AWS_SECRET_ACCESS_KEY": account_id,
    }

    events_file = os.path.join(tempfile.gettempdir(), f"kclipy.{short_uid()}.fifo")
    TMP_FILES.append(events_file)
    processor_script = _generate_processor_script(events_file)

    properties_file = os.path.join(tempfile.gettempdir(), f"kclipy.{short_uid()}.properties")
    app_name = f"{stream_name}{ddb_lease_table_suffix}"
    # create config file
    kclipy_helper.create_config_file(
        config_file=properties_file,
        executableName=processor_script,
        streamName=stream_name,
        applicationName=app_name,
        region_name=region_name,
        metricsLevel="NONE",
        initialPositionInStream="LATEST",
        # set parameters for local connection
        kinesisEndpoint=config.internal_service_url(protocol="http"),
        dynamoDBEndpoint=config.internal_service_url(protocol="http"),
        disableCertChecking="true",
    )
    TMP_FILES.append(properties_file)
    # start stream consumer
    kinesis_processor = KinesisProcessorThread(
        stream_name=stream_name,
        properties_file=properties_file,
        env_vars=env_vars,
        listener_function=listener_function,
        events_file=events_file,
    )
    kinesis_processor.start()
    TMP_THREADS.append(kinesis_processor)
    return kinesis_processor


def _generate_processor_script(events_file: str):
    script_file = os.path.join(tempfile.gettempdir(), f"kclipy.{short_uid()}.processor.py")
    content = f"""#!/usr/bin/env python
import os, sys, glob, json, socket, time, logging, subprocess, tempfile
logging.basicConfig(level=logging.INFO)
for path in glob.glob('{LOCALSTACK_VENV_FOLDER}/lib/python*/site-packages'):
    sys.path.insert(0, path)
sys.path.insert(0, '{LOCALSTACK_ROOT_FOLDER}')
from localstack.config import DEFAULT_ENCODING
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.time import timestamp
events_file = '{events_file}'
log_file = None
error_log = os.path.join(tempfile.gettempdir(), 'kclipy.error.log')
if __name__ == '__main__':
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    num_tries = 3
    sleep_time = 2
    error = None
    for i in range(0, num_tries):
        try:
            sock.connect(events_file)
            error = None
            break
        except Exception as e:
            error = e
            if i < num_tries:
                msg = '%s: Unable to connect to UNIX socket. Retrying.' % timestamp()
                subprocess.check_output('echo "%s" >> %s' % (msg, error_log), shell=True)
                time.sleep(sleep_time)
    if error:
        print("WARN: Unable to connect to UNIX socket after retrying: %s" % error)
        raise error

    def receive_msg(records, checkpointer, shard_id):
        try:
            # records is a list of amazon_kclpy.messages.Record objects -> convert to JSON
            records_dicts = [j._json_dict for j in records]
            message_to_send = {{'shard_id': shard_id, 'records': records_dicts}}
            string_to_send = '%s\\n' % json.dumps(message_to_send)
            bytes_to_send = string_to_send.encode(DEFAULT_ENCODING)
            sock.send(bytes_to_send)
        except Exception as e:
            msg = "WARN: Unable to forward event: %s" % e
            print(msg)
            subprocess.check_output('echo "%s" >> %s' % (msg, error_log), shell=True)
    kinesis_connector.KinesisProcessor.run_processor(log_file=log_file, processor_func=receive_msg)
    """
    save_file(script_file, content)
    chmod_r(script_file, 0o755)
    TMP_FILES.append(script_file)
    return script_file


def listen_to_kinesis(
    stream_name: str,
    account_id: str,
    region_name: str,
    listener_func: ListenerFunction,
    ddb_lease_table_suffix: str | None = None,
    wait_until_started: bool = False,
):
    """
    High-level function that allows to subscribe to a Kinesis stream
    and receive events in a listener function. A KCL client process is
    automatically started in the background.
    """
    process = _start_kcl_client_process(
        stream_name=stream_name,
        account_id=account_id,
        region_name=region_name,
        listener_function=listener_func,
        ddb_lease_table_suffix=ddb_lease_table_suffix,
    )

    if wait_until_started:
        # Wait at most 90 seconds for initialization. Note that creating the DDB table can take quite a bit
        success = process.wait_is_up(timeout=90)
        if not success:
            raise Exception("Timeout when waiting for KCL initialization.")
        # ignore success/failure of wait because a timeout merely means that there is no shard available to take
        # waiting here, since otherwise some messages would be ignored even though the connector reports ready
        process.wait_subprocesses_initialized(timeout=30)

    return process
