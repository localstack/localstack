#!/usr/bin/env python

import base64
import json
import os
import sys
import re
import socket
import time
import traceback
import threading
import logging
import Queue
from urlparse import urlparse
from amazon_kclpy import kcl
from docopt import docopt
from sh import tail
from localstack.utils.common import *
from localstack.utils.kinesis import kclipy_helper
from localstack.utils.kinesis.kinesis_util import EventFileReaderThread
from localstack.constants import *
from localstack.utils.common import ShellCommandThread, FuncThread
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import KinesisStream


EVENTS_FILE_PATTERN = '/tmp/kclipy.*.fifo'
LOG_FILE_PATTERN = '/tmp/kclipy.*.log'
DEFAULT_DDB_LEASE_TABLE_SUFFIX = '-app'

# define Java class names
MULTI_LANG_DAEMON_CLASS = 'com.atlassian.KinesisStarter'

# set up log levels
logging.SEVERE = 60
logging.FATAL = 70
logging.addLevelName(logging.SEVERE, 'SEVERE')
logging.addLevelName(logging.FATAL, 'FATAL')
LOG_LEVELS = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL, logging.SEVERE]

# default log level for the KCL log output
DEFAULT_KCL_LOG_LEVEL = logging.WARNING

# set up local logger
LOGGER = logging.getLogger(__name__)

# checkpointing settings
CHECKPOINT_RETRIES = 5
CHECKPOINT_SLEEP_SECS = 5
CHECKPOINT_FREQ_SECS = 60


class KinesisProcessor(kcl.RecordProcessorBase):

    def __init__(self, log_file=None, processor_func=None, auto_checkpoint=True):
        self.log_file = log_file
        self.processor_func = processor_func
        self.shard_id = None
        self.checkpointer = None
        self.auto_checkpoint = auto_checkpoint
        self.last_checkpoint_time = 0
        self._largest_seq = (None, None)

    def initialize(self, shard_id):
        if self.log_file:
            self.log("initialize '%s'" % (shard_id))
        self.shard_id = shard_id

    def process_records(self, records, checkpointer):
        if self.processor_func:
            self.processor_func(records=records,
                checkpointer=checkpointer, shard_id=self.shard_id)
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

    def shutdown(self, checkpointer, reason):
        if self.log_file:
            self.log("Shutdown processor for shard '%s'" % self.shard_id)
        self.checkpointer = checkpointer
        if reason == 'TERMINATE':
            self.checkpoint(checkpointer)

    def checkpoint(self, checkpointer, sequence_number=None, sub_sequence_number=None):
        def do_checkpoint():
            checkpointer.checkpoint(sequence_number, sub_sequence_number)

        try:
            retry(do_checkpoint, retries=CHECKPOINT_RETRIES, sleep=CHECKPOINT_SLEEP_SECS)
        except Exception, e:
            LOGGER.warning('Unable to checkpoint Kinesis after retries: %s' % e)

    def should_update_sequence(self, sequence_number, sub_sequence_number):
        return self._largest_seq == (None, None) or sequence_number > self._largest_seq[0] or \
            (sequence_number == self._largest_seq[0] and sub_sequence_number > self._largest_seq[1])

    def log(self, s):
        s = '%s\n' % s
        if self.log_file:
            save_file(self.log_file, s, append=True)

    @staticmethod
    def run_processor(log_file=None, processor_func=None):
        proc = kcl.KCLProcess(KinesisProcessor(log_file, processor_func))
        proc.run()


class KinesisProcessorThread(ShellCommandThread):
    def __init__(self, params):
        props_file = params['properties_file']
        env_vars = params['env_vars']
        cmd = kclipy_helper.get_kcl_app_command('java',
            MULTI_LANG_DAEMON_CLASS, props_file)
        if not params['log_file']:
            params['log_file'] = '%s.log' % props_file
            TMP_FILES.append(params['log_file'])
        # print(cmd)
        env = aws_stack.get_environment()
        quiet = env.region == REGION_LOCAL
        ShellCommandThread.__init__(self, cmd, outfile=params['log_file'], env_vars=env_vars, quiet=quiet)

    @staticmethod
    def start_consumer(kinesis_stream):
        thread = KinesisProcessorThread(kinesis_stream.stream_info)
        thread.start()
        return thread


class OutputReaderThread(FuncThread):
    def __init__(self, params):
        FuncThread.__init__(self, self.start_reading, params)
        self.running = True
        self.buffer = []
        self.params = params
        # number of lines that make up a single log entry
        self.buffer_size = 2
        # determine log level
        self.log_level = params.get('level')
        # get log subscribers
        self.log_subscribers = params.get('log_subscribers', [])
        if self.log_level is None:
            self.log_level = DEFAULT_KCL_LOG_LEVEL
        if self.log_level > 0:
            levels = OutputReaderThread.get_log_level_names(self.log_level)
            # regular expression to filter the printed output
            self.filter_regex = r'.*(%s):.*' % ('|'.join(levels))
            # create prefix and logger
            self.prefix = params.get('log_prefix') or 'LOG'
            self.logger = logging.getLogger(self.prefix)
            self.logger.severe = self.logger.critical
            self.logger.fatal = self.logger.critical
            self.logger.setLevel(self.log_level)

    @classmethod
    def get_log_level_names(cls, min_level):
        return [logging.getLevelName(l) for l in LOG_LEVELS if l >= min_level]

    def get_logger_for_level_in_log_line(self, line):
        level = self.log_level
        for l in LOG_LEVELS:
            if l >= level:
                level_name = logging.getLevelName(l)
                if re.match(r'.*(%s):.*' % level_name, line):
                    return getattr(self.logger, level_name.lower())
        return None

    def notify_subscribers(self, line):
        for subscriber in self.log_subscribers:
            try:
                if re.match(subscriber.regex, line):
                    subscriber.update(line)
            except Exception, e:
                LOGGER.warning('Unable to notify log subscriber: %s' % e)

    def start_reading(self, params):
        for line in tail("-n", 0, "-f", params['file'], _iter=True):
            if not self.running:
                return
            line = line.replace('\n', '')
            # notify subscribers
            self.notify_subscribers(line)
            if self.log_level > 0:
                # add line to buffer
                self.buffer.append(line)
                if len(self.buffer) >= self.buffer_size:
                    logger_func = None
                    for line in self.buffer:
                        if re.match(self.filter_regex, line):
                            logger_func = self.get_logger_for_level_in_log_line(line)
                            break
                    if logger_func:
                        for buffered_line in self.buffer:
                            logger_func(buffered_line)
                    self.buffer = []

    def stop(self, quiet=True):
        self.running = False


class KclLogListener(object):
    def __init__(self, regex='.*'):
        self.regex = regex

    def update(self, log_line):
        print(log_line)


class KclStartedLogListener(KclLogListener):
    def __init__(self):
        self.regex_init = r'.*Initialization complete.*'
        self.regex_take_shard = r'.*Received response .* for initialize.*'
        # construct combined regex
        regex = r'(%s)|(%s)' % (self.regex_init, self.regex_take_shard)
        super(KclStartedLogListener, self).__init__(regex=regex)
        # Semaphore.acquire does not provide timeout parameter, so we
        # use a Queue here which provides the required functionality
        self.sync_init = Queue.Queue(0)
        self.sync_take_shard = Queue.Queue(0)

    def update(self, log_line):
        if re.match(self.regex_init, log_line):
            self.sync_init.put(1, block=False)
        if re.match(self.regex_take_shard, log_line):
            self.sync_take_shard.put(1, block=False)


# construct a stream info hash
def get_stream_info(stream_name, log_file=None, shards=None, env=None, endpoint_url=None,
        ddb_lease_table_suffix=None, env_vars={}):
    if not ddb_lease_table_suffix:
        ddb_lease_table_suffix = DEFAULT_DDB_LEASE_TABLE_SUFFIX
    # construct stream info
    env = aws_stack.get_environment(env)
    props_file = os.path.join('/tmp/', 'kclipy.%s.properties' % short_uid())
    app_name = '%s%s' % (stream_name, ddb_lease_table_suffix)
    stream_info = {
        'name': stream_name,
        'region': DEFAULT_REGION,
        'shards': shards,
        'properties_file': props_file,
        'log_file': log_file,
        'app_name': app_name,
        'env_vars': env_vars
    }
    # set local connection
    if env.region == REGION_LOCAL:
        from localstack.constants import LOCALHOST, DEFAULT_PORT_KINESIS
        stream_info['conn_kwargs'] = {
            'host': LOCALHOST,
            'port': DEFAULT_PORT_KINESIS,
            'is_secure': False
        }
    if endpoint_url:
        if 'conn_kwargs' not in stream_info:
            stream_info['conn_kwargs'] = {}
        url = urlparse(endpoint_url)
        stream_info['conn_kwargs']['host'] = url.hostname
        stream_info['conn_kwargs']['port'] = url.port
        stream_info['conn_kwargs']['is_secure'] = url.scheme == 'https'
    return stream_info


def start_kcl_client_process(stream_name, listener_script, log_file=None, env=None, configs={},
        endpoint_url=None, ddb_lease_table_suffix=None, env_vars={},
        kcl_log_level=DEFAULT_KCL_LOG_LEVEL, log_subscribers=[]):
    env = aws_stack.get_environment(env)
    # decide which credentials provider to use
    credentialsProvider = None
    if (('AWS_ASSUME_ROLE_ARN' in os.environ or 'AWS_ASSUME_ROLE_ARN' in env_vars) and
            ('AWS_ASSUME_ROLE_SESSION_NAME' in os.environ or 'AWS_ASSUME_ROLE_SESSION_NAME' in env_vars)):
        # use special credentials provider that can assume IAM roles and handle temporary STS auth tokens
        credentialsProvider = 'com.atlassian.DefaultSTSAssumeRoleSessionCredentialsProvider'
        # pass through env variables to child process
        for var_name in ['AWS_ASSUME_ROLE_ARN', 'AWS_ASSUME_ROLE_SESSION_NAME',
                'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']:
            if var_name in os.environ and var_name not in env_vars:
                env_vars[var_name] = os.environ[var_name]
    if env.region == REGION_LOCAL:
        # need to disable CBOR protocol, enforce use of plain JSON,
        # see https://github.com/mhart/kinesalite/issues/31
        env_vars['AWS_CBOR_DISABLE'] = 'true'
    if kcl_log_level or (len(log_subscribers) > 0):
        if not log_file:
            log_file = LOG_FILE_PATTERN.replace('*', short_uid())
            TMP_FILES.append(log_file)
        run('touch %s' % log_file)
        # start log output reader thread which will read the KCL log
        # file and print each line to stdout of this process...
        reader_thread = OutputReaderThread({'file': log_file, 'level': kcl_log_level,
            'log_prefix': 'KCL', 'log_subscribers': log_subscribers})
        reader_thread.start()

    # construct stream info
    stream_info = get_stream_info(stream_name, log_file, env=env, endpoint_url=endpoint_url,
        ddb_lease_table_suffix=ddb_lease_table_suffix, env_vars=env_vars)
    props_file = stream_info['properties_file']
    # set kcl config options
    kwargs = {
        'metricsLevel': 'NONE',
        'initialPositionInStream': 'LATEST'
    }
    # set parameters for local connection
    if env.region == REGION_LOCAL:
        from localstack.constants import LOCALHOST, DEFAULT_PORT_KINESIS, DEFAULT_PORT_DYNAMODB
        kwargs['kinesisEndpoint'] = '%s:%s' % (LOCALHOST, DEFAULT_PORT_KINESIS)
        kwargs['dynamodbEndpoint'] = '%s:%s' % (LOCALHOST, DEFAULT_PORT_DYNAMODB)
        kwargs['kinesisProtocol'] = 'http'
        kwargs['dynamodbProtocol'] = 'http'
        kwargs['disableCertChecking'] = 'true'
    kwargs.update(configs)
    # create config file
    kclipy_helper.create_config_file(config_file=props_file, executableName=listener_script,
        streamName=stream_name, applicationName=stream_info['app_name'],
        credentialsProvider=credentialsProvider, **kwargs)
    TMP_FILES.append(props_file)
    # start stream consumer
    stream = KinesisStream(id=stream_name, params=stream_info)
    thread_consumer = KinesisProcessorThread.start_consumer(stream)
    TMP_THREADS.append(thread_consumer)
    return thread_consumer


def generate_processor_script(events_file, log_file=None):
    script_file = os.path.join('/tmp/', 'kclipy.%s.processor.py' % short_uid())
    if log_file:
        log_file = "'%s'" % log_file
    else:
        log_file = 'None'
    content = """#!/usr/bin/env python
import os, sys, json, socket, time, logging
import subprocess32 as subprocess
logging.basicConfig(level=logging.INFO)
sys.path.insert(0, '%s/lib/python2.7/site-packages')
sys.path.insert(0, '%s')
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.common import timestamp
events_file = '%s'
log_file = %s
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
        except Exception, e:
            error = e
            if i < num_tries:
                msg = '%%s: Unable to connect to UNIX socket. Retrying.' %% timestamp()
                subprocess.check_output('echo "%%s" >> /tmp/kclipy.error.log' %% msg, shell=True)
                time.sleep(sleep_time)
    if error:
        print("WARN: Unable to connect to UNIX socket after retrying: %%s" %% error)
        raise error

    def receive_msg(records, checkpointer, shard_id):
        try:
            # records is a list of amazon_kclpy.messages.Record objects -> convert to JSON
            records_dicts = [j._json_dict for j in records]
            message_to_send = {'shard_id': shard_id, 'records': records_dicts}
            sock.send(b'%%s\\n' %% json.dumps(message_to_send))
        except Exception, e:
            print("WARN: Unable to forward event: %%s" %% e)
    kinesis_connector.KinesisProcessor.run_processor(log_file=log_file, processor_func=receive_msg)
    """ % (LOCALSTACK_VENV_FOLDER, LOCALSTACK_ROOT_FOLDER, events_file, log_file)
    save_file(script_file, content)
    run('chmod +x %s' % script_file)
    TMP_FILES.append(script_file)
    return script_file


def listen_to_kinesis(stream_name, listener_func=None, processor_script=None,
        events_file=None, endpoint_url=None, log_file=None, configs={}, env=None,
        ddb_lease_table_suffix=None, env_vars={}, kcl_log_level=DEFAULT_KCL_LOG_LEVEL,
        log_subscribers=[], wait_until_started=False):
    """
    High-level function that allows to subscribe to a Kinesis stream
    and receive events in a listener function. A KCL client process is
    automatically started in the background.
    """
    env = aws_stack.get_environment(env)
    if not events_file:
        events_file = os.path.join(EVENTS_FILE_PATTERN.replace('*', '%s') % short_uid())
        TMP_FILES.append(events_file)
    if not processor_script:
        processor_script = generate_processor_script(events_file, log_file=log_file)

    run('rm -f %s' % events_file)
    # start event reader thread (this process)
    ready_mutex = threading.Semaphore(0)
    thread = EventFileReaderThread(events_file, listener_func, ready_mutex=ready_mutex)
    thread.start()
    # Wait until the event reader thread is ready (to avoid 'Connection refused' error on the UNIX socket)
    ready_mutex.acquire()
    # start KCL client (background process)
    if processor_script[-4:] == '.pyc':
        processor_script = processor_script[0:-1]
    # add log listener that notifies when KCL is started
    if wait_until_started:
        listener = KclStartedLogListener()
        log_subscribers.append(listener)

    process = start_kcl_client_process(stream_name, processor_script,
        endpoint_url=endpoint_url, log_file=log_file, configs=configs, env=env,
        ddb_lease_table_suffix=ddb_lease_table_suffix, env_vars=env_vars, kcl_log_level=kcl_log_level,
        log_subscribers=log_subscribers)

    if wait_until_started:
        # wait at most 30 seconds for initialization
        try:
            listener.sync_init.get(block=True, timeout=30)
        except Exception, e:
            raise Exception('Timeout when waiting for KCL initialization.')
        # wait at most 30 seconds for shard lease notification
        try:
            listener.sync_take_shard.get(block=True, timeout=30)
        except Exception, e:
            # this merely means that there is no shard available to take. Do nothing.
            pass

    return process
