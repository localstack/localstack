import os
import json
import time
from six.moves import queue
from localstack.config import TMP_FOLDER, CONFIG_FILE_PATH
from localstack.constants import API_ENDPOINT, ENV_INTERNAL_TEST_RUN
from localstack.utils.common import (JsonObject, to_str,
    timestamp, short_uid, save_file, FuncThread, load_file)
from localstack.utils.common import safe_requests as requests

PROCESS_ID = short_uid()
MACHINE_ID = None

# event type constants
EVENT_START_INFRA = 'inf.up'
EVENT_STOP_INFRA = 'inf.dn'
EVENT_KINESIS_CREATE_STREAM = 'kns.cs'
EVENT_KINESIS_DELETE_STREAM = 'kns.ds'
EVENT_LAMBDA_CREATE_FUNC = 'lmb.cf'
EVENT_LAMBDA_DELETE_FUNC = 'lmb.df'
EVENT_SQS_CREATE_QUEUE = 'sqs.cq'
EVENT_SQS_DELETE_QUEUE = 'sqs.dq'
EVENT_S3_CREATE_BUCKET = 's3.cb'
EVENT_S3_DELETE_BUCKET = 's3.db'
EVENT_DYNAMODB_CREATE_TABLE = 'ddb.ct'
EVENT_DYNAMODB_DELETE_TABLE = 'ddb.dt'

# sender thread and queue
SENDER_THREAD = None
EVENT_QUEUE = queue.Queue()


class AnalyticsEvent(JsonObject):

    def __init__(self, **kwargs):
        self.t = kwargs.get('timestamp') or kwargs.get('t') or timestamp()
        self.m_id = kwargs.get('machine_id') or kwargs.get('m_id') or get_machine_id()
        self.p_id = kwargs.get('process_id') or kwargs.get('p_id') or get_process_id()
        self.e_t = kwargs.get('event_type') or kwargs.get('e_t')
        self.p = kwargs.get('payload') if kwargs.get('payload') is not None else kwargs.get('p')

    def timestamp(self):
        return self.t

    def machine_id(self):
        return self.m_id

    def process_id(self):
        return self.p_id

    def event_type(self):
        return self.e_t

    def payload(self):
        return self.p


def get_or_create_file(config_file):
    if os.path.exists(config_file):
        return config_file
    try:
        save_file(config_file, '{}')
        return config_file
    except Exception as e:
        pass


def get_config_file_homedir():
    return get_or_create_file(CONFIG_FILE_PATH)


def get_config_file_tempdir():
    return get_or_create_file(os.path.join(TMP_FOLDER, '.localstack'))


def get_machine_id():
    global MACHINE_ID
    if MACHINE_ID:
        return MACHINE_ID

    # determine MACHINE_ID from config files
    configs_map = {}
    config_file_tmp = get_config_file_tempdir()
    config_file_home = get_config_file_homedir()
    for config_file in (config_file_home, config_file_tmp):
        if config_file:
            local_configs = load_file(config_file)
            local_configs = json.loads(to_str(local_configs))
            configs_map[config_file] = local_configs
            if 'machine_id' in local_configs:
                MACHINE_ID = local_configs['machine_id']
                break

    # if we can neither find NOR create the config files, fall back to process id
    if not configs_map:
        return PROCESS_ID

    # assign default id if empty
    if not MACHINE_ID:
        MACHINE_ID = short_uid()

    # update MACHINE_ID in all config files
    for config_file, configs in configs_map.items():
        configs['machine_id'] = MACHINE_ID
        save_file(config_file, json.dumps(configs))

    return MACHINE_ID


def get_process_id():
    return PROCESS_ID


def poll_and_send_messages(params):
    while True:
        try:
            event = EVENT_QUEUE.get(block=True, timeout=None)
            event = event.to_dict()
            endpoint = '%s/events' % API_ENDPOINT
            result = requests.post(endpoint, json=event)
        except Exception as e:
            # silently fail, make collection of usage data as non-intrusive as possible
            time.sleep(1)


def is_travis():
    return os.environ.get('TRAVIS', '').lower() in ['true', '1']


def get_hash(name):
    if not name:
        return '0'
    max_hash = 10000000000
    hashed = hash(name) % max_hash
    hashed = hex(hashed).replace('0x', '')
    return hashed


def fire_event(event_type, payload=None):
    global SENDER_THREAD
    if not SENDER_THREAD:
        SENDER_THREAD = FuncThread(poll_and_send_messages, {})
        SENDER_THREAD.start()
    if payload is None:
        payload = {}
    if isinstance(payload, dict):
        if is_travis():
            payload['travis'] = True
        if os.environ.get(ENV_INTERNAL_TEST_RUN):
            payload['int'] = True

    event = AnalyticsEvent(event_type=event_type, payload=payload)
    EVENT_QUEUE.put_nowait(event)
