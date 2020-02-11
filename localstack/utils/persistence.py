import os
import json
import base64
import traceback
import requests
import logging
from localstack.config import DATA_DIR
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_bytes, to_str

USE_SINGLE_DUMP_FILE = True

if USE_SINGLE_DUMP_FILE:
    API_FILE_PATTERN = '{data_dir}/recorded_api_calls.json'
else:
    API_FILE_PATTERN = '{data_dir}/{api}_api_calls.json'

# Stack with flags to indicate whether we are currently re-playing API calls.
# (We should not be re-playing and recording at the same time)
CURRENTLY_REPLAYING = []

# file paths by API
API_FILE_PATHS = {}

# set up logger
LOG = logging.getLogger(__name__)


def should_record(api, method, path, data, headers, response=None):
    """ Decide whether or not a given API call should be recorded (persisted to disk) """
    if api in ['es', 's3']:
        return method in ['PUT', 'POST', 'DELETE']
    return False


def record(api, method=None, path=None, data=None, headers=None, response=None, request=None):
    """ Record a given API call to a persistent file on disk """
    file_path = get_file_path(api)
    if CURRENTLY_REPLAYING or not file_path:
        return
    if request:
        method = method or request.method
        path = path or request.path
        headers = headers or request.headers
        data = data or request.data
    should_be_recorded = should_record(api, method, path, data, headers, response=response)
    if not should_be_recorded:
        return
    entry = None
    try:
        if isinstance(data, dict):
            data = json.dumps(data)

        def get_recordable_data(data):
            if data or data in [u'', b'']:
                try:
                    data = to_bytes(data)
                except Exception as e:
                    LOG.warning('Unable to call to_bytes: %s' % e)
                data = to_str(base64.b64encode(data))
            return data

        data = get_recordable_data(data)
        response_data = get_recordable_data('' if response is None else response.content)

        entry = {
            'a': api,
            'm': method,
            'p': path,
            'd': data,
            'h': dict(headers),
            'rd': response_data
        }
        with open(file_path, 'a') as dumpfile:
            dumpfile.write('%s\n' % json.dumps(entry))
    except Exception as e:
        print('Error recording API call to persistent file: %s %s' % (e, traceback.format_exc()))


def prepare_replay_data(command):
    data = command['d']
    data = data and base64.b64decode(data)
    return data


def replay_command(command):
    function = getattr(requests, command['m'].lower())
    data = prepare_replay_data(command)
    endpoint = aws_stack.get_local_service_url(command['a'])
    full_url = (endpoint[:-1] if endpoint.endswith('/') else endpoint) + command['p']
    response = function(full_url, data=data, headers=command['h'], verify=False)
    return response


def replay(api):
    file_path = get_file_path(api)
    if not file_path:
        return
    CURRENTLY_REPLAYING.append(True)
    count = 0
    try:
        with open(file_path, 'r') as reader:
            for line in reader:
                if line.strip():
                    count += 1
                    command = json.loads(line)
                    replay_command(command)
    finally:
        CURRENTLY_REPLAYING.pop(0)
    if count:
        LOG.info('Restored %s API calls from persistent file: %s' % (count, file_path))


def restore_persisted_data(apis):
    if USE_SINGLE_DUMP_FILE:
        return replay('_all_')
    apis = apis if isinstance(apis, list) else [apis]
    for api in apis:
        replay(apis)


# ---------------
# HELPER METHODS
# ---------------

def get_file_path(api, create=True):
    if api not in API_FILE_PATHS:
        API_FILE_PATHS[api] = False
        if not DATA_DIR:
            return False
        file_path = API_FILE_PATTERN.format(data_dir=DATA_DIR, api=api)
        if create and not os.path.exists(file_path):
            with open(file_path, 'a'):
                os.utime(file_path, None)
        if os.path.exists(file_path):
            API_FILE_PATHS[api] = file_path
    return API_FILE_PATHS.get(api)
