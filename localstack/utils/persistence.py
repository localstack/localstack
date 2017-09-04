import os
import json
import base64
import traceback
import requests
import logging
from localstack.config import DATA_DIR
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_bytes, to_str

API_FILE_PATTERN = '{data_dir}/{api}_api_calls.json'

# Stack with flags to indicate whether we are currently re-playing API calls.
# (We should not be re-playing and recording at the same time)
CURRENTLY_REPLAYING = []

# file paths by API
API_FILE_PATHS = {}

# set up logger
LOGGER = logging.getLogger(__name__)


def should_record(api, method, path, data, headers):
    """ Decide whether or not a given API call should be recorded (persisted to disk) """
    if api == 's3':
        if method not in ['PUT', 'POST', 'DELETE']:
            return False
        return True
    return False


def record(api, method, path, data, headers):
    """ Record a given API call to a persistent file on disk """
    file_path = get_file_path(api, create=True)
    if CURRENTLY_REPLAYING or not file_path or not should_record(api, method, path, data, headers):
        return
    entry = None
    try:
        if isinstance(data, dict):
            data = json.dumps(data)
        if data:
            try:
                data = to_bytes(data)
            except Exception as e:
                LOGGER.warning('Unable to call to_bytes: %s' % e)
            data = to_str(base64.b64encode(data))
        entry = {
            'a': api,
            'm': method,
            'p': path,
            'd': data,
            'h': dict(headers)
        }
        with open(file_path, 'a') as dumpfile:
            dumpfile.write('%s\n' % json.dumps(entry))
    except Exception as e:
        print('Error recording API call to persistent file: %s %s' % (e, traceback.format_exc()))


def replay_command(command):
    function = getattr(requests, command['m'].lower())
    data = command['d']
    if data:
        data = base64.b64decode(data)
    endpoint = aws_stack.get_local_service_url(command['a'])
    full_url = (endpoint[:-1] if endpoint.endswith('/') else endpoint) + command['p']
    result = function(full_url, data=data, headers=command['h'])
    return result


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
        LOGGER.info('Restored %s API calls from persistent file: %s' % (count, file_path))


def restore_persisted_data(api):
    return replay(api)


# ---------------
# HELPER METHODS
# ---------------

def get_file_path(api, create=False):
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
