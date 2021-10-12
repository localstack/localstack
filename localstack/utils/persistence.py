import base64
import datetime
import json
import logging
import os
import re
import traceback
from abc import ABCMeta, abstractmethod
from typing import NamedTuple

import requests
from six import add_metaclass

from localstack import config, constants
from localstack.config import DATA_DIR, is_env_not_false, is_env_true
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws import aws_stack
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.common import chmod_r, to_bytes, to_str

USE_SINGLE_DUMP_FILE = is_env_not_false("PERSISTENCE_SINGLE_FILE")

if USE_SINGLE_DUMP_FILE:
    API_FILE_PATTERN = "{data_dir}/recorded_api_calls.json"
else:
    API_FILE_PATTERN = "{data_dir}/api_calls_{api}.json"

STARTUP_INFO_FILE = "startup_info.json"

# Stack with flags to indicate whether we are currently re-playing API calls.
# (We should not be re-playing and recording at the same time)
CURRENTLY_REPLAYING = []

# file paths by API
API_FILE_PATHS = {}

# flag to indicate if the restoration of api calls is complete
API_CALLS_RESTORED = False

# set up logger
LOG = logging.getLogger(__name__)


@add_metaclass(ABCMeta)
class PersistingProxyListener(ProxyListener):
    """
    This proxy listener could be extended by any API that wishes to record its requests and responses,
    via the existing persistence facility.
    """

    SKIP_PERSISTENCE_TARGET_METHOD_REGEX = re.compile(r".*\.List|.*\.Describe|.*\.Get")

    def return_response(self, method, path, data, headers, response, request_handler=None):
        res = super(PersistingProxyListener, self).return_response(
            method, path, data, headers, response, request_handler
        )

        if self.should_persist(method, path, data, headers, response):
            record(self.api_name(), to_str(method), to_str(path), data, headers, response)

        return res

    # noinspection PyMethodMayBeStatic,PyUnusedLocal
    def should_persist(self, method, path, data, headers, response):
        """
        Every API listener may choose which endpoints should be persisted;
        The default behavior is persisting all calls with:

        - HTTP PUT / POST / DELETE methods
        - Successful response (non 4xx, 5xx)
        - Excluding methods with 'Describe', 'List', and 'Get' in the X-Amz-Target header

        :param method: The HTTP method name (e.g. 'GET', 'POST')
        :param path: The HTTP path (e.g. '/update')
        :param data: The request body
        :param headers: HTTP response headers
        :param response: HTTP response object
        :return: If True, will persist the current API call.
        :rtype bool
        """
        target_method = headers.get("X-Amz-Target", "")
        skip_target_method = self.SKIP_PERSISTENCE_TARGET_METHOD_REGEX.match(target_method, re.I)

        return (
            should_record(method)
            and response is not None
            and response.ok
            and skip_target_method is None
        )

    @abstractmethod
    def api_name(self):
        """This should return the name of the API we're operating against, e.g. 'sqs'"""
        raise NotImplementedError("Implement me")


def should_record(method):
    """Decide whether or not a given API call should be recorded (persisted to disk)"""
    return method in ["PUT", "POST", "DELETE", "PATCH"]


def record(api, method=None, path=None, data=None, headers=None, response=None, request=None):
    """Record a given API call to a persistent file on disk"""
    file_path = get_file_path(api)
    if CURRENTLY_REPLAYING or not file_path:
        return
    if request:
        method = method or request.method
        path = path or request.path
        headers = headers or request.headers
        data = data or request.data

    should_be_recorded = should_record(method)
    if not should_be_recorded:
        return

    try:
        if isinstance(data, dict):
            data = json.dumps(data)

        def get_recordable_data(request_data):
            if request_data or request_data in ["", b""]:
                try:
                    request_data = to_bytes(request_data)
                except Exception as ex:
                    LOG.warning("Unable to call to_bytes: %s" % ex)
                request_data = to_str(base64.b64encode(request_data))
            return request_data

        data = get_recordable_data(data)
        response_data = get_recordable_data("" if response is None else response.content)

        entry = {
            "a": api,
            "m": method,
            "p": path,
            "d": data,
            "h": dict(headers),
            "rd": response_data,
        }

        with open(file_path, "a") as dumpfile:
            dumpfile.write("%s\n" % json.dumps(entry))
    except Exception as e:
        print("Error recording API call to persistent file: %s %s" % (e, traceback.format_exc()))


def prepare_replay_data(command):
    data = command["d"]
    data = data and base64.b64decode(data)
    return data


def replay_command(command):
    api = command["a"]
    if not is_api_enabled(api):
        return
    function = getattr(requests, command["m"].lower())
    data = prepare_replay_data(command)
    endpoint = aws_stack.get_local_service_url(api)
    full_url = (endpoint[:-1] if endpoint.endswith("/") else endpoint) + command["p"]
    headers = aws_stack.set_internal_auth(command["h"])
    try:
        # fix an error when calling requests with invalid payload encoding
        data and hasattr(data, "encode") and data.encode("latin-1")
    except UnicodeEncodeError:
        if hasattr(data, "encode"):
            data = data.encode("utf-8")
    response = function(full_url, data=data, headers=headers, verify=False)
    return response


def replay(api):
    file_path = get_file_path(api)
    if not file_path:
        return
    CURRENTLY_REPLAYING.append(True)
    count = 0
    try:
        with open(file_path, "r") as reader:
            for line in reader:
                if line.strip():
                    count += 1
                    command = json.loads(line)
                    replay_command(command)
    finally:
        CURRENTLY_REPLAYING.pop(0)
    if count:
        LOG.info("Restored %s API calls from persistent file: %s" % (count, file_path))


def restore_persisted_data(apis):
    global API_CALLS_RESTORED

    if USE_SINGLE_DUMP_FILE:
        replay("_all_")
    else:
        apis = apis if isinstance(apis, list) else [apis]
        for api in apis:
            replay(api)
    API_CALLS_RESTORED = True


def is_persistence_enabled():
    return bool(config.DATA_DIR)


def is_persistence_restored():
    return not is_persistence_enabled() or API_CALLS_RESTORED


class StartupInfo(NamedTuple):
    timestamp: str
    localstack_version: str
    localstack_ext_version: str
    pro_activated: bool


def save_startup_info():
    from localstack_ext.constants import VERSION as LOCALSTACK_EXT_VERSION

    file_path = os.path.join(DATA_DIR, STARTUP_INFO_FILE)

    info = StartupInfo(
        timestamp=datetime.datetime.now().isoformat(),
        localstack_version=constants.VERSION,
        localstack_ext_version=LOCALSTACK_EXT_VERSION,
        pro_activated=is_env_true(constants.ENV_PRO_ACTIVATED),
    )
    LOG.debug("saving startup info %s", info)
    try:
        _append_startup_info(file_path, info)
    except IOError as e:
        LOG.error("could not save startup info: %s", e)

    chmod_r(file_path, 0o777)
    return info


def _append_startup_info(file_path, startup_info: StartupInfo):
    if not os.path.exists(file_path):
        infos = list()
    else:
        with open(file_path, "r") as fd:
            infos = json.load(fd)

    infos.append(startup_info._asdict())
    with open(file_path, "w") as fd:
        json.dump(infos, fd)


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
            with open(file_path, "a"):
                os.utime(file_path, None)
        if os.path.exists(file_path):
            API_FILE_PATHS[api] = file_path
    return API_FILE_PATHS.get(api)
