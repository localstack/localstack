import datetime
import json
import logging
import os
import re
from abc import ABCMeta, abstractmethod
from typing import NamedTuple

from localstack import config, constants
from localstack.config import is_env_true
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.files import chmod_r

STARTUP_INFO_FILE = "startup_info.json"

# set up logger
LOG = logging.getLogger(__name__)


class PersistingProxyListener(ProxyListener, metaclass=ABCMeta):
    """
    This proxy listener could be extended by any API that wishes to record its requests and responses,
    via the existing persistence facility.
    """

    SKIP_PERSISTENCE_TARGET_METHOD_REGEX = re.compile(r".*\.List|.*\.Describe|.*\.Get")

    def return_response(self, method, path, data, headers, response):
        res = super(PersistingProxyListener, self).return_response(
            method, path, data, headers, response
        )
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
    """Decide whether a given API call should be recorded (persisted to disk)"""
    return method in ["PUT", "POST", "DELETE", "PATCH"]


def is_persistence_enabled():
    return config.PERSISTENCE and config.dirs.data


def is_persistence_restored():
    return not is_persistence_enabled()


class StartupInfo(NamedTuple):
    timestamp: str
    localstack_version: str
    localstack_ext_version: str
    pro_activated: bool


def save_startup_info():
    from localstack_ext import __version__ as localstack_ext_version

    file_path = os.path.join(config.dirs.data, STARTUP_INFO_FILE)

    info = StartupInfo(
        timestamp=datetime.datetime.now().isoformat(),
        localstack_version=constants.VERSION,
        localstack_ext_version=localstack_ext_version,
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
        infos = []
    else:
        with open(file_path, "r") as fd:
            infos = json.load(fd)

    infos.append(startup_info._asdict())
    with open(file_path, "w") as fd:
        json.dump(infos, fd)
