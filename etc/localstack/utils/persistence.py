import datetime
import json
import logging
import os
from typing import NamedTuple

from localstack import config, constants
from localstack.config import is_env_true
from localstack.utils.files import chmod_r

STARTUP_INFO_FILE = "startup_info.json"

# set up logger
LOG = logging.getLogger(__name__)


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
