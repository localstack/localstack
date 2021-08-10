import dataclasses
import functools
import json
import logging
import os
import platform

from localstack import config, constants
from localstack.utils import common

LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class ClientMetadata:
    session_id: str
    machine_id: str
    api_key: str
    system: str
    version: str
    is_ci: bool
    is_docker: bool
    is_testing: bool

    def __repr__(self):
        d = dataclasses.asdict(self)

        # anonymize api_key
        k = d.get("api_key")
        if k:
            k = "*" * len(k)
        d["api_key"] = k

        return "ClientMetadata(%s)" % d


def get_version_string() -> str:
    gh = config.LOCALSTACK_BUILD_GIT_HASH
    if gh:
        return f"{constants.VERSION}:{gh}"
    else:
        return constants.VERSION


def read_client_metadata() -> ClientMetadata:
    return ClientMetadata(
        session_id=get_session_id(),
        machine_id=get_machine_id(),
        api_key=read_api_key_safe(),
        system=get_system(),
        version=get_version_string(),
        is_ci=os.getenv("CI") is not None,
        is_docker=config.is_in_docker,
        is_testing=config.is_env_true(constants.ENV_INTERNAL_TEST_RUN),
    )


@functools.lru_cache()
def get_session_id() -> str:
    return _generate_session_id()


@functools.lru_cache()
def get_client_metadata() -> ClientMetadata:
    metadata = read_client_metadata()

    if config.DEBUG_ANALYTICS:
        LOG.info("resolved client metadata: %s", metadata)

    return metadata


@functools.lru_cache()
def get_machine_id() -> str:
    machine_id = None
    # determine machine_id from config files
    configs_map = {}
    # TODO check if this distinction is needed - config.CONFIG_FILE_PATH already handles tmp vs home folder
    config_file_tmp = get_config_file_tempdir()
    config_file_home = get_config_file_homedir()
    for config_file in (config_file_home, config_file_tmp):
        if config_file:
            local_configs = configs_map[config_file] = config.load_config_file(
                config_file=config_file
            )
            if "machine_id" in local_configs:
                machine_id = local_configs["machine_id"]
                break

    # if we can neither find NOR create the config files, fall back to process id
    if not configs_map:
        return get_session_id()

    # assign default id if empty
    if not machine_id:
        machine_id = common.short_uid()

    # update machine_id in all config files
    for config_file, configs in configs_map.items():
        configs["machine_id"] = machine_id
        common.save_file(config_file, json.dumps(configs))

    return machine_id


def _generate_session_id() -> str:
    return common.long_uid()


def _get_config_file(path):
    common.get_or_create_file(path)
    return path


def get_config_file_homedir():
    return _get_config_file(config.CONFIG_FILE_PATH)


def get_config_file_tempdir():
    return _get_config_file(os.path.join(config.TMP_FOLDER, ".localstack"))


def read_api_key_safe():
    try:
        from localstack_ext.bootstrap.licensing import read_api_key

        return read_api_key(raise_if_missing=False)
    except Exception:
        return None


def get_system() -> str:
    return platform.system()
