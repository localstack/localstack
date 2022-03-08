import dataclasses
import functools
import logging
import os
import platform

from localstack import config, constants
from localstack.runtime import hooks
from localstack.utils.functions import call_safe
from localstack.utils.json import FileMappedDocument
from localstack.utils.strings import long_uid, md5, short_uid

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
        is_testing=config.is_local_test_mode(),
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
    cache_path = os.path.join(config.dirs.cache, "machine.json")
    doc = FileMappedDocument(cache_path)

    if "machine_id" not in doc:
        # generate a machine id
        doc["machine_id"] = _generate_machine_id()
        # try to cache the machine ID
        call_safe(doc.save)

    return doc["machine_id"]


@hooks.prepare_host()
def prepare_host_machine_id():
    # lazy-init machine ID into cache on the host, which can then be used in the container
    get_machine_id()


def _generate_session_id() -> str:
    return long_uid()


def _generate_machine_id() -> str:
    if config.is_in_docker:
        return short_uid()

    # this can potentially be useful when generated on the host using the CLI and then mounted into the container via
    # machine.json
    try:
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id") as fd:
                return md5(str(fd.read()))[:8]
    except Exception:
        pass

    # always fall back to short_uid()
    return short_uid()


def read_api_key_safe():
    try:
        from localstack_ext.bootstrap.licensing import read_api_key

        return read_api_key(raise_if_missing=False)
    except Exception:
        return None


def get_system() -> str:
    return platform.system()
