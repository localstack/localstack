import dataclasses
import logging
import os
import platform
from typing import Optional

from localstack import config, constants
from localstack.runtime import hooks
from localstack.utils.functions import call_safe
from localstack.utils.json import FileMappedDocument
from localstack.utils.objects import singleton_factory
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
        api_key=get_api_key_or_auth_token() or "",  # api key should not be None
        system=get_system(),
        version=get_version_string(),
        is_ci=os.getenv("CI") is not None,
        is_docker=config.is_in_docker,
        is_testing=config.is_local_test_mode(),
    )


@singleton_factory
def get_session_id() -> str:
    """
    Returns the unique ID for this LocalStack session.
    :return: a UUID
    """
    return _generate_session_id()


@singleton_factory
def get_client_metadata() -> ClientMetadata:
    metadata = read_client_metadata()

    if config.DEBUG_ANALYTICS:
        LOG.info("resolved client metadata: %s", metadata)

    return metadata


@singleton_factory
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
    try:
        # try to get a robust ID from the docker socket
        from localstack.utils.docker_utils import DOCKER_CLIENT

        docker_id = DOCKER_CLIENT.get_system_id()
        if docker_id:
            return f"d_{md5(docker_id)[:12]}"
    except Exception:
        pass

    if config.is_in_docker:
        return f"ls_{short_uid()}"

    # this can potentially be useful when generated on the host using the CLI and then mounted into the
    # container via machine.json
    try:
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id") as fd:
                return f"sys_{md5(str(fd.read()))[:12]}"
    except Exception:
        pass

    # always fall back to short_uid()
    return f"ls_{short_uid()}"


def get_api_key_or_auth_token() -> Optional[str]:
    # TODO: this is duplicated code from ext, but should probably migrate that to localstack
    auth_token = os.environ.get("LOCALSTACK_AUTH_TOKEN", "").strip("'\" ")
    if auth_token:
        return auth_token

    api_key = os.environ.get("LOCALSTACK_API_KEY", "").strip("'\" ")
    if api_key:
        return api_key

    return None


@singleton_factory
def get_system() -> str:
    try:
        # try to get the system from the docker socket
        from localstack.utils.docker_utils import DOCKER_CLIENT

        system = DOCKER_CLIENT.get_system_info()
        if system.get("OSType"):
            return system.get("OSType").lower()
    except Exception:
        pass

    if config.is_in_docker:
        return "docker"

    return platform.system().lower()
