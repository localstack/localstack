import dataclasses
import logging
import os
import platform
from typing import Optional

from localstack import config
from localstack.constants import VERSION
from localstack.runtime import get_current_runtime, hooks
from localstack.utils.bootstrap import Container
from localstack.utils.files import rm_rf
from localstack.utils.functions import call_safe
from localstack.utils.json import FileMappedDocument
from localstack.utils.objects import singleton_factory
from localstack.utils.strings import long_uid, md5

LOG = logging.getLogger(__name__)

_PHYSICAL_ID_SALT = "ls"


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
    product: str
    edition: str

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
        return f"{VERSION}:{gh}"
    else:
        return VERSION


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
        product=get_localstack_product(),
        edition=os.getenv("LOCALSTACK_TELEMETRY_EDITION") or get_localstack_edition(),
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
    try:
        doc = FileMappedDocument(cache_path)
    except Exception:
        # it's possible that the file is somehow messed up, so we try to delete the file first and try again.
        # if that fails, we return a generated ID.
        call_safe(rm_rf, args=(cache_path,))

        try:
            doc = FileMappedDocument(cache_path)
        except Exception:
            return _generate_machine_id()

    if "machine_id" not in doc:
        # generate a machine id
        doc["machine_id"] = _generate_machine_id()
        # try to cache the machine ID
        call_safe(doc.save)

    return doc["machine_id"]


def get_localstack_edition() -> str:
    # Generator expression to find the first hidden file ending with '-version'
    version_file = next(
        (
            f
            for f in os.listdir(config.dirs.static_libs)
            if f.startswith(".") and f.endswith("-version")
        ),
        None,
    )

    # Return the base name of the version file, or unknown if no file is found
    return version_file.removesuffix("-version").removeprefix(".") if version_file else "unknown"


def get_localstack_product() -> str:
    """
    Returns the telemetry product name from the env var, runtime, or "unknown".
    """
    try:
        runtime_product = get_current_runtime().components.name
    except ValueError:
        runtime_product = None

    return os.getenv("LOCALSTACK_TELEMETRY_PRODUCT") or runtime_product or "unknown"


def is_license_activated() -> bool:
    try:
        from localstack.pro.core import config  # noqa
    except ImportError:
        return False

    try:
        from localstack.pro.core.bootstrap import licensingv2

        return licensingv2.get_licensed_environment().activated
    except Exception:
        LOG.exception("Could not determine license activation status")
        return False


def _generate_session_id() -> str:
    return long_uid()


def _anonymize_physical_id(physical_id: str) -> str:
    """
    Returns 12 digits of the salted hash of the given physical ID.

    :param physical_id: the physical id
    :return: an anonymized 12 digit value representing the physical ID.
    """
    hashed = md5(_PHYSICAL_ID_SALT + physical_id)
    return hashed[:12]


def _generate_machine_id() -> str:
    try:
        # try to get a robust ID from the docker socket (which will be the same from the host and the
        # container)
        from localstack.utils.docker_utils import DOCKER_CLIENT

        docker_id = DOCKER_CLIENT.get_system_id()
        # some systems like podman don't return a stable ID, so we double-check that here
        if docker_id == DOCKER_CLIENT.get_system_id():
            return f"dkr_{_anonymize_physical_id(docker_id)}"
    except Exception:
        pass

    if config.is_in_docker:
        return f"gen_{long_uid()[:12]}"

    # this can potentially be useful when generated on the host using the CLI and then mounted into the
    # container via machine.json
    try:
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id") as fd:
                machine_id = str(fd.read()).strip()
                if machine_id:
                    return f"sys_{_anonymize_physical_id(machine_id)}"
    except Exception:
        pass

    # always fall back to a generated id
    return f"gen_{long_uid()[:12]}"


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


@hooks.prepare_host()
def prepare_host_machine_id():
    # lazy-init machine ID into cache on the host, which can then be used in the container
    get_machine_id()


@hooks.configure_localstack_container()
def _mount_machine_file(container: Container):
    from localstack.utils.container_utils.container_client import BindMount

    # mount tha machine file from the host's CLI cache directory into the appropriate location in the
    # container
    machine_file = os.path.join(config.dirs.cache, "machine.json")
    if os.path.isfile(machine_file):
        target = os.path.join(config.dirs.for_container().cache, "machine.json")
        container.config.volumes.add(BindMount(machine_file, target, read_only=True))
