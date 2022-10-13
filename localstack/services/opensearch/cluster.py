import logging
import os
from typing import Dict, List, NamedTuple, Optional
from urllib.parse import urlparse

import requests

from localstack import config, constants
from localstack.aws.api.opensearch import EngineType
from localstack.services.generic_proxy import EndpointProxy
from localstack.services.infra import DEFAULT_BACKEND_HOST
from localstack.services.opensearch import versions
from localstack.services.opensearch.packages import elasticsearch_package, opensearch_package
from localstack.utils.common import (
    ShellCommandThread,
    chmod_r,
    get_free_tcp_port,
    is_root,
    mkdir,
    rm_rf,
)
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)

CommandSettings = Dict[str, str]


class Directories(NamedTuple):
    install: str
    tmp: str
    mods: str
    data: str
    backup: str


def get_cluster_health_status(url: str) -> Optional[str]:
    """
    Queries the health endpoint of OpenSearch/Elasticsearch and returns either the status ('green', 'yellow',
    ...) or None if the response returned a non-200 response.
    """
    resp = requests.get(url + "/_cluster/health")

    if resp and resp.ok:
        opensearch_status = resp.json()
        opensearch_status = opensearch_status["status"]
        return opensearch_status

    return None


def init_directories(dirs: Directories):
    """Makes sure the directories exist and have the necessary permissions."""
    LOG.debug("initializing cluster directories %s", dirs)
    chmod_r(dirs.install, 0o777)

    if not config.dirs.data or not dirs.data.startswith(config.dirs.data):
        # only clear previous data if it's not in DATA_DIR
        rm_rf(dirs.data)

    rm_rf(dirs.tmp)
    mkdir(dirs.tmp)
    chmod_r(dirs.tmp, 0o777)

    mkdir(dirs.data)
    chmod_r(dirs.data, 0o777)

    mkdir(dirs.backup)
    chmod_r(dirs.backup, 0o777)

    # clear potentially existing lock files (which cause problems since ES 7.10)
    for d, dirs, files in os.walk(dirs.data, True):
        for f in files:
            if f.endswith(".lock"):
                rm_rf(os.path.join(d, f))


def resolve_directories(version: str, cluster_path: str, data_root: str = None) -> Directories:
    """
    Determines directories to find the opensearch binary as well as where to store the instance data.

    :param version: the full OpenSearch/Elasticsearch version (to resolve the install dir)
    :param cluster_path: the path between data_root and the actual data directories
    :param data_root: the root of the data dir (will be resolved to TMP_PATH or DATA_DIR by default)
    :returns: a Directories data structure
    """
    # where to find cluster binary and the modules
    engine_type, install_version = versions.get_install_type_and_version(version)
    install_dir = opensearch_package.get_installed_dir(version)

    modules_dir = os.path.join(install_dir, "modules")

    if not data_root:
        data_root = config.dirs.data or config.dirs.tmp

    if engine_type == EngineType.OpenSearch:
        data_path = os.path.join(data_root, "opensearch", cluster_path)
    else:
        data_path = os.path.join(data_root, "elasticsearch", cluster_path)

    tmp_dir = os.path.join(data_path, "tmp")
    data_dir = os.path.join(data_path, "data")
    backup_dir = os.path.join(data_path, "backup")

    return Directories(install_dir, tmp_dir, modules_dir, data_dir, backup_dir)


def build_cluster_run_command(cluster_bin: str, settings: CommandSettings) -> List[str]:
    """
    Takes the command settings dict and builds the actual command (which can then be executed as a shell command).

    :param cluster_bin: path to the OpenSearch/Elasticsearch binary (including the binary)
    :param settings: dictionary where each item will be set as a command arguments
    :return: list of strings for the command with the settings to be executed as a shell command
    """
    cmd_settings = [f"-E {k}={v}" for k, v, in settings.items()]
    return [cluster_bin] + cmd_settings


class OpensearchCluster(Server):
    """Manages an OpenSearch cluster which is installed and operated by LocalStack."""

    def __init__(self, port: int, arn: str, host: str = "localhost", version: str = None) -> None:
        super().__init__(port, host)
        self._version = version or self.default_version
        self.arn = arn

        self.command_settings = {}

    @property
    def default_version(self) -> str:
        return constants.OPENSEARCH_DEFAULT_VERSION

    @property
    def version(self) -> str:
        return self._version

    @property
    def install_version(self) -> str:
        _, install_version = versions.get_install_type_and_version(self._version)
        return install_version

    @property
    def bin_name(self) -> str:
        return "opensearch"

    @property
    def os_user(self):
        return constants.OS_USER_OPENSEARCH

    def health(self) -> Optional[str]:
        return get_cluster_health_status(self.url)

    def do_start_thread(self) -> FuncThread:
        self._ensure_installed()
        directories = resolve_directories(version=self.version, cluster_path=self.arn)
        init_directories(directories)

        cmd = self._create_run_command(
            directories=directories, additional_settings=self.command_settings
        )
        cmd = " ".join(cmd)

        if is_root() and self.os_user:
            # run the opensearch process as a non-root user (when running in docker)
            cmd = f"su {self.os_user} -c '{cmd}'"

        env_vars = self._create_env_vars(directories)

        LOG.info("starting %s: %s with env %s", self.bin_name, cmd, env_vars)
        t = ShellCommandThread(
            cmd,
            env_vars=env_vars,
            strip_color=True,
            log_listener=self._log_listener,
            name="opensearch-cluster",
        )
        t.start()
        return t

    def _ensure_installed(self):
        opensearch_package.install(self.version)

    def _base_settings(self, dirs) -> CommandSettings:
        settings = {
            "http.port": self.port,
            "http.publish_port": self.port,
            "transport.port": "0",
            "network.host": self.host,
            "http.compression": "false",
            "path.data": f'"{dirs.data}"',
            "path.repo": f'"{dirs.backup}"',
            "plugins.security.disabled": "true",
            "discovery.type": "single-node",
        }

        if os.path.exists(os.path.join(dirs.mods, "x-pack-ml")):
            settings["xpack.ml.enabled"] = "false"

        return settings

    def _create_run_command(
        self, directories: Directories, additional_settings: Optional[CommandSettings] = None
    ) -> List[str]:
        # delete opensearch data that may be cached locally from a previous test run
        bin_path = os.path.join(directories.install, "bin", self.bin_name)

        settings = self._base_settings(directories)

        if additional_settings:
            settings.update(additional_settings)

        cmd = build_cluster_run_command(bin_path, settings)
        return cmd

    def _create_env_vars(self, directories: Directories) -> Dict:
        return {
            "OPENSEARCH_JAVA_OPTS": os.environ.get("OPENSEARCH_JAVA_OPTS", "-Xms200m -Xmx600m"),
            "OPENSEARCH_TMPDIR": directories.tmp,
        }

    def _log_listener(self, line, **_kwargs):
        # logging the port before each line to be able to connect logs to specific instances
        LOG.info("[%s] %s", self.port, line.rstrip())


class CustomEndpoint:
    """
    Encapsulates a custom endpoint (combines CustomEndpoint and CustomEndpointEnabled within the DomainEndpointOptions
    of the cluster, i.e. combines two fields from the AWS OpenSearch service model).
    """

    enabled: bool
    endpoint: str

    def __init__(self, enabled: bool, endpoint: str) -> None:
        """
        :param enabled: true if the custom endpoint is enabled (refers to DomainEndpointOptions#CustomEndpointEnabled)
        :param endpoint: defines the endpoint (i.e. the URL - refers to DomainEndpointOptions#CustomEndpoint)
        """
        self.enabled = enabled
        self.endpoint = endpoint

        if self.endpoint:
            self.url = urlparse(endpoint)
        else:
            self.url = None


class EdgeProxiedOpensearchCluster(Server):
    """
    Opensearch-backed Server that can be routed through the edge proxy using an UrlMatchingForwarder to forward
    requests to the backend cluster.
    """

    def __init__(self, url: str, arn: str, version=None) -> None:
        self._url = urlparse(url)

        super().__init__(
            host=self._url.hostname,
            port=self._url.port,
        )
        self._version = version or self.default_version
        self.arn = arn

        self.cluster = None
        self.cluster_port = None
        self.proxy = None

    @property
    def version(self):
        return self._version

    @property
    def default_version(self):
        return constants.OPENSEARCH_DEFAULT_VERSION

    @property
    def url(self) -> str:
        return self._url.geturl()

    def is_up(self):
        # check service lifecycle
        if not self.cluster:
            return False

        if not self.cluster.is_up():
            return False

        return super().is_up()

    def health(self):
        """calls the health endpoint of cluster through the proxy, making sure implicitly that both are running"""
        return get_cluster_health_status(self.url)

    def _backend_cluster(self) -> OpensearchCluster:
        return OpensearchCluster(
            port=self.cluster_port,
            host=DEFAULT_BACKEND_HOST,
            arn=self.arn,
            version=self.version,
        )

    def do_run(self):
        self.cluster_port = get_free_tcp_port()
        self.cluster = self._backend_cluster()
        self.cluster.start()

        self.proxy = EndpointProxy(self.url, self.cluster.url)
        LOG.info("registering an endpoint proxy for %s => %s", self.url, self.cluster.url)
        self.proxy.register()

        self.cluster.wait_is_up()
        LOG.info("cluster on %s is ready", self.cluster.url)

        return self.cluster.join()

    def do_shutdown(self):
        if self.proxy:
            self.proxy.unregister()
        if self.cluster:
            self.cluster.shutdown()


class ElasticsearchCluster(OpensearchCluster):
    @property
    def default_version(self) -> str:
        return constants.ELASTICSEARCH_DEFAULT_VERSION

    @property
    def bin_name(self) -> str:
        return "elasticsearch"

    @property
    def os_user(self):
        return constants.OS_USER_OPENSEARCH

    def _ensure_installed(self):
        elasticsearch_package.install(self.version)

    def _base_settings(self, dirs) -> CommandSettings:
        settings = {
            "http.port": self.port,
            "http.publish_port": self.port,
            "transport.port": "0",
            "network.host": self.host,
            "http.compression": "false",
            "path.data": f'"{dirs.data}"',
            "path.repo": f'"{dirs.backup}"',
            "discovery.type": "single-node",
        }

        if os.path.exists(os.path.join(dirs.mods, "x-pack-ml")):
            settings["xpack.ml.enabled"] = "false"

        return settings

    def _create_env_vars(self, directories: Directories) -> Dict:
        return {
            "ES_JAVA_OPTS": os.environ.get("ES_JAVA_OPTS", "-Xms200m -Xmx600m"),
            "ES_TMPDIR": directories.tmp,
        }


class EdgeProxiedElasticsearchCluster(EdgeProxiedOpensearchCluster):
    @property
    def default_version(self):
        return constants.ELASTICSEARCH_DEFAULT_VERSION

    def _backend_cluster(self) -> OpensearchCluster:
        return ElasticsearchCluster(
            port=self.cluster_port, host=DEFAULT_BACKEND_HOST, arn=self.arn, version=self.version
        )
