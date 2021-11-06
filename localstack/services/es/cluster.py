"""
Higher-level abstraction to start elasticsearch using the elasticsearch binary.
Here's how you can use it:

    import time
    import threading

    cluster = ElasticsearchCluster(7541)

    def monitor():
        cluster.wait_is_up()
        print('elasticsearch is up!', cluster.health())

    threading.Thread(target=monitor, daemon=True).start()

    try:
        cluster.start()
        cluster.join()
    except KeyboardInterrupt:
        cluster.shutdown()
    finally:
        print('ok, bye')
"""
import logging
import os
from typing import Dict, List, NamedTuple, Optional
from urllib.parse import urlparse

import requests

from localstack import config, constants
from localstack.services import install
from localstack.services.generic_proxy import ProxyListener, UrlMatchingForwarder
from localstack.services.infra import DEFAULT_BACKEND_HOST, start_proxy_for_service
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
    base: str
    tmp: str
    mods: str
    data: str
    backup: str


def _build_elasticsearch_run_command(es_bin: str, settings: CommandSettings) -> List[str]:
    cmd_settings = [f"-E {k}={v}" for k, v, in settings.items()]
    return [es_bin] + cmd_settings


class ElasticsearchCluster(Server):
    def __init__(self, port=9200, host="localhost", version=None) -> None:
        super().__init__(port, host)
        self._version = version or constants.ELASTICSEARCH_DEFAULT_VERSION

        self.command_settings = {}
        self.directories = self._resolve_directories()

    @property
    def version(self):
        return self._version

    def health(self):
        return get_elasticsearch_health_status(self.url)

    def do_start_thread(self) -> FuncThread:
        # FIXME: if this fails the cluster could be left in a wonky state
        # FIXME: this is not a good place to run install, and it only works because we're
        #  assuming that there will only ever be one running Elasticsearch cluster
        install.install_elasticsearch(self.version)
        self._init_directories()

        cmd = self._create_run_command(additional_settings=self.command_settings)
        cmd = " ".join(cmd)

        user = constants.OS_USER_ELASTICSEARCH
        if is_root() and user:
            # run the elasticsearch process as a non-root user (when running in docker)
            cmd = f"su {user} -c '{cmd}'"

        env_vars = self._create_env_vars()

        LOG.info("starting elasticsearch: %s with env %s", cmd, env_vars)
        t = ShellCommandThread(
            cmd,
            env_vars=env_vars,
            strip_color=True,
            log_listener=self._log_listener,
        )
        t.start()
        return t

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())

    def _create_run_command(
        self, additional_settings: Optional[CommandSettings] = None
    ) -> List[str]:
        # delete Elasticsearch data that may be cached locally from a previous test run
        dirs = self.directories

        bin_path = os.path.join(dirs.base, "bin/elasticsearch")

        # build command settings for bin/elasticsearch
        settings = {
            "http.port": self.port,
            "http.publish_port": self.port,
            "transport.port": "0",
            "network.host": self.host,
            "http.compression": "false",
            "path.data": f'"{dirs.data}"',
            "path.repo": f'"{dirs.backup}"',
        }

        if os.path.exists(os.path.join(dirs.mods, "x-pack-ml")):
            settings["xpack.ml.enabled"] = "false"

        if additional_settings:
            settings.update(additional_settings)

        self._settings_compatibility(settings)

        cmd = _build_elasticsearch_run_command(bin_path, settings)

        return cmd

    def _create_env_vars(self) -> Dict:
        return {
            "ES_JAVA_OPTS": os.environ.get("ES_JAVA_OPTS", "-Xms200m -Xmx600m"),
            "ES_TMPDIR": self.directories.tmp,
        }

    def _settings_compatibility(self, settings):
        # compatibility hacks for older versions
        if int(self.version.split(".")[0]) <= 5:
            settings["transport.tcp.port"] = settings["transport.port"]
            del settings["transport.port"]

    def _resolve_directories(self) -> Directories:
        # determine various directory paths
        base_dir = install.get_elasticsearch_install_dir(self.version)

        es_tmp_dir = os.path.join(base_dir, "tmp")
        es_mods_dir = os.path.join(base_dir, "modules")
        if config.DATA_DIR:
            es_data_dir = os.path.join(config.DATA_DIR, "elasticsearch")
        else:
            es_data_dir = os.path.join(base_dir, "data")
        backup_dir = os.path.join(config.TMP_FOLDER, "es_backup")

        return Directories(base_dir, es_tmp_dir, es_mods_dir, es_data_dir, backup_dir)

    def _init_directories(self):
        dirs = self.directories

        LOG.debug("initializing elasticsearch directories %s", dirs)
        chmod_r(dirs.base, 0o777)

        if not dirs.data.startswith(config.DATA_DIR):
            # only clear previous data if it's not in DATA_DIR
            rm_rf(dirs.data)

        mkdir(dirs.data)
        chmod_r(dirs.data, 0o777)

        rm_rf(dirs.tmp)
        mkdir(dirs.tmp)
        chmod_r(dirs.tmp, 0o777)

        # clear potentially existing lock files (which cause problems since ES 7.10)
        for d, dirs, files in os.walk(dirs.data, True):
            for f in files:
                if f.endswith(".lock"):
                    rm_rf(os.path.join(d, f))


class ProxiedElasticsearchCluster(Server):
    """
    Starts an ElasticsearchCluster behind a localstack service proxy. The ElasticsearchCluster
    backend will be assigned a random port.
    """

    def __init__(self, port=9200, host="localhost", version=None) -> None:
        super().__init__(port, host)
        self._version = version or constants.ELASTICSEARCH_DEFAULT_VERSION

        self.cluster = None
        self.cluster_port = None

    @property
    def version(self):
        return self._version

    def is_up(self):
        # check service lifecycle
        if not self.cluster:
            return False

        if not self.cluster.is_up():
            return False

        return super().is_up()

    def health(self):
        """
        calls the health endpoint of elasticsearch through the proxy, making sure implicitly that
        both are running
        """
        return get_elasticsearch_health_status(self.url)

    def do_start_thread(self) -> FuncThread:
        # start elasticsearch backend
        if not self.cluster_port:
            self.cluster_port = get_free_tcp_port()

        self.cluster = ElasticsearchCluster(
            port=self.cluster_port, host=DEFAULT_BACKEND_HOST, version=self.version
        )
        self.cluster.start()

        self.cluster.wait_is_up()
        LOG.info("elasticsearch cluster on %s is ready", self.cluster.url)

        # start front-facing proxy
        return start_proxy_for_service(
            "elasticsearch",
            self.port,
            self.cluster_port,
            update_listener=None,
            quiet=True,
            params={"protocol_version": "HTTP/1.0"},
        )

    def do_shutdown(self):
        self.cluster.shutdown()


class CustomEndpoint:
    enabled: bool
    endpoint: str

    def __init__(self, enabled: bool, endpoint: str) -> None:
        self.enabled = enabled
        self.endpoint = endpoint

        if self.endpoint:
            self.url = urlparse(endpoint)
        else:
            self.url = None


class EndpointProxy(ProxyListener):
    def __init__(self, base_url: str, cluster_url: str) -> None:
        super().__init__()
        self.forwarder = UrlMatchingForwarder(
            base_url=base_url,
            forward_url=cluster_url,
        )
        self.forward_request = self.forwarder.forward_request

    def register(self):
        ProxyListener.DEFAULT_LISTENERS.append(self)

    def unregister(self):
        ProxyListener.DEFAULT_LISTENERS.remove(self)


class EdgeProxiedElasticsearchCluster(Server):
    """
    Elasticsearch-backed Server that can be routed through the edge proxy using an UrlMatchingForwarder to forward
    requests to the backend cluster.
    """

    def __init__(self, url: str, version=None) -> None:
        self._url = urlparse(url)

        super().__init__(
            host=self._url.hostname,
            port=self._url.port,
        )
        self._version = version or constants.ELASTICSEARCH_DEFAULT_VERSION

        self.cluster = None
        self.cluster_port = None
        self.proxy = None

    @property
    def version(self):
        return self._version

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
        """
        calls the health endpoint of elasticsearch through the proxy, making sure implicitly that
        both are running
        """
        return get_elasticsearch_health_status(self.url)

    def do_run(self):
        self.cluster_port = get_free_tcp_port()
        self.cluster = ElasticsearchCluster(
            port=self.cluster_port, host=DEFAULT_BACKEND_HOST, version=self.version
        )
        self.cluster.start()

        self.proxy = EndpointProxy(self.url, self.cluster.url)
        LOG.info("registering an endpoint proxy for %s => %s", self.url, self.cluster.url)
        self.proxy.register()

        self.cluster.wait_is_up()
        LOG.info("elasticsearch cluster on %s is ready", self.cluster.url)

        return self.cluster.join()

    def do_shutdown(self):
        if self.proxy:
            self.proxy.unregister()
        if self.cluster:
            self.cluster.shutdown()


def get_elasticsearch_health_status(url: str) -> Optional[str]:
    """
    Queries the health endpoint of elasticsearch and returns either the status ('green', 'yellow',
    ...) or None if the response returned a non-200 response.
    """
    resp = requests.get(url + "/_cluster/health")

    if resp and resp.ok:
        es_status = resp.json()
        es_status = es_status["status"]
        return es_status

    return None
