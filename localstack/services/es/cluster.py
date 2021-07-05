"""
Higher-level abstraction to start elasticsearch using the elasticsearch binary.
Here's how you can use it:

    import time
    import threading

    cluster = ElasticsearchCluster(7541)

    def monitor():
        for i in range(60):
            if cluster.is_up():
                print('elasticsearch is up!', cluster.health())
                return
            else:
                print('sill waiting')

            time.sleep(1)

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
import multiprocessing
import os
import time
from typing import Dict, List, NamedTuple, Optional

import requests

from localstack import config, constants
from localstack.services import install
from localstack.services.infra import DEFAULT_BACKEND_HOST, do_run, start_proxy_for_service
from localstack.utils.common import (
    chmod_r,
    get_free_tcp_port,
    get_service_protocol,
    is_root,
    mkdir,
    rm_rf,
    start_thread,
)

LOG = logging.getLogger(__name__)

CommandSettings = Dict[str, str]

Directories = NamedTuple(
    "Directories", [("base", str), ("tmp", str), ("mods", str), ("data", str), ("backup", str)]
)


def _build_elasticsearch_run_command(es_bin: str, settings: CommandSettings) -> List[str]:
    cmd_settings = [f"-E {k}={v}" for k, v, in settings.items()]
    return [es_bin] + cmd_settings


class ElasticsearchCluster:
    def __init__(self, port=9200, host="localhost", version=None) -> None:
        super().__init__()
        self._port = port
        self._host = host
        self._version = version or constants.ELASTICSEARCH_DEFAULT_VERSION

        self.command_settings = {}

        self.directories = self._resolve_directories()

        self._elasticsearch_thread = None

        self._lifecycle_lock = multiprocessing.RLock()
        self._started = False
        self._stopped = multiprocessing.Event()
        self._starting = multiprocessing.Event()

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def version(self):
        return self._version

    @property
    def url(self):
        return "%s://%s:%s" % (get_service_protocol(), self.host, self.port)

    def is_up(self):
        if not self._started:
            return False
        if not self._starting.is_set():
            return False

        try:
            return self.health() is not None
        except Exception:
            return False

    def health(self):
        return get_elasticsearch_health_status(self.url)

    def shutdown(self):
        with self._lifecycle_lock:
            if not self._started:
                return

            if not self._elasticsearch_thread:
                return

            self._elasticsearch_thread.stop()

    def start(self):
        with self._lifecycle_lock:
            if self._started:
                return
            self._started = True

        start_thread(self._run_elasticsearch)

    def join(self, timeout=None):
        with self._lifecycle_lock:
            if not self._started:
                return

        if not self._elasticsearch_thread:
            self._starting.wait()

        return self._elasticsearch_thread.join(timeout=timeout)

    def _run_elasticsearch(self, *args):
        # *args is necessary for start_thread to work
        with self._lifecycle_lock:
            if self._elasticsearch_thread:
                return

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
            # use asynchronous=True to get a ShellCommandThread
            self._elasticsearch_thread = do_run(cmd, asynchronous=True, env_vars=env_vars)
            self._starting.set()

        # block until the thread running the command is done
        try:
            self._elasticsearch_thread.join()
        finally:
            LOG.info("elasticsearch process ended")
            self._stopped.set()

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

        cmd = _build_elasticsearch_run_command(bin_path, settings)

        return cmd

    def _create_env_vars(self) -> Dict:
        return {
            "ES_JAVA_OPTS": os.environ.get("ES_JAVA_OPTS", "-Xms200m -Xmx600m"),
            "ES_TMPDIR": self.directories.tmp,
        }

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


class ProxiedElasticsearchCluster:
    """
    Starts an ElasticsearchCluster behind a localstack service proxy. The ElasticsearchCluster
    backend will be assigned a random port.
    """

    def __init__(self, port=9200, host="localhost", version=None) -> None:
        super().__init__()
        self._port = port
        self._host = host
        self._version = version or constants.ELASTICSEARCH_DEFAULT_VERSION

        self._cluster = None
        self._backend_port = None
        self._proxy_thread = None

        self._lifecycle_lock = multiprocessing.RLock()
        self._started = False
        self._stopped = multiprocessing.Event()
        self._starting = multiprocessing.Event()

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def version(self):
        return self._version

    @property
    def url(self):
        return "%s://%s:%s" % (get_service_protocol(), self.host, self.port)

    def is_up(self):
        # check service lifecycle
        if not self._started:
            return False
        if not self._starting.is_set():
            return False
        if not self._cluster or not self._proxy_thread:
            return False

        # check that proxy is running
        if not self._proxy_thread.running:
            return False

        if not self._cluster.is_up():
            return False

        try:
            # calls health through the proxy to elasticsearch, making sure implicitly that both are
            # running
            LOG.info("calling health endpoint %s", self.url)
            return self.health() is not None
        except Exception:
            return False

    def health(self):
        """
        calls the health endpoint of elasticsearch through the proxy, making sure implicitly that
        both are running
        """
        return get_elasticsearch_health_status(self.url)

    def shutdown(self):
        with self._lifecycle_lock:
            if not self._started:
                return

            if self._proxy_thread:
                self._proxy_thread.stop()
            if self._cluster:
                self._cluster.shutdown()

    def start(self):
        with self._lifecycle_lock:
            if self._started:
                return
            self._started = True

        # start elasticsearch backend
        self._backend_port = get_free_tcp_port()
        self._cluster = ElasticsearchCluster(port=self._backend_port, host=DEFAULT_BACKEND_HOST)
        self._cluster.start()

        # start front-facing proxy
        self._proxy_thread = start_proxy_for_service(
            "elasticsearch",
            self.port,
            self._backend_port,
            update_listener=None,
            quiet=True,
            params={"protocol_version": "HTTP/1.0"},
        )

        self._starting.set()

    def join(self, timeout=None):
        with self._lifecycle_lock:
            if not self._started:
                return

        if not self._proxy_thread:
            self._starting.wait()

        then = time.time()

        if self._proxy_thread:
            self._proxy_thread.join(timeout=timeout)

        # subtract time already spent waiting, but wait at least another 100 ms
        timeout = max(0.1, (timeout - (time.time() - then)))

        self._cluster.join(timeout=timeout)


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
