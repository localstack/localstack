import logging
import os
from typing import Dict, List, NamedTuple, Optional

import requests

from localstack import config, constants
from localstack.services import install
from localstack.utils.common import ShellCommandThread, chmod_r, is_root, mkdir, rm_rf
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


def get_opensearch_health_status(url: str) -> Optional[str]:
    """
    Queries the health endpoint of opensearch and returns either the status ('green', 'yellow',
    ...) or None if the response returned a non-200 response.
    """
    resp = requests.get(url + "/_cluster/health")

    if resp and resp.ok:
        opensearch_status = resp.json()
        opensearch_status = opensearch_status["status"]
        return opensearch_status

    return None


def init_directories(dirs: Directories):
    """
    Makes sure the directories exist and have the necessary permissions.
    """
    LOG.debug("initializing elasticsearch directories %s", dirs)
    chmod_r(dirs.install, 0o777)

    if not dirs.data.startswith(config.dirs.data):
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
    Determines directories to find the elasticsearch binary as well as where to store the instance data.

    :param version: the opensearch version (to resolve the install dir)
    :param cluster_path: the path between data_root and the actual data directories
    :param data_root: the root of the data dir (will be resolved to TMP_PATH or DATA_DIR by default)
    :returns: a Directories data structure
    """
    # where to find elasticsearch binary and the modules
    install_dir = install.get_opensearch_install_dir(version)
    modules_dir = os.path.join(install_dir, "modules")

    if data_root is None:
        if config.dirs.data:
            data_root = config.dirs.data
        else:
            data_root = config.dirs.tmp

    data_path = os.path.join(data_root, "opensearch", cluster_path)

    tmp_dir = os.path.join(data_path, "tmp")
    data_dir = os.path.join(data_path, "data")
    backup_dir = os.path.join(data_path, "backup")

    return Directories(install_dir, tmp_dir, modules_dir, data_dir, backup_dir)


def build_opensearch_run_command(opensearch_bin: str, settings: CommandSettings) -> List[str]:
    cmd_settings = [f"-E {k}={v}" for k, v, in settings.items()]
    return [opensearch_bin] + cmd_settings


class OpensearchCluster(Server):
    def __init__(
        self, port=9200, host="localhost", version: str = None, directories: Directories = None
    ) -> None:
        super().__init__(port, host)
        self._version = version or constants.OPENSEARCH_DEFAULT_VERSION

        self.command_settings = {}
        self.directories = directories or self._resolve_directories()

    @property
    def version(self):
        return self._version

    def health(self):
        return get_opensearch_health_status(self.url)

    def do_start_thread(self) -> FuncThread:
        # FIXME: if this fails the cluster could be left in a wonky state
        # FIXME: this is not a good place to run install, and it only works because we're
        #  assuming that there will only ever be one running Opensearch cluster
        install.install_opensearch(self.version)
        self._init_directories()

        cmd = self._create_run_command(additional_settings=self.command_settings)
        cmd = " ".join(cmd)

        # todo opensearch
        user = constants.OS_USER_ELASTICSEARCH
        if is_root() and user:
            # run the elasticsearch process as a non-root user (when running in docker)
            cmd = f"su {user} -c '{cmd}'"

        env_vars = self._create_env_vars()

        LOG.info("starting opensearch: %s with env %s", cmd, env_vars)
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

        bin_path = os.path.join(dirs.install, "bin/opensearch")

        # build command settings for bin/opensearch
        settings = {
            "http.port": self.port,
            "http.publish_port": self.port,
            "transport.port": "0",
            "network.host": self.host,
            "http.compression": "false",
            "path.data": f'"{dirs.data}"',
            "path.repo": f'"{dirs.backup}"',
            "plugins.security.disabled": "true",  # todo: should this stay?
        }

        if os.path.exists(os.path.join(dirs.mods, "x-pack-ml")):
            settings["xpack.ml.enabled"] = "false"

        if additional_settings:
            settings.update(additional_settings)

        self._settings_compatibility(settings)

        cmd = build_opensearch_run_command(bin_path, settings)

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
        # by default, the cluster data will be placed in <data_dir>/opensearch/<version>/
        return resolve_directories(version=self.version, cluster_path=self.version)

    def _init_directories(self):
        init_directories(self.directories)
