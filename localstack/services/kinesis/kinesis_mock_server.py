import logging
from typing import Dict, List, Optional, Tuple

from localstack import config
from localstack.services.kinesis.packages import kinesismock_package
from localstack.utils.common import (
    TMP_THREADS,
    ShellCommandThread,
    chmod_r,
    get_free_tcp_port,
    mkdir,
)
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)


class KinesisMockServer(Server):
    """
    Server abstraction for controlling Kinesis Mock in a separate thread
    """

    def __init__(
        self,
        port: int,
        bin_path: str,
        latency: str,
        account_id: str,
        host: str = "localhost",
        log_level: str = "INFO",
        data_dir: Optional[str] = None,
        initialize_streams: Optional[str] = None,
    ) -> None:
        self._account_id = account_id
        self._latency = latency
        self._initialize_streams = initialize_streams
        self._data_dir = data_dir
        self._data_filename = f"{self._account_id}.json"
        self._bin_path = bin_path
        self._log_level = log_level
        super().__init__(port, host)

    def do_start_thread(self) -> FuncThread:
        cmd, env_vars = self._create_shell_command()
        LOG.debug("starting kinesis process %s with env vars %s", cmd, env_vars)
        t = ShellCommandThread(
            cmd,
            strip_color=True,
            env_vars=env_vars,
            log_listener=self._log_listener,
            auto_restart=True,
            name="kinesis-mock",
        )
        TMP_THREADS.append(t)
        t.start()
        return t

    def _create_shell_command(self) -> Tuple[List, Dict]:
        """
        Helper method for creating kinesis mock invocation command
        :return: returns a tuple containing the command list and a dictionary with the environment variables
        """
        env_vars = {
            "KINESIS_MOCK_PLAIN_PORT": self.port,
            # Each kinesis-mock instance listens to two ports - secure and insecure.
            # LocalStack uses only one - the insecure one. Block the secure port to avoid conflicts.
            "KINESIS_MOCK_TLS_PORT": get_free_tcp_port(),
            "SHARD_LIMIT": config.KINESIS_SHARD_LIMIT,
            "ON_DEMAND_STREAM_COUNT_LIMIT": config.KINESIS_ON_DEMAND_STREAM_COUNT_LIMIT,
            "AWS_ACCOUNT_ID": self._account_id,
        }

        latency_params = [
            "CREATE_STREAM_DURATION",
            "DELETE_STREAM_DURATION",
            "REGISTER_STREAM_CONSUMER_DURATION",
            "START_STREAM_ENCRYPTION_DURATION",
            "STOP_STREAM_ENCRYPTION_DURATION",
            "DEREGISTER_STREAM_CONSUMER_DURATION",
            "MERGE_SHARDS_DURATION",
            "SPLIT_SHARD_DURATION",
            "UPDATE_SHARD_COUNT_DURATION",
            "UPDATE_STREAM_MODE_DURATION",
        ]
        for param in latency_params:
            env_vars[param] = self._latency

        if self._data_dir:
            env_vars["SHOULD_PERSIST_DATA"] = "true"
            env_vars["PERSIST_PATH"] = self._data_dir
            env_vars["PERSIST_FILE_NAME"] = self._data_filename
            env_vars["PERSIST_INTERVAL"] = config.KINESIS_MOCK_PERSIST_INTERVAL

        env_vars["LOG_LEVEL"] = self._log_level
        if self._initialize_streams:
            env_vars["INITIALIZE_STREAMS"] = self._initialize_streams

        if self._bin_path.endswith(".jar"):
            cmd = ["java", "-XX:+UseG1GC", "-jar", self._bin_path]
        else:
            chmod_r(self._bin_path, 0o777)
            cmd = [self._bin_path, "--gc=G1"]
        return cmd, env_vars

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())


def create_kinesis_mock_server(
    account_id: str, port=None, persist_path: Optional[str] = None
) -> KinesisMockServer:
    """
    Creates a new Kinesis Mock server instance. Installs Kinesis Mock on the host first if necessary.
    Introspects on the host config to determine server configuration:
    config.dirs.data -> if set, the server runs with persistence using the path to store data
    config.LS_LOG -> configure kinesis mock log level (defaults to INFO)
    config.KINESIS_LATENCY -> configure stream latency (in milliseconds)
    config.KINESIS_INITIALIZE_STREAMS -> Initialize the given streams on startup
    """
    port = port or get_free_tcp_port()
    kinesismock_package.install()
    kinesis_mock_bin_path = kinesismock_package.get_installer().get_executable_path()
    persist_path = (
        f"{config.dirs.data}/kinesis" if not persist_path and config.dirs.data else persist_path
    )
    if persist_path:
        mkdir(persist_path)

    if config.LS_LOG:
        if config.LS_LOG == "warning":
            log_level = "WARN"
        else:
            log_level = config.LS_LOG.upper()
    else:
        log_level = "INFO"

    latency = config.KINESIS_LATENCY + "ms"
    initialize_streams = (
        config.KINESIS_INITIALIZE_STREAMS if config.KINESIS_INITIALIZE_STREAMS else None
    )

    server = KinesisMockServer(
        port=port,
        bin_path=kinesis_mock_bin_path,
        log_level=log_level,
        latency=latency,
        initialize_streams=initialize_streams,
        data_dir=persist_path,
        account_id=account_id,
    )
    return server
