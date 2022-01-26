import logging
from typing import Optional

from localstack import config
from localstack.services import install
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
        host: str = "localhost",
        log_level: str = "INFO",
        data_dir: Optional[str] = None,
        initialize_streams: Optional[str] = None,
    ) -> None:
        self._latency = latency
        self._initialize_streams = initialize_streams
        self._data_dir = data_dir
        self._bin_path = bin_path
        self._log_level = log_level
        super().__init__(port, host)

    def do_start_thread(self) -> FuncThread:
        cmd = self._create_shell_command()
        LOG.debug("starting kinesis process %s", cmd)
        t = ShellCommandThread(
            cmd,
            strip_color=True,
            log_listener=self._log_listener,
            auto_restart=True,
        )
        TMP_THREADS.append(t)
        t.start()
        return t

    def _create_shell_command(self) -> str:
        """
        helper method for creating kinesis mock invocation command
        """
        if self._data_dir:
            kinesis_data_dir_param = "SHOULD_PERSIST_DATA=true PERSIST_PATH=%s" % self._data_dir
        else:
            kinesis_data_dir_param = ""
        log_level_param = "LOG_LEVEL=%s" % self._log_level
        latency_param = (
            "CREATE_STREAM_DURATION={l} DELETE_STREAM_DURATION={l} REGISTER_STREAM_CONSUMER_DURATION={l} "
            "START_STREAM_ENCRYPTION_DURATION={l} STOP_STREAM_ENCRYPTION_DURATION={l} "
            "DEREGISTER_STREAM_CONSUMER_DURATION={l} MERGE_SHARDS_DURATION={l} SPLIT_SHARD_DURATION={l} "
            "UPDATE_SHARD_COUNT_DURATION={l}"
        ).format(l=self._latency)
        init_streams_param = (
            "INITIALIZE_STREAMS=%s" % self._initialize_streams if self._initialize_streams else ""
        )

        if self._bin_path.endswith(".jar"):
            cmd = (
                "KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s java -XX:+UseG1GC -jar %s"
                % (
                    self.port,
                    config.KINESIS_SHARD_LIMIT,
                    latency_param,
                    kinesis_data_dir_param,
                    log_level_param,
                    init_streams_param,
                    self._bin_path,
                )
            )
        else:
            chmod_r(self._bin_path, 0o777)
            cmd = "KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s %s --gc=G1" % (
                self.port,
                config.KINESIS_SHARD_LIMIT,
                latency_param,
                kinesis_data_dir_param,
                log_level_param,
                init_streams_param,
                self._bin_path,
            )
        return cmd

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())


def create_kinesis_mock_server(port=None) -> KinesisMockServer:
    """
    Creates a new Kinesis Mock server instance. Installs Kinesis Mock on the host first if necessary.
    Introspects on the host config to determine server configuration:
    config.dirs.data -> if set, the server runs with persistence using the path to store data
    config.LS_LOG -> configure kinesis mock log level (defaults to INFO)
    config.KINESIS_LATENCY -> configure stream latency (in milliseconds)
    config.KINESIS_INITIALIZE_STREAMS -> Initialize the given streams on startup
    """
    port = port or get_free_tcp_port()
    is_kinesis_mock_installed, kinesis_mock_bin_path = install.get_is_kinesis_mock_installed()
    if not is_kinesis_mock_installed:
        install.install_kinesis_mock(kinesis_mock_bin_path)
    if config.dirs.data:
        kinesis_data_dir = "%s/kinesis" % config.dirs.data
        mkdir(kinesis_data_dir)
    else:
        kinesis_data_dir = None

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
        data_dir=kinesis_data_dir,
    )
    return server
