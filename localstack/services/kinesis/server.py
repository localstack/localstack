import logging
import os
import platform
from typing import Optional, Tuple, List
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server
from localstack import config
from localstack.services import install
from localstack.utils.common import TMP_THREADS, ShellCommandThread, get_free_tcp_port, mkdir
from localstack.utils.common import (
    chmod_r,
    get_free_tcp_port,
    mkdir,
)


LOG = logging.getLogger(__name__)

def _get_kinesis_mock_bin_file_and_path() -> Tuple[str, str]:
    target_dir = install.INSTALL_PATH_KINESIS_MOCK
    machine = platform.machine().lower()
    system = platform.system().lower()
    version = platform.version().lower()
    is_probably_m1 = system == "darwin" and ("arm64" in version or "arm32" in version)

    LOG.debug("getting kinesis-mock for %s %s", system, machine)
    if config.is_env_true("KINESIS_MOCK_FORCE_JAVA"):  # TODO: set this in constructor
        # sometimes the static binaries may have problems, and we want to fal back to Java
        bin_file = "kinesis-mock.jar"
    elif (machine == "x86_64" or machine == "amd64") and not is_probably_m1:
        if system == "windows":
            bin_file = "kinesis-mock-mostly-static.exe"
        elif system == "linux":
            bin_file = "kinesis-mock-linux-amd64-static"
        elif system == "darwin":
            bin_file = "kinesis-mock-macos-amd64-dynamic"
        else:
            bin_file = "kinesis-mock.jar"
    else:
        bin_file = "kinesis-mock.jar"
    bin_file_path = os.path.join(target_dir, bin_file)
    return bin_file, bin_file_path


class KinesisServer(Server):

    def __init__(self, port: int, host: str = "localhost") -> None:
        super().__init__(port, host)

    def health(self):
        return super().health()

    def do_run(self):
        super().do_run()

    def do_shutdown(self):
        super().do_shutdown()

    def do_start_thread(self) -> FuncThread:
        bin_file, bin_file_path, cmd = self._create_shell_command()

        install.install_kinesis_mock(bin_file, bin_file_path)
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

    def _create_shell_command(self) -> Tuple[str, str, str]:
        # TODO kinesalite
        kinesis_mock_bin, kinesis_mock_bin_path = _get_kinesis_mock_bin_file_and_path()
        kinesis_data_dir_param = ""
        if config.dirs.data:  # TODO: move this to create_kinesis_server and/or class property
            kinesis_data_dir = "%s/kinesis" % config.dirs.data
            mkdir(kinesis_data_dir)
            kinesis_data_dir_param = "SHOULD_PERSIST_DATA=true PERSIST_PATH=%s" % kinesis_data_dir
        if not config.LS_LOG:
            log_level = "INFO"
        elif config.LS_LOG == "warning":
            log_level = "WARN"
        else:
            log_level = config.LS_LOG.upper()
        log_level_param = "LOG_LEVEL=%s" % log_level
        latency = config.KINESIS_LATENCY + "ms"
        latency_param = (
            "CREATE_STREAM_DURATION={l} DELETE_STREAM_DURATION={l} REGISTER_STREAM_CONSUMER_DURATION={l} "
            "START_STREAM_ENCRYPTION_DURATION={l} STOP_STREAM_ENCRYPTION_DURATION={l} "
            "DEREGISTER_STREAM_CONSUMER_DURATION={l} MERGE_SHARDS_DURATION={l} SPLIT_SHARD_DURATION={l} "
            "UPDATE_SHARD_COUNT_DURATION={l}"
        ).format(l=latency)

        if config.KINESIS_INITIALIZE_STREAMS != "":
            initialize_streams_param = "INITIALIZE_STREAMS=%s" % config.KINESIS_INITIALIZE_STREAMS
        else:
            initialize_streams_param = ""

        if kinesis_mock_bin.endswith(".jar"):
            cmd = "KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s java -XX:+UseG1GC -jar %s" % (
                self.port,
                config.KINESIS_SHARD_LIMIT,
                latency_param,
                kinesis_data_dir_param,
                log_level_param,
                initialize_streams_param,
                kinesis_mock_bin_path,
            )
        else:
            chmod_r(kinesis_mock_bin, 0o777)
            cmd = "KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s %s --gc=G1" % (
                self.port,
                config.KINESIS_SHARD_LIMIT,
                latency_param,
                kinesis_data_dir_param,
                log_level_param,
                initialize_streams_param,
                kinesis_mock_bin_path,
            )
        return kinesis_mock_bin, kinesis_mock_bin_path, cmd

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())

def create_kinesis_server(port=None) -> KinesisServer:
    port = port or get_free_tcp_port()
    server = KinesisServer(port)
    #TODO: mk data dir and set class properties here
    return server
