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


class KinesisServer(Server):
    def __init__(self, port: int, bin_path: str, host: str = "localhost") -> None:
        self._bin_path = bin_path
        super().__init__(port, host)

    @property
    def bin_path(self) -> str:
        return self._bin_path

    def health(self):
        return super().health()

    def do_run(self):
        super().do_run()

    def do_shutdown(self):
        super().do_shutdown()

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
        # TODO kinesalite
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

        if self.bin_path.endswith(".jar"):
            cmd = "KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s java -XX:+UseG1GC -jar %s" % (
                self.port,
                config.KINESIS_SHARD_LIMIT,
                latency_param,
                kinesis_data_dir_param,
                log_level_param,
                initialize_streams_param,
                self.bin_path,
            )
        else:
            chmod_r(self.bin_path, 0o777)
            cmd = "KINESIS_MOCK_PLAIN_PORT=%s SHARD_LIMIT=%s %s %s %s %s %s --gc=G1" % (
                self.port,
                config.KINESIS_SHARD_LIMIT,
                latency_param,
                kinesis_data_dir_param,
                log_level_param,
                initialize_streams_param,
                self.bin_path,
            )
        return cmd

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())


def create_kinesis_server(port=None) -> KinesisServer:
    port = port or get_free_tcp_port()
    is_kinesis_mock_installed, kinesis_mock_bin_path = install.get_is_kinesis_mock_installed()
    if not is_kinesis_mock_installed:
        install.install_kinesis_mock(kinesis_mock_bin_path)

    server = KinesisServer(port=port, bin_path=kinesis_mock_bin_path)
    #TODO: mk data dir and set class properties here
    return server
