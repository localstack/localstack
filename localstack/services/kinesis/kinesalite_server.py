from typing import Optional
import logging
from localstack import config
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server
from localstack.services import install
from localstack.utils.common import TMP_THREADS, ShellCommandThread
from localstack.utils.common import (
    get_free_tcp_port,
    mkdir,
)


LOG = logging.getLogger(__name__)


class KinesaliteServer(Server):
    def __init__(self, port: int, latency: str, host: str = "localhost", data_dir: Optional[str] = None):
        self._latency = latency
        self._data_dir = data_dir
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
        return (
                  "%s/node_modules/kinesalite/cli.js --shardLimit %s --port %s"
                  " --createStreamMs %s --deleteStreamMs %s --updateStreamMs %s %s"
              ) % (
                  install.MODULE_MAIN_PATH,
                  config.KINESIS_SHARD_LIMIT,
                  self.port,
                  self._latency,
                  self._latency,
                  self._latency,
                  "--path %s" % self._data_dir if self._data_dir else "",
              )

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())

def create_kinesalite_server(port=None):
    port = port or get_free_tcp_port()

    install.install_kinesalite()
    if config.dirs.data:
        kinesis_data_dir = "%s/kinesis" % config.dirs.data
        mkdir(kinesis_data_dir)
    else:
        kinesis_data_dir = None

    return KinesaliteServer(port=port, latency=config.KINESIS_LATENCY, data_dir=kinesis_data_dir)