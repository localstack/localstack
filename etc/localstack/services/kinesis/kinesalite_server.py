import logging
from typing import Optional

from localstack import config
from localstack.services import install
from localstack.utils.common import TMP_THREADS, ShellCommandThread, get_free_tcp_port, mkdir
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)


class KinesaliteServer(Server):
    """
    Server abstraction for controlling Kinesalite on a separate thread
    """

    def __init__(
        self, port: int, latency: str, host: str = "localhost", data_dir: Optional[str] = None
    ):
        self._latency = latency
        self._data_dir = data_dir
        super().__init__(port, host)

    def do_start_thread(self) -> FuncThread:
        """
        Start Kinesalite in a new thread
        :returns: The running thread
        """
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
            config.dirs.static_libs,
            config.KINESIS_SHARD_LIMIT,
            self.port,
            self._latency,
            self._latency,
            self._latency,
            "--path %s" % self._data_dir if self._data_dir else "",
        )

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())


def create_kinesalite_server(port=None, persist_path: Optional[str] = None) -> KinesaliteServer:
    """
    Creates a new Kinesalite server instance. Installs Kinesalite on the host first if necessary.
    Introspects on the host config to determine server configuration:
    config.dirs.data -> if set, the server runs with persistence using the path to store data
    config.KINESIS_LATENCY -> configure stream latency (in milliseconds)
    """
    port = port or get_free_tcp_port()

    install.install_kinesalite()
    persist_path = (
        f"{config.dirs.data}/dynamodb" if not persist_path and config.dirs.data else persist_path
    )
    if persist_path:
        mkdir(persist_path)

    return KinesaliteServer(port=port, latency=config.KINESIS_LATENCY, data_dir=persist_path)
