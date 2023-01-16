import logging
from typing import Dict, List, Optional, Tuple

from localstack import config
from localstack.services.kms.packages import kms_local_package
from localstack.utils.net import get_free_tcp_port
from localstack.utils.run import ShellCommandThread
from localstack.utils.serving import Server
from localstack.utils.threads import TMP_THREADS, FuncThread

LOG = logging.getLogger(__name__)


class LocalKMSServer(Server):
    """
    Server abstraction for controlling KMS in a separate thread
    """

    def __init__(
        self,
        port: int,
        bin_path: str,
        account_id: str,
        host: str = "localhost",
        log_level: str = "INFO",
        kms_data_path: Optional[str] = None,
    ) -> None:
        self._account_id = account_id
        self._kms_data_path = kms_data_path
        self._bin_path = bin_path
        self._log_level = log_level
        super().__init__(port, host)

    def do_start_thread(self) -> FuncThread:
        cmd, env_vars = self._create_shell_command()
        LOG.debug("starting local-kms process %s with env vars %s", cmd, env_vars)
        t = ShellCommandThread(
            cmd,
            strip_color=True,
            env_vars=env_vars,
            log_listener=self._log_listener,
            auto_restart=True,
            name="local-kms",
        )
        TMP_THREADS.append(t)
        t.start()
        return t

    def _log_listener(self, line: str, **_kwargs) -> None:
        LOG.info(line.rstrip())

    def _create_shell_command(self) -> Tuple[List, Dict]:
        env_vars = {
            "PORT": str(self.port),
            "ACCOUNT_ID": self._account_id,
            "KMS_ACCOUNT_ID": self._account_id,
            "REGION": config.DEFAULT_REGION,
            "KMS_REGION": config.DEFAULT_REGION,
        }
        if self._kms_data_path and config.PERSISTENCE:
            env_vars["KMS_DATA_PATH"] = self._kms_data_path

        return [self._bin_path], env_vars


def create_local_kms_server(
    account_id: str, port=None, persist_path: Optional[str] = None
) -> LocalKMSServer:
    """
    Creates a new KMS server instance. Installs the local-kms binary if necessary.
    """
    port = port or get_free_tcp_port()
    kms_local_package.install()
    kms_binary = kms_local_package.get_installer().get_executable_path()
    persist_path = (
        f"{config.dirs.data}/local-kms" if not persist_path and config.dirs.data else persist_path
    )
    server = LocalKMSServer(
        port=port, bin_path=kms_binary, account_id=account_id, kms_data_path=persist_path
    )
    return server
