import logging
import os
from typing import List, Optional

from localstack import config
from localstack.config import dirs, is_env_true
from localstack.services import install
from localstack.utils.common import TMP_THREADS, ShellCommandThread, get_free_tcp_port, mkdir
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)


class DynamodbServer(Server):
    db_path: Optional[str]
    heap_size: str

    delay_transient_statuses: bool
    optimize_db_before_startup: bool
    share_db: bool
    cors: Optional[str]

    def __init__(self, port: int, host: str = "localhost") -> None:
        super().__init__(port, host)

        # set defaults
        self.heap_size = config.DYNAMODB_HEAP_SIZE
        self.delay_transient_statuses = False
        self.optimize_db_before_startup = False
        self.share_db = False
        self.cors = None
        self.db_path = None

    @property
    def in_memory(self):
        return self.db_path is None

    @property
    def jar_path(self) -> str:
        return f"{dirs.static_libs}/dynamodb/DynamoDBLocal.jar"

    @property
    def library_path(self) -> str:
        return f"{dirs.static_libs}/dynamodb/DynamoDBLocal_lib"

    def _create_shell_command(self) -> List[str]:
        cmd = [
            "java",
            "-Xmx%s" % self.heap_size,
            "-Djava.library.path=%s" % self.library_path,
            "-jar",
            self.jar_path,
        ]
        parameters = []

        parameters.extend(["-port", str(self.port)])
        if self.in_memory:
            parameters.append("-inMemory")
        if self.db_path:
            parameters.extend(["-dbPath", self.db_path])
        if self.delay_transient_statuses:
            parameters.extend(["-delayTransientStatuses"])
        if self.optimize_db_before_startup:
            parameters.extend(["-optimizeDbBeforeStartup"])
        if self.share_db:
            parameters.extend(["-sharedDb"])

        return cmd + parameters

    def do_start_thread(self) -> FuncThread:
        install.install_dynamodb_local()

        cmd = self._create_shell_command()
        LOG.debug("starting dynamodb process %s", cmd)
        t = ShellCommandThread(
            cmd,
            strip_color=True,
            log_listener=self._log_listener,
            auto_restart=True,
        )
        TMP_THREADS.append(t)
        t.start()
        return t

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())


def create_dynamodb_server(port=None) -> DynamodbServer:
    """
    Creates a dynamodb server from the LocalStack configuration.
    """
    port = port or get_free_tcp_port()

    server = DynamodbServer(port)

    if config.dirs.data:
        ddb_data_dir = "%s/dynamodb" % config.dirs.data
        mkdir(ddb_data_dir)
        absolute_path = os.path.abspath(ddb_data_dir)
        server.db_path = absolute_path

    server.heap_size = config.DYNAMODB_HEAP_SIZE
    server.share_db = is_env_true("DYNAMODB_SHARE_DB")
    server.optimize_db_before_startup = is_env_true("DYNAMODB_OPTIMIZE_DB_BEFORE_STARTUP")
    server.delay_transient_statuses = is_env_true("DYNAMODB_DELAY_TRANSIENT_STATUSES")
    server.cors = os.getenv("DYNAMODB_CORS", None)

    return server
