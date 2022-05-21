import logging
import os
from typing import List, Optional

from localstack import config
from localstack.config import dirs, is_env_true
from localstack.services import install
from localstack.services.install import DDB_AGENT_JAR_PATH
from localstack.utils.aws import aws_stack
from localstack.utils.common import TMP_THREADS, ShellCommandThread, get_free_tcp_port, mkdir
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

# server singleton
# TODO: consider removing this module-level singleton, and instead making the DynamodDB server part of the provider
_server: Optional["DynamodbServer"] = None


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
            f"-javaagent:{DDB_AGENT_JAR_PATH}",
            f"-Djava.library.path={self.library_path}",
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
    ddb_data_dir = f"{config.dirs.data}/dynamodb" if config.dirs.data else None
    return do_create_dynamodb_server(port, ddb_data_dir)


def do_create_dynamodb_server(port: int, ddb_data_dir: Optional[str]) -> DynamodbServer:
    server = DynamodbServer(port)
    if ddb_data_dir:
        mkdir(ddb_data_dir)
        absolute_path = os.path.abspath(ddb_data_dir)
        server.db_path = absolute_path

    server.heap_size = config.DYNAMODB_HEAP_SIZE
    server.share_db = is_env_true("DYNAMODB_SHARE_DB")
    server.optimize_db_before_startup = is_env_true("DYNAMODB_OPTIMIZE_DB_BEFORE_STARTUP")
    server.delay_transient_statuses = is_env_true("DYNAMODB_DELAY_TRANSIENT_STATUSES")
    server.cors = os.getenv("DYNAMODB_CORS", None)

    return server


def wait_for_dynamodb():
    retry(check_dynamodb, sleep=0.4, retries=10)


def check_dynamodb(expect_shutdown=False, print_error=False):
    out = None

    if not expect_shutdown:
        assert _server

    try:
        _server.wait_is_up()
        out = aws_stack.connect_to_service("dynamodb", endpoint_url=_server.url).list_tables()
    except Exception:
        if print_error:
            LOG.exception("DynamoDB health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out["TableNames"], list)


def start_dynamodb(port=None, asynchronous=True, update_listener=None):
    global _server
    if not _server:
        _server = create_dynamodb_server()

    _server.start()

    return _server


def get_server():
    return _server


def restart_dynamodb():
    global _server
    if _server:
        _server.shutdown()
        _server.join(timeout=10)
        _server = None

    LOG.debug("Restarting DynamoDB process ...")
    start_dynamodb()
    wait_for_dynamodb()
