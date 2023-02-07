import logging
import os
from typing import List, Optional

from localstack import config
from localstack.config import is_env_true, is_persistence_enabled
from localstack.services.dynamodb.packages import dynamodblocal_package
from localstack.utils.aws import aws_stack
from localstack.utils.bootstrap import is_api_key_configured
from localstack.utils.common import TMP_THREADS, ShellCommandThread, get_free_tcp_port, mkdir
from localstack.utils.files import rm_rf
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
        return f"{dynamodblocal_package.get_installed_dir()}/DynamoDBLocal.jar"

    @property
    def library_path(self) -> str:
        return f"{dynamodblocal_package.get_installed_dir()}/DynamoDBLocal_lib"

    def _create_shell_command(self) -> List[str]:
        cmd = [
            "java",
            "-Xmx%s" % self.heap_size,
            f"-javaagent:{dynamodblocal_package.get_installer().get_ddb_agent_jar_path()}",
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
        dynamodblocal_package.install()

        cmd = self._create_shell_command()
        LOG.debug("starting dynamodb process %s", cmd)
        t = ShellCommandThread(
            cmd,
            strip_color=True,
            log_listener=self._log_listener,
            auto_restart=True,
            name="dynamodb-server",
        )
        TMP_THREADS.append(t)
        t.start()
        return t

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())


def create_dynamodb_server(
    port: Optional[int] = None, db_path: Optional[str] = None, clean_db_path: Optional[bool] = None
) -> DynamodbServer:
    """
    Creates a DynamoDB server from the local configuration.
    :param port:          optional, the port to start the server on (defaults to a random port)
    :param db_path:       path to the persistent state files used by the DynamoDB Local process
    :param clean_db_path: optional, whether to clean the state files before starting the process; if None is passed,
                          the state files are cleaned by default, unless persistence is enabled with API key configured
    :return: the server instance
    """
    port = port or get_free_tcp_port()
    server = DynamodbServer(port)
    db_path = f"{config.dirs.data}/dynamodb" if not db_path and config.dirs.data else db_path

    if is_env_true("DYNAMODB_IN_MEMORY"):
        # the DYNAMODB_IN_MEMORY variable takes precedence and will set the DB path to None which forces inMemory=true
        db_path = None

    # In some cases (e.g., DDB starting not in memory and persistence not set), the DBLocal assets are persisted
    # but the Store data is not. This might lead to an inconsistent state (#7118). Therefore, we clean the db path
    # before starting the DynamoDB server. Note: only cleaning if clean_db_path is None (i.e., not specified)
    if clean_db_path is None:
        clean_db_path = not (is_persistence_enabled() and is_api_key_configured())

    if db_path:
        if clean_db_path:
            rm_rf(db_path)
        mkdir(db_path)
        absolute_path = os.path.abspath(db_path)
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


def start_dynamodb(port=None, db_path=None, clean_db_path=False):
    global _server
    if not _server:
        _server = create_dynamodb_server(port, db_path, clean_db_path)

    _server.start()

    return _server


def get_server():
    return _server
