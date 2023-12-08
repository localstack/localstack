import logging
import os
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from localstack import config
from localstack.services.kinesis.packages import kinesismock_package
from localstack.utils.common import TMP_THREADS, ShellCommandThread, get_free_tcp_port, mkdir
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
        js_path: Path,
        latency: str,
        account_id: str,
        host: str = "localhost",
        log_level: str = "INFO",
        data_dir: Optional[str] = None,
    ) -> None:
        self._account_id = account_id
        self._latency = latency
        self._data_dir = data_dir
        self._data_filename = f"{self._account_id}.json"
        self._js_path = js_path
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
            # Use the `server.json` packaged next to the main.js
            "KINESIS_MOCK_CERT_PATH": str((self._js_path.parent / "server.json").absolute()),
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
            # FIXME use relative path to current working directory until
            #  https://github.com/etspaceman/kinesis-mock/issues/554 is resolved
            env_vars["PERSIST_PATH"] = os.path.relpath(self._data_dir)
            env_vars["PERSIST_FILE_NAME"] = self._data_filename
            env_vars["PERSIST_INTERVAL"] = config.KINESIS_MOCK_PERSIST_INTERVAL

        env_vars["LOG_LEVEL"] = self._log_level
        cmd = ["node", self._js_path]
        return cmd, env_vars

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())


class KinesisServerManager:
    default_startup_timeout = 60

    def __init__(self):
        self._lock = threading.RLock()
        self._servers: dict[str, KinesisMockServer] = {}

    def get_server_for_account(self, account_id: str) -> KinesisMockServer:
        if account_id in self._servers:
            return self._servers[account_id]

        with self._lock:
            if account_id in self._servers:
                return self._servers[account_id]

            LOG.info("Creating kinesis backend for account %s", account_id)
            self._servers[account_id] = self._create_kinesis_mock_server(account_id)
            self._servers[account_id].start()
            if not self._servers[account_id].wait_is_up(timeout=self.default_startup_timeout):
                raise TimeoutError("gave up waiting for kinesis backend to start up")
            return self._servers[account_id]

    def shutdown_all(self):
        with self._lock:
            while self._servers:
                account_id, server = self._servers.popitem()
                LOG.info("Shutting down kinesis backend for account %s", account_id)
                server.shutdown()

    def _create_kinesis_mock_server(self, account_id: str) -> KinesisMockServer:
        """
        Creates a new Kinesis Mock server instance. Installs Kinesis Mock on the host first if necessary.
        Introspects on the host config to determine server configuration:
        config.dirs.data -> if set, the server runs with persistence using the path to store data
        config.LS_LOG -> configure kinesis mock log level (defaults to INFO)
        config.KINESIS_LATENCY -> configure stream latency (in milliseconds)
        """
        port = get_free_tcp_port()
        kinesismock_package.install()
        kinesis_mock_js_path = Path(kinesismock_package.get_installer().get_executable_path())

        # kinesis-mock stores state in json files <account_id>.json, so we can dump everything into `kinesis/`
        persist_path = os.path.join(config.dirs.data, "kinesis")
        mkdir(persist_path)
        if config.KINESIS_MOCK_LOG_LEVEL:
            log_level = config.KINESIS_MOCK_LOG_LEVEL.upper()
        elif config.LS_LOG:
            if config.LS_LOG == "warning":
                log_level = "WARN"
            else:
                log_level = config.LS_LOG.upper()
        else:
            log_level = "INFO"
        latency = config.KINESIS_LATENCY + "ms"

        server = KinesisMockServer(
            port=port,
            js_path=kinesis_mock_js_path,
            log_level=log_level,
            latency=latency,
            data_dir=persist_path,
            account_id=account_id,
        )
        return server
