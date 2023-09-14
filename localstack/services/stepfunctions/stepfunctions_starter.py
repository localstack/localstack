import logging
import threading
from typing import Any, Dict

from localstack import config
from localstack.services.stepfunctions.packages import stepfunctions_local_package
from localstack.utils.aws import aws_stack
from localstack.utils.net import get_free_tcp_port, port_can_be_bound
from localstack.utils.run import ShellCommandThread
from localstack.utils.serving import Server
from localstack.utils.threads import TMP_THREADS, FuncThread

LOG = logging.getLogger(__name__)

# max heap size allocated for the Java process
MAX_HEAP_SIZE = "256m"


class StepFunctionsServer(Server):
    def __init__(
        self, port: int, account_id: str, region_name: str, host: str = "localhost"
    ) -> None:
        self.account_id = account_id
        self.region_name = region_name
        super().__init__(port, host)

    def do_start_thread(self) -> FuncThread:
        cmd = self.generate_shell_command()
        env_vars = self.generate_env_vars()
        cwd = stepfunctions_local_package.get_installed_dir()
        LOG.debug("Starting StepFunctions process %s with env vars %s", cmd, env_vars)
        t = ShellCommandThread(
            cmd,
            strip_color=True,
            env_vars=env_vars,
            log_listener=self._log_listener,
            name="stepfunctions",
            cwd=cwd,
        )
        TMP_THREADS.append(t)
        t.start()
        return t

    def generate_env_vars(self) -> Dict[str, Any]:
        return {
            "EDGE_PORT": config.EDGE_PORT_HTTP or config.EDGE_PORT,
            "EDGE_PORT_HTTP": config.EDGE_PORT_HTTP or config.EDGE_PORT,
            "DATA_DIR": config.dirs.data,
            "PORT": self._port,
        }

    def generate_shell_command(self) -> str:
        cmd = (
            f"java "
            f"-javaagent:aspectjweaver-1.9.7.jar "
            f"-Dorg.aspectj.weaver.loadtime.configuration=META-INF/aop.xml "
            f"-Dcom.amazonaws.sdk.disableCertChecking "
            f"-Xmx{MAX_HEAP_SIZE} "
            f"-jar StepFunctionsLocal.jar "
            f"--aws-account {self.account_id} "
            f"--aws-region {self.region_name} "
        )

        if config.STEPFUNCTIONS_LAMBDA_ENDPOINT.lower() != "default":
            lambda_endpoint = (
                config.STEPFUNCTIONS_LAMBDA_ENDPOINT or aws_stack.get_local_service_url("lambda")
            )
            cmd += f" --lambda-endpoint {lambda_endpoint}"

        # add service endpoint flags
        services = [
            "athena",
            "batch",
            "dynamodb",
            "ecs",
            "eks",
            "events",
            "glue",
            "sagemaker",
            "sns",
            "sqs",
            "stepfunctions",
        ]

        for service in services:
            flag = f"--{service}-endpoint"
            if service == "stepfunctions":
                flag = "--step-functions-endpoint"
            elif service == "events":
                flag = "--eventbridge-endpoint"
            elif service in ["athena", "eks"]:
                flag = f"--step-functions-{service}"
            endpoint = aws_stack.get_local_service_url(service)
            cmd += f" {flag} {endpoint}"

        return cmd

    def _log_listener(self, line, **kwargs):
        LOG.debug(line.rstrip())


class StepFunctionsServerManager:
    default_startup_timeout = 20

    def __init__(self):
        self._lock = threading.RLock()
        self._servers: dict[tuple[str, str], StepFunctionsServer] = {}

    def get_server_for_account_region(
        self, account_id: str, region_name: str
    ) -> StepFunctionsServer:
        locator = (account_id, region_name)

        if locator in self._servers:
            return self._servers[locator]

        with self._lock:
            if locator in self._servers:
                return self._servers[locator]

            LOG.info("Creating StepFunctions server for %s", locator)
            self._servers[locator] = self._create_stepfunctions_server(account_id, region_name)

            self._servers[locator].start()

            if not self._servers[locator].wait_is_up(timeout=self.default_startup_timeout):
                raise TimeoutError("Gave up waiting for StepFunctions server to start up")

            return self._servers[locator]

    def shutdown_all(self):
        with self._lock:
            while self._servers:
                locator, server = self._servers.popitem()
                LOG.info("Shutting down StepFunctions for %s", locator)
                server.shutdown()

    def _create_stepfunctions_server(
        self, account_id: str, region_name: str
    ) -> StepFunctionsServer:
        port = config.LOCAL_PORT_STEPFUNCTIONS
        if not port_can_be_bound(port):
            port = get_free_tcp_port()
        stepfunctions_local_package.install()

        server = StepFunctionsServer(
            port=port,
            account_id=account_id,
            region_name=region_name,
        )
        return server
