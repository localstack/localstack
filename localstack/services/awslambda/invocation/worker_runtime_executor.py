import json
import logging
from concurrent.futures import Future
from typing import Optional

from localstack import config
from localstack.services.awslambda.invocation.executor_endpoint import (
    ExecutorEndpoint,
    ServiceEndpoint,
)
from localstack.services.awslambda.invocation.lambda_models import FunctionVersion
from localstack.services.awslambda.invocation.runtime_executor import (
    RuntimeExecutor,
)
from localstack.services.edge import ROUTER
from localstack.http import route, Request
from localstack.utils.strings import long_uid
from localstack.utils.threads import start_thread

LOG = logging.getLogger(__name__)

MANAGER_THREAD = None

def start_manager():
    start_thread()



class WorkerInfo:
    worker_id: str
    status: WorkerStatus


class WorkerManager:

    workers: list[dict]

    # TODO: envs makes no sense here?
    envs: dict[str, str]

    def __init__(self):
        self.workers = list()
        self.envs = dict()

    def register(self, runtimes, archs):

        # generate new  worker id
        worker_id = long_uid()

        self.workers.append({
            "worker_id": worker_id,
            "runtimes": runtimes,
            "archs": archs
        })

        return worker_id

    def report_command_request(self, worker_id: str) -> Future[dict]:
        pass

        future = Future()


class WorkerRuntimeExecutor(RuntimeExecutor):

    ip: Optional[str]
    executor_endpoint: Optional[ExecutorEndpoint]
    container_name: str

    def __init__(
            self, id: str, function_version: FunctionVersion, service_endpoint: ServiceEndpoint
    ) -> None:
        super(WorkerRuntimeExecutor, self).__init__(
            id=id, function_version=function_version, service_endpoint=service_endpoint
        )
        self.executor_endpoint = ExecutorEndpoint(self.id, service_endpoint=service_endpoint, container_address="localhost")


    def start(self, env_vars: dict[str, str]) -> None:
        self.executor_endpoint.start()
        manager = WorkerManager()
        manager.envs = env_vars
        presigned_endpoint = (
            f"http://{self.get_endpoint_from_executor()}:{config.get_edge_port_http()}"
        )
        code_archives = [
            {
                "url": self.function_version.config.code.generate_presigned_url(
                    endpoint_url=presigned_endpoint
                ),
                "target_path": "/var/task",
            }
        ]

        manager.envs["LOCALSTACK_CODE_ARCHIVES"] = json.dumps(code_archives)
        ROUTER.add(WorkerApiEndpoint(manager))

        # TODO: this actually seems a bit synchronous? might this be the issue?


    def stop(self) -> None:
        pass

    def get_address(self) -> str:
        return "localhost"

    def get_endpoint_from_executor(self) -> str:
        return "localhost"

    def get_runtime_endpoint(self) -> str:
        return f"http://{self.get_endpoint_from_executor()}:{config.EDGE_PORT}{self.executor_endpoint.get_endpoint_prefix()}"

    def invoke(self, payload: dict[str, str]) -> None:
        self.executor_endpoint.invoke(payload)

    @classmethod
    def prepare_version(cls, function_version: FunctionVersion) -> None:
        pass

    @classmethod
    def cleanup_version(cls, function_version: FunctionVersion):
        pass

class InitCommand:
    ...


class WorkerApiEndpoint:

    def __init__(self, manager: WorkerManager):
        self.registered = False
        self.manager = manager

    @route("/_aws/lambda/worker/register", methods=["POST"])
    def handle_register(self, request: Request):
        """

        :param request:
        :return:
        """
        content = request.json
        runtimes = content.get("compatibleRuntimes")
        archs = content.get("compatibleArchitectures")
        worker_id = self.manager.register(runtimes, archs)
        return {"workerId": worker_id}



    @route("/_aws/lambda/worker/<worker_id>/command", methods=["GET"])
    def handle_command_request(self, request: Request, worker_id: str):
        """
        :param request:
        :param worker_id:
        :return:
        """
        # self.manager.block_for_worker(worker_id)

        future: Future[dict] = self.manager.report_command_request(worker_id)
        payload = future.result()

        # payload = json.dumps({
        #     "environment": self.manager.envs
        # })

        return {
            "commandType": "INIT_EXECUTION_ENVIRONMENT",
            "payload": json.dumps(payload)
        }
