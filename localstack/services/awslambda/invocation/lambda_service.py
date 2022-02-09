import dataclasses
from concurrent.futures import Future
from threading import RLock
from typing import Dict, Optional

from localstack.services.awslambda.invocation.runtime_api import LambdaRuntimeAPI
from localstack.services.awslambda.invocation.version_manager import LambdaVersionManager
from localstack.utils.common import get_free_tcp_port


@dataclasses.dataclass
class FunctionVersion:
    qualified_arn: str  # qualified arn for the version
    code: bytes  # zip file
    runtime: str  # runtime
    architecture: str  # architecture
    role: str  # lambda role


class LambdaService:
    # mapping from qualified ARN to version manager
    lambda_version_managers: Dict[str, LambdaVersionManager]
    lambda_version_manager_lock: RLock
    lambda_runtime_api: LambdaRuntimeAPI

    def __init__(self) -> None:
        self.lambda_version_managers = {}
        self.lambda_runtime_api = self._build_runtime_api()
        self.lambda_version_manager_lock = RLock()

    # TODO do not start in the constructor? maybe a separate start method or handle the runtime api above
    def _build_runtime_api(self) -> LambdaRuntimeAPI:
        port = get_free_tcp_port()
        runtime_api = LambdaRuntimeAPI(port, lambda_service=self)
        runtime_api.start()
        return runtime_api

    def get_lambda_version_manager(self, function_arn: str) -> LambdaVersionManager:
        """
        Get the lambda version for the given arn
        :param function_arn: qualified arn for the lambda version
        :return: LambdaVersionManager for the arn
        """
        version_manager = self.lambda_version_managers.get(function_arn)
        if not version_manager:
            raise Exception("Version '%s' not created", function_arn)

        return version_manager

    def create_function(self, function_version_definition: FunctionVersion):
        with self.lambda_version_manager_lock:
            version_manager = self.lambda_version_managers.get(
                function_version_definition.qualified_arn
            )
            if version_manager:
                raise Exception(
                    "Version '%s' already created", function_version_definition.qualified_arn
                )
            version_manager = LambdaVersionManager(
                function_arn=function_version_definition.qualified_arn,
                function_configuration=function_version_definition,
            )
            self.lambda_version_managers[
                function_version_definition.qualified_arn
            ] = version_manager

    def invoke(
        self,
        function_arn_qualified: str,
        invocation_type: Optional[str],
        log_type: Optional[str],
        client_context: Optional[str],
        payload: Optional[bytes],
    ) -> Future:
        version_manager = self.get_lambda_version_manager(function_arn_qualified)
        return version_manager.invoke(
            payload=payload, client_context=client_context, invocation_type=invocation_type
        )
