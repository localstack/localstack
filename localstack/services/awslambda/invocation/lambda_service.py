from concurrent.futures import Future
from threading import RLock
from typing import Dict, Optional

from localstack.services.awslambda.invocation.runtime_api import LambdaRuntimeAPI
from localstack.services.awslambda.invocation.version_manager import LambdaVersionManager
from localstack.utils.aws import aws_stack
from localstack.utils.common import get_free_tcp_port


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
        if version_manager:
            return version_manager
        with self.lambda_version_manager_lock:
            version_manager = self.lambda_version_managers.get(function_arn)
            if version_manager:
                return version_manager
            # TODO function configuration source depends on storage location
            version_manager = LambdaVersionManager(
                function_arn=function_arn, function_configuration={}
            )
            self.lambda_version_managers[function_arn] = version_manager
            return version_manager

    def invoke(
        self,
        function_name: str,
        account: str,
        region: str,
        invocation_type: Optional[str],
        log_type: Optional[str],
        client_context: Optional[str],
        payload: Optional[bytes],
        qualifier: Optional[str],
    ) -> Future:
        qualified_arn = qualified_lambda_arn(function_name, qualifier, account, region)
        version_manager = self.get_lambda_version_manager(qualified_arn)
        version_manager.invoke(
            payload=payload, client_context=client_context, invocation_type=invocation_type
        )
        return Future()


def qualified_lambda_arn(
    function_name: str, qualifier: Optional[str], account: str, region: str
) -> str:
    partition = aws_stack.get_partition(region)
    qualifier = qualifier or "$LATEST"
    return f"arn:{partition}:lambda:{region}:{account}:function:{function_name}:{qualifier}"
