from typing import Dict

from localstack.services.awslambda.invocation.runtime_api import LambdaRuntimeAPI
from localstack.services.awslambda.invocation.version_manager import LambdaVersionManager


class LambdaService:
    # mapping from qualified ARN to version manager
    lambda_version_managers: Dict[str, LambdaVersionManager]
    lambda_runtime_api: LambdaRuntimeAPI

    def __init__(self, lambda_runtime_api: LambdaRuntimeAPI):
        self.lambda_version_managers = {}
        self.lambda_runtime_api = lambda_runtime_api
