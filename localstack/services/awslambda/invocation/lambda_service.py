import dataclasses
import logging
import threading
from concurrent.futures import Future
from threading import RLock
from typing import Dict, Optional

from localstack.aws.api.awslambda import AliasConfiguration, FunctionCode, FunctionConfiguration
from localstack.services.awslambda.invocation.executor_endpoint import InvocationResult
from localstack.services.awslambda.invocation.version_manager import LambdaVersionManager
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.tagging import TaggingService

LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class FunctionVersion:
    qualified_arn: str  # qualified arn for the version
    name: str
    version: str
    region: str
    architecture: str  # architecture
    role: str  # lambda role
    environment: Dict[str, str]  # Environment set when creating the function
    zip_file: Optional[bytes] = None
    runtime: Optional[str] = None
    handler: Optional[str] = None
    image_uri: Optional[str] = None
    image_config: Optional[Dict[str, str]] = None


@dataclasses.dataclass
class Invocation:
    payload: bytes
    client_context: Optional[str]
    invocation_type: str


@dataclasses.dataclass
class LambdaFunctionVersion:  # TODO: reconcile with FunctionVersion above
    config: FunctionConfiguration
    code: FunctionCode


@dataclasses.dataclass
class LambdaFunction:
    latest: LambdaFunctionVersion  # points to the '$LATEST' version
    versions: Dict[str, LambdaFunctionVersion] = dataclasses.field(default_factory=dict)
    aliases: Dict[str, AliasConfiguration] = dataclasses.field(default_factory=dict)
    next_version: int = 1
    lock: threading.RLock = dataclasses.field(default_factory=threading.RLock)

    # TODO: implement later
    # provisioned_concurrency_configs: Dict[str, ProvisionedConcurrencyConfig]
    # code_signing_config: Dict[str, CodeSigningConfig]
    # function_event_invoke_config: Dict[str, EventInvokeConfig]
    # function_concurrency: Dict[str, FunctionConcurrency]


class LambdaServiceBackend(RegionBackend):
    # name => Function; Account/region are implicit through the Backend
    functions: Dict[str, LambdaFunction] = {}
    # static tagging service instance
    TAGS = TaggingService()


class LambdaService:
    # mapping from qualified ARN to version manager
    lambda_version_managers: Dict[str, LambdaVersionManager]
    lambda_version_manager_lock: RLock

    def __init__(self) -> None:
        self.lambda_version_managers = {}
        self.lambda_version_manager_lock = RLock()

    def stop(self) -> None:
        for version_manager in self.lambda_version_managers.values():
            version_manager.stop()

    def stop_version(self, qualified_arn: str) -> None:
        """
        Stops a specific lambda service version
        :param qualified_arn: Qualified arn for the version to stop
        """
        LOG.debug("Stopping version %s", qualified_arn)
        version_manager = self.lambda_version_managers.get(qualified_arn)
        if not version_manager:
            LOG.error("Could not find version manager for %s", qualified_arn)
        version_manager.stop()

    def get_lambda_version_manager(self, function_arn: str) -> LambdaVersionManager:
        """
        Get the lambda version for the given arn
        :param function_arn: qualified arn for the lambda version
        :return: LambdaVersionManager for the arn
        """
        version_manager = self.lambda_version_managers.get(function_arn)
        if not version_manager:
            raise Exception(f"Version '{function_arn}' not created")

        return version_manager

    def create_function_version(self, function_version_definition: FunctionVersion) -> None:
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
                function_version=function_version_definition,
            )
            self.lambda_version_managers[
                function_version_definition.qualified_arn
            ] = version_manager
            version_manager.start()

    def invoke(
        self,
        function_arn_qualified: str,
        invocation_type: str,
        client_context: Optional[str],
        payload: bytes,
    ) -> Future[InvocationResult]:
        version_manager = self.get_lambda_version_manager(function_arn_qualified)
        return version_manager.invoke(
            invocation=Invocation(
                payload=payload, client_context=client_context, invocation_type=invocation_type
            )
        )
