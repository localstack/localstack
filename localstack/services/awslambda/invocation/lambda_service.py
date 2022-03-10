import logging
from concurrent.futures import Future
from dataclasses import replace
from threading import RLock

from localstack.services.awslambda.invocation.executor_endpoint import InvocationResult
from localstack.services.awslambda.invocation.version_manager import LambdaVersionManager
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.tagging import TaggingService
from .lambda_models import *

LOG = logging.getLogger(__name__)

LAMBDA_DEFAULT_TIMEOUT_SECONDS = 3
LAMBDA_DEFAULT_MEMORY_SIZE = 128


class LambdaServiceBackend(RegionBackend):
    # name => Function; Account/region are implicit through the Backend
    functions: Dict[str, Function] = {}
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

    # CRUD
    def _create_version(self, region_name: str, function_name: str, qualifier: str) -> Version:
        return

    def create_function(self, region_name: str, function_name: str, ) -> Version:
        state = LambdaServiceBackend.get(region_name)

        fn = Function(function_name=function_name)
        # TODO: create initial version
        version = self._create_version(region_name, function_name, '$LATEST')
        fn.versions['$LATEST'] = version
        state.functions[function_name] = fn

        return version

    def create_version(self, region_name: str, function_name: str, description: str) -> Version:
        state = LambdaServiceBackend.get(region_name)
        fn = state.functions[function_name]
        with fn.lock:
            latest = fn.versions['$LATEST']
            qualifier = str(fn.next_version)
            new_version = replace(latest, qualifier=qualifier, description=description)
            fn.versions[qualifier] = new_version
            fn.next_version += 1
            return new_version

    # TODO: is this sync?
    def delete_function(self, region_name: str, function_name: str):
        state = LambdaServiceBackend.get(region_name)
        del state.functions[function_name] # TODO: downstream effects (graceful shutdown)

    def delete_version(self, region_name: str, function_name: str, version_qualifier: str):
        ...

    # def update_function(self, region_name: str, function_args):
    #     ...

    def get_function_version(self, region_name: str,  function_name, version) -> Version:
        ...

    def list_function_versions(self):
        ...

    def create_alias(self):
        ...

    def get_alias(self, region_name: str, function_name: str, alias_name: str):
        state = LambdaServiceBackend.get(region_name)
        return state.functions[function_name].aliases[alias_name]

    def update_alias(self, region_name: str, function_name: str, alias_name: str, version: int, description):
        state = LambdaServiceBackend.get(region_name)
        fn = state.functions[function_name]
        del fn.aliases[alias_name]

    def delete_alias(self, region_name: str, function_name: str, alias_name: str):
        state = LambdaServiceBackend.get(region_name)
        fn = state.functions[function_name]
        del fn.aliases[alias_name]

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

    # Commands

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
