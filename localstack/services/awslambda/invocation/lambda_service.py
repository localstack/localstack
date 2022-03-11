import concurrent.futures
import logging
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from dataclasses import replace
from threading import RLock
from typing import Dict, Optional

from localstack.services.awslambda.invocation.lambda_models import (
    Code,
    Function,
    FunctionConfigurationMeta,
    FunctionVersion,
    Invocation,
    InvocationResult,
    UpdateStatus,
    VersionFunctionConfiguration,
    VersionIdentifier,
)
from localstack.services.awslambda.invocation.version_manager import LambdaVersionManager
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.tagging import TaggingService

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
    create_fn_lock: RLock
    task_executor: Executor

    def __init__(self) -> None:
        self.lambda_version_managers = {}
        self.lambda_version_manager_lock = RLock()
        self.create_fn_lock = RLock()
        self.task_executor = ThreadPoolExecutor()

    def stop(self) -> None:
        shutdown_futures = []
        for version_manager in self.lambda_version_managers.values():
            shutdown_futures.append(self.task_executor.submit(version_manager.stop))
        concurrent.futures.wait(shutdown_futures, timeout=5)
        self.task_executor.shutdown(cancel_futures=True)

    def stop_version(self, qualified_arn: str) -> None:
        """
        Stops a specific lambda service version
        :param qualified_arn: Qualified arn for the version to stop
        """
        LOG.debug("Stopping version %s", qualified_arn)
        version_manager = self.lambda_version_managers.pop(qualified_arn)
        if not version_manager:
            LOG.error("Could not find version manager for %s", qualified_arn)
        self.task_executor.submit(version_manager.stop)

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
    def _create_version(
        self, region_name: str, function_name: str, qualifier: str
    ) -> FunctionVersion:
        return

    def create_function(
        self,
        region_name: str,
        function_name: str,
        function_config: VersionFunctionConfiguration,
        code: Code,
    ) -> FunctionVersion:
        state = LambdaServiceBackend.get(region_name)
        fn = Function(function_name=function_name)

        with self.create_fn_lock:
            # TODO: create initial version
            arn = VersionIdentifier(function_name, "$LATEST", region_name, "?")
            version = FunctionVersion(
                id=arn,
                qualified_arn=arn.qualified_arn(),
                qualifier="$LATEST",
                code=code,
                config_meta=FunctionConfigurationMeta(
                    function_arn=arn.qualified_arn(),
                    revision_id="?",
                    code_size=0,
                    coda_sha256="bla",
                    last_modified="asdf",
                    last_update=UpdateStatus(status="?"),
                ),
                config=function_config,
            )
            fn.versions["$LATEST"] = version
            state.functions[function_name] = fn

        return version

    def create_version(
        self, region_name: str, function_name: str, description: str
    ) -> FunctionVersion:
        state = LambdaServiceBackend.get(region_name)
        fn = state.functions[function_name]
        with fn.lock:
            latest = fn.versions["$LATEST"]
            qualifier = str(fn.next_version)
            new_version = replace(latest, qualifier=qualifier)
            fn.versions[qualifier] = new_version
            fn.next_version += 1
            return new_version

    # TODO: is this sync?
    def delete_function(self, region_name: str, function_name: str):
        state = LambdaServiceBackend.get(region_name)

        function = state.functions.pop(function_name)
        for version in function.versions.values():
            self.stop_version(qualified_arn=version.qualified_arn)

    def delete_version(self, region_name: str, function_name: str, version_qualifier: str):
        ...

    # def update_function(self, region_name: str, function_args):
    #     ...

    def get_function_version(self, region_name: str, function_name, version) -> FunctionVersion:
        ...

    def list_function_versions(self):
        ...

    def create_alias(self):
        ...

    def get_alias(self, region_name: str, function_name: str, alias_name: str):
        state = LambdaServiceBackend.get(region_name)
        return state.functions[function_name].aliases[alias_name]

    def update_alias(
        self, region_name: str, function_name: str, alias_name: str, version: int, description
    ):
        state = LambdaServiceBackend.get(region_name)
        fn = state.functions[function_name]
        del fn.aliases[alias_name]

    def delete_alias(self, region_name: str, function_name: str, alias_name: str):
        state = LambdaServiceBackend.get(region_name)
        fn = state.functions[function_name]
        del fn.aliases[alias_name]

    def create_function_version(self, function_version: FunctionVersion) -> None:
        with self.lambda_version_manager_lock:
            version_manager = self.lambda_version_managers.get(function_version.qualified_arn)
            if version_manager:
                raise Exception("Version '%s' already created", function_version.qualified_arn)
            version_manager = LambdaVersionManager(
                function_arn=function_version.qualified_arn,
                function_version=function_version,
            )
            self.lambda_version_managers[function_version.qualified_arn] = version_manager
            self.task_executor.submit(version_manager.start)

    # Commands

    def invoke(
        self,
        function_arn_qualified: str,
        invocation_type: str,
        client_context: Optional[str],
        payload: bytes,
    ) -> "Future[InvocationResult]":
        version_manager = self.get_lambda_version_manager(function_arn_qualified)
        return version_manager.invoke(
            invocation=Invocation(
                payload=payload, client_context=client_context, invocation_type=invocation_type
            )
        )
