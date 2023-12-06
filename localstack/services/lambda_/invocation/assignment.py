import contextlib
import logging
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor
from typing import ContextManager

from localstack.services.lambda_.invocation.execution_environment import (
    EnvironmentStartupTimeoutException,
    ExecutionEnvironment,
    InvalidStatusException,
)
from localstack.services.lambda_.invocation.executor_endpoint import StatusErrorException
from localstack.services.lambda_.invocation.lambda_models import (
    FunctionVersion,
    InitializationType,
    OtherServiceEndpoint,
)

LOG = logging.getLogger(__name__)


class AssignmentException(Exception):
    pass


class AssignmentService(OtherServiceEndpoint):
    """
    scope: LocalStack global
    """

    # function_version (fully qualified function ARN) => runtime_environment_id => runtime_environment
    environments: dict[str, dict[str, ExecutionEnvironment]]

    # Global pool for spawning and killing provisioned Lambda runtime environments
    provisioning_pool: ThreadPoolExecutor

    def __init__(self):
        self.environments = defaultdict(dict)
        self.provisioning_pool = ThreadPoolExecutor(thread_name_prefix="lambda-provisioning-pool")

    @contextlib.contextmanager
    def get_environment(
        self, function_version: FunctionVersion, provisioning_type: InitializationType
    ) -> ContextManager[ExecutionEnvironment]:
        version_arn = function_version.qualified_arn
        applicable_envs = (
            env
            for env in self.environments[version_arn].values()
            if env.initialization_type == provisioning_type
        )
        execution_environment = None
        for environment in applicable_envs:
            try:
                environment.reserve()
                execution_environment = environment
                break
            except InvalidStatusException:
                pass

        if execution_environment is None:
            if provisioning_type == "provisioned-concurrency":
                raise AssignmentException(
                    "No provisioned concurrency environment available despite lease."
                )
            elif provisioning_type == "on-demand":
                execution_environment = self.start_environment(function_version)
                self.environments[version_arn][execution_environment.id] = execution_environment
                execution_environment.reserve()
            else:
                raise ValueError(f"Invalid provisioning type {provisioning_type}")

        try:
            yield execution_environment
            execution_environment.release()
        except InvalidStatusException as invalid_e:
            LOG.error("InvalidStatusException: %s", invalid_e)
        except Exception as e:
            LOG.error("Failed invocation %s", e)
            self.stop_environment(execution_environment)
            raise e

    def start_environment(self, function_version: FunctionVersion) -> ExecutionEnvironment:
        LOG.debug("Starting new environment")
        execution_environment = ExecutionEnvironment(
            function_version=function_version,
            initialization_type="on-demand",
            on_timeout=self.on_timeout,
        )
        try:
            execution_environment.start()
        except StatusErrorException:
            raise
        except EnvironmentStartupTimeoutException:
            raise
        except Exception as e:
            message = f"Could not start new environment: {e}"
            raise AssignmentException(message) from e
        return execution_environment

    def on_timeout(self, version_arn: str, environment_id: str) -> None:
        """Callback for deleting environment after function times out"""
        del self.environments[version_arn][environment_id]

    def stop_environment(self, environment: ExecutionEnvironment) -> None:
        version_arn = environment.function_version.qualified_arn
        try:
            environment.stop()
            self.environments.get(version_arn).pop(environment.id)
        except Exception as e:
            LOG.debug(
                "Error while stopping environment for lambda %s, environment: %s, error: %s",
                version_arn,
                environment.id,
                e,
            )

    def stop_environments_for_version(self, function_version: FunctionVersion):
        # We have to materialize the list before iterating due to concurrency
        environments_to_stop = list(
            self.environments.get(function_version.qualified_arn, {}).values()
        )
        for env in environments_to_stop:
            self.stop_environment(env)

    def scale_provisioned_concurrency(
        self, function_version: FunctionVersion, target_provisioned_environments: int
    ) -> list[Future[None]]:
        version_arn = function_version.qualified_arn
        current_provisioned_environments = [
            e
            for e in self.environments[version_arn].values()
            if e.initialization_type == "provisioned-concurrency"
        ]
        # TODO: refine scaling loop to re-use existing environments instead of re-creating all
        # current_provisioned_environments_count = len(current_provisioned_environments)
        # diff = target_provisioned_environments - current_provisioned_environments_count

        # TODO: handle case where no provisioned environment is available during scaling
        # Most simple scaling implementation for now:
        futures = []
        # 1) Re-create new target
        for _ in range(target_provisioned_environments):
            execution_environment = ExecutionEnvironment(
                function_version=function_version,
                initialization_type="provisioned-concurrency",
                on_timeout=self.on_timeout,
            )
            self.environments[version_arn][execution_environment.id] = execution_environment
            futures.append(self.provisioning_pool.submit(execution_environment.start))
        # 2) Kill all existing
        for env in current_provisioned_environments:
            # TODO: think about concurrent updates while deleting a function
            futures.append(self.provisioning_pool.submit(self.stop_environment, env))

        return futures

    def stop(self):
        self.provisioning_pool.shutdown(cancel_futures=True)
