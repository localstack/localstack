# assignment + placement service
import contextlib
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures._base import Future
from typing import ContextManager

from localstack.services.lambda_.invocation.execution_environment import (
    ExecutionEnvironment,
    InvalidStatusException,
)
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
        for environment in applicable_envs:
            try:
                environment.reserve()
                execution_environment = environment
                break
            except InvalidStatusException:
                pass
        else:
            # TODO: use constant for provisioning type
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
            LOG.error("Should not happen: %s", invalid_e)
        except Exception as e:
            # TODO: add logging, stop environment
            LOG.error("Failed invocation %s", e)
            execution_environment.errored()

    def start_environment(self, function_version: FunctionVersion):
        LOG.debug("Starting new environment")
        runtime_environment = ExecutionEnvironment(
            function_version=function_version,
            initialization_type="on-demand",
        )
        try:
            runtime_environment.start()
        except Exception as e:
            LOG.error(f"Could not start new environment: {e}")
        return runtime_environment

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

    # def get_most_recently_used_active_environment(self):
    #     ...

    # def count_environment_by_status(self, status: List[RuntimeStatus]) -> int:
    #     return len(
    #         [runtime for runtime in self.all_environments.values() if runtime.status in status]
    #     )
    #
    # def ready_environment_count(self) -> int:
    #     return self.count_environment_by_status([RuntimeStatus.READY])
    #
    # def active_environment_count(self) -> int:
    #     return self.count_environment_by_status(
    #         [RuntimeStatus.READY, RuntimeStatus.STARTING, RuntimeStatus.RUNNING]
    #     )
    def stop_environments_for_version(self, function_version: FunctionVersion):
        for env in self.environments.get(function_version.qualified_arn, []):
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
        current_provisioned_environments_count = len(current_provisioned_environments)
        diff = target_provisioned_environments - current_provisioned_environments_count

        futures = []
        if diff > 0:
            for _ in range(diff):
                runtime_environment = ExecutionEnvironment(
                    function_version=function_version,
                    initialization_type="provisioned-concurrency",
                )
                self.environments[version_arn][runtime_environment.id] = runtime_environment
                futures.append(self.provisioning_pool.submit(runtime_environment.start))
        elif diff < 0:
            # Most simple: killall and restart the target

            # 1) kill non-executing
            # 2) give a shutdown pill for running invocation (or kill immediately for now)
            pass
            # current_provisioned_environments
            # TODO: kill non-running first, give running ones a shutdown pill (or alike)
            #  e.status != RuntimeStatus.RUNNING
            # TODO: implement killing envs
            # for e in provisioned_envs[: (diff * -1)]:
            #     futures.append(self.provisioning_pool.submit(self.stop_environment, e))
        else:
            # NOOP
            pass

        return futures


# class PlacementService:
#
#     def prepare_host_for_execution_environment(self):
#
#     def stop(self):
#         ...
