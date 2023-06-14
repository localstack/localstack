# assignment + placement service
import contextlib
import logging
from collections import defaultdict
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


class AssignmentService(OtherServiceEndpoint):
    """
    scope: LocalStack global
    """

    # function_version (fully qualified function ARN) => runtime_environment
    environments: dict[str, list[ExecutionEnvironment]]

    def __init__(self):
        self.environments = defaultdict(list)

    @contextlib.contextmanager
    def get_environment(
        self, function_version: FunctionVersion, provisioning_type: InitializationType
    ) -> ContextManager[ExecutionEnvironment]:
        # TODO: re-use existing ones if available
        execution_environment = self.start_environment(function_version)
        version_arn = function_version.qualified_arn
        self.environments[version_arn].append(execution_environment)
        try:
            execution_environment.reserve()
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
            self.environments.get(version_arn).remove(environment)
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


# class PlacementService:
#
#     def prepare_host_for_execution_environment(self):
#
#     def stop(self):
#         ...
