# assignment + placement service
from localstack.services.awslambda.invocation.lambda_models import OtherServiceEndpoint


class AssignmentService(OtherServiceEndpoint):
    def start_environment(self):
        # we should never spawn more execution environments than we can have concurrent invocations
        # so only start an environment when we have at least one available concurrency left
        if (
                self.lambda_service.get_available_fn_concurrency(
                    self.function.latest().id.unqualified_arn()
                )
                > 0
        ):
            LOG.debug("Starting new environment")
            runtime_environment = RuntimeEnvironment(
                function_version=self.function_version,
                initialization_type="on-demand",
                service_endpoint=self,
            )
            self.all_environments[runtime_environment.id] = runtime_environment
            self.execution_env_pool.submit(runtime_environment.start)

    def stop_environment(self, environment: RuntimeEnvironment) -> None:
        try:
            environment.stop()
            self.all_environments.pop(environment.id)
        except Exception as e:
            LOG.debug(
                "Error while stopping environment for lambda %s, environment: %s, error: %s",
                self.function_arn,
                environment.id,
                e,
            )

    def count_environment_by_status(self, status: List[RuntimeStatus]) -> int:
        return len(
            [runtime for runtime in self.all_environments.values() if runtime.status in status]
        )

    def ready_environment_count(self) -> int:
        return self.count_environment_by_status([RuntimeStatus.READY])

    def active_environment_count(self) -> int:
        return self.count_environment_by_status(
            [RuntimeStatus.READY, RuntimeStatus.STARTING, RuntimeStatus.RUNNING]
        )

    def set_environment_ready(self, executor_id: str) -> None:
        environment = self.all_environments.get(executor_id)
        if not environment:
            raise Exception(
                "Inconsistent state detected: Non existing environment '%s' reported error.",
                executor_id,
            )
        environment.set_ready()
        self.available_environments.put(environment)

    def set_environment_failed(self, executor_id: str) -> None:
        environment = self.all_environments.get(executor_id)
        if not environment:
            raise Exception(
                "Inconsistent state detected: Non existing environment '%s' reported error.",
                executor_id,
            )
        environment.errored()


    def status_ready(self, executor_id: str) -> None:
        pass

    def status_error(self, executor_id: str) -> None:
        pass


class PlacementService:

    def prepare_host_for_execution_environment(self):

    def stop(self):
        ...