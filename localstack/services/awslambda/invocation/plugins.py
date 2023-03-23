from plugin import Plugin


class RuntimeExecutorPlugin(Plugin):
    namespace = "localstack.lambda.runtime_executor"


class DockerRuntimeExecutorPlugin(RuntimeExecutorPlugin):
    name = "docker"

    def load(self, *args, **kwargs):
        from localstack.services.awslambda.invocation.docker_runtime_executor import (
            DockerRuntimeExecutor,
        )

        return DockerRuntimeExecutor


class WorkerRuntimeExecutorPlugin(RuntimeExecutorPlugin):
    name = "worker"

    def load(self, *args, **kwargs):
        from localstack.services.awslambda.invocation.worker_runtime_executor import (
            WorkerRuntimeExecutor,
        )

        return WorkerRuntimeExecutor
