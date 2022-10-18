from localstack.services.awslambda.invocation.runtime_executor import RuntimeExecutorPlugin


class DockerRuntimeExecutorPlugin(RuntimeExecutorPlugin):
    name = "docker"

    def load(self, *args, **kwargs):
        from localstack.services.awslambda.invocation.docker_runtime_executor import (
            DockerRuntimeExecutor,
        )

        return DockerRuntimeExecutor
