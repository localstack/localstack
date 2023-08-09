from plugin import Plugin


class RuntimeExecutorPlugin(Plugin):
    namespace = "localstack.lambda.runtime_executor"


class DockerRuntimeExecutorPlugin(RuntimeExecutorPlugin):
    name = "docker"

    def load(self, *args, **kwargs):
        from localstack.services.lambda_.invocation.docker_runtime_executor import (
            DockerRuntimeExecutor,
        )

        return DockerRuntimeExecutor
