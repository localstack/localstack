from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LogsLogGroupProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Logs::LogGroup"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.logs.resource_providers.aws_logs_loggroup import (
            LogsLogGroupProvider,
        )

        self.factory = LogsLogGroupProvider
