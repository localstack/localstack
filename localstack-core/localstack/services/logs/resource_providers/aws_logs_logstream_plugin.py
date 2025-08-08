from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LogsLogStreamProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Logs::LogStream"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.logs.resource_providers.aws_logs_logstream import (
            LogsLogStreamProvider,
        )

        self.factory = LogsLogStreamProvider
