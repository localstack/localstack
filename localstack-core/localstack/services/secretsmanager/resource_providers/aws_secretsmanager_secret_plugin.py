from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SecretsManagerSecretProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SecretsManager::Secret"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.secretsmanager.resource_providers.aws_secretsmanager_secret import (
            SecretsManagerSecretProvider,
        )

        self.factory = SecretsManagerSecretProvider
