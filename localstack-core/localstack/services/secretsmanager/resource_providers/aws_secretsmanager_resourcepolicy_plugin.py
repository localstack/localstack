from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SecretsManagerResourcePolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SecretsManager::ResourcePolicy"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.secretsmanager.resource_providers.aws_secretsmanager_resourcepolicy import (
            SecretsManagerResourcePolicyProvider,
        )

        self.factory = SecretsManagerResourcePolicyProvider
