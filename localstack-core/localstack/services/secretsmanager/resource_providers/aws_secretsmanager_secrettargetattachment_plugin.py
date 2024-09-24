from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SecretsManagerSecretTargetAttachmentProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SecretsManager::SecretTargetAttachment"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.secretsmanager.resource_providers.aws_secretsmanager_secrettargetattachment import (
            SecretsManagerSecretTargetAttachmentProvider,
        )

        self.factory = SecretsManagerSecretTargetAttachmentProvider
