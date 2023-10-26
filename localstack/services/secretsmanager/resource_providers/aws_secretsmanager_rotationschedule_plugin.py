from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SecretsManagerRotationScheduleProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SecretsManager::RotationSchedule"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.secretsmanager.resource_providers.aws_secretsmanager_rotationschedule import (
            SecretsManagerRotationScheduleProvider,
        )

        self.factory = SecretsManagerRotationScheduleProvider
