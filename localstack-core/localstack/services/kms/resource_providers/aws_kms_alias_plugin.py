from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class KMSAliasProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::KMS::Alias"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.kms.resource_providers.aws_kms_alias import KMSAliasProvider

        self.factory = KMSAliasProvider
