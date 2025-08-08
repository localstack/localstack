from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class KMSKeyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::KMS::Key"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.kms.resource_providers.aws_kms_key import KMSKeyProvider

        self.factory = KMSKeyProvider
