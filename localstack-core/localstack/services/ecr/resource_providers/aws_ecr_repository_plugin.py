from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ECRRepositoryProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ECR::Repository"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.ecr.resource_providers.aws_ecr_repository import (
            ECRRepositoryProvider,
        )

        self.factory = ECRRepositoryProvider
