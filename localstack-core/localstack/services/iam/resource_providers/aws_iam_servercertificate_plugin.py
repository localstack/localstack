from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class IAMServerCertificateProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::ServerCertificate"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.iam.resource_providers.aws_iam_servercertificate import (
            IAMServerCertificateProvider,
        )

        self.factory = IAMServerCertificateProvider
