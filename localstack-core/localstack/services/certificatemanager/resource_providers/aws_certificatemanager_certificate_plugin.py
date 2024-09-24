from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CertificateManagerCertificateProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CertificateManager::Certificate"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.certificatemanager.resource_providers.aws_certificatemanager_certificate import (
            CertificateManagerCertificateProvider,
        )

        self.factory = CertificateManagerCertificateProvider
