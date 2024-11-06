from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SESEmailIdentityProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SES::EmailIdentity"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ses.resource_providers.aws_ses_emailidentity import (
            SESEmailIdentityProvider,
        )

        self.factory = SESEmailIdentityProvider
