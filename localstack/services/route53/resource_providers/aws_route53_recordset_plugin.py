from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class Route53RecordSetProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Route53::RecordSet"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.route53.resource_providers.aws_route53_recordset import (
            Route53RecordSetProvider,
        )

        self.factory = Route53RecordSetProvider
