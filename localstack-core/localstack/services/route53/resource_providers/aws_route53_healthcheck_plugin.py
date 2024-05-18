from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class Route53HealthCheckProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Route53::HealthCheck"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.route53.resource_providers.aws_route53_healthcheck import (
            Route53HealthCheckProvider,
        )

        self.factory = Route53HealthCheckProvider
