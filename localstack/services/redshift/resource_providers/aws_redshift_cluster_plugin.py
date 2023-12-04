from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class RedshiftClusterProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Redshift::Cluster"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.redshift.resource_providers.aws_redshift_cluster import (
            RedshiftClusterProvider,
        )

        self.factory = RedshiftClusterProvider
