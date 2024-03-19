from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ResourceGroupsGroupProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ResourceGroups::Group"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.resource_groups.resource_providers.aws_resourcegroups_group import (
            ResourceGroupsGroupProvider,
        )

        self.factory = ResourceGroupsGroupProvider
