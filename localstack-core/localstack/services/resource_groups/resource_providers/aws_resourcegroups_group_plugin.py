from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ResourceGroupsGroupProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ResourceGroups::Group"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.resource_groups.resource_providers.aws_resourcegroups_group import (
            ResourceGroupsGroupProvider,
        )

        self.factory = ResourceGroupsGroupProvider
