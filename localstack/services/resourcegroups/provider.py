from abc import ABC

from localstack.aws.api.resource_groups import ResourceGroupsApi


class ResourceGroupsProvider(ResourceGroupsApi, ABC):
    pass
