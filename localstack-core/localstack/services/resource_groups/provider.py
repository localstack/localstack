from localstack.aws.api.resource_groups import ResourceGroupsApi
from localstack.state import StateVisitor


class ResourceGroupsProvider(ResourceGroupsApi):
    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.resourcegroups.models import resourcegroups_backends

        visitor.visit(resourcegroups_backends)
