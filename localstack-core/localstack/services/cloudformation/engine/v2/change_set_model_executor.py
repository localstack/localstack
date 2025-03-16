import logging
from typing import Final, cast

from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeProperty,
    NodeResource,
    NodeTemplate,
    TerminalValue,
)
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)

LOG = logging.getLogger(__name__)


class ChangeSetModelExecutor(ChangeSetModelVisitor):
    node_template: Final[NodeTemplate]
    account_id: Final[str]
    region: Final[str]

    def __init__(self, node_template: NodeTemplate, account_id: str, region: str):
        self.node_template = node_template
        self.account_id = account_id
        self.region = region
        super().__init__()

    def execute(self):
        self.visit(self.node_template)

    def visit_node_resource(self, node_resource: NodeResource):
        resource_type = cast(TerminalValue, node_resource.type_).value
        LOG.info("SRW: visiting %s (%s)", node_resource.name, resource_type)
        return super().visit_node_resource(node_resource)

    def visit_node_property(self, node_property: NodeProperty):
        LOG.info("SRW: visiting property %s", node_property.name)
        return super().visit_node_property(node_property)
