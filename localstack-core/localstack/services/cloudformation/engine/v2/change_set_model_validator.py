import re

from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeParameters,
    NodeResource,
    NodeTemplate,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    PreprocEntityDelta,
)
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.v2.entities import ChangeSet

VALID_LOGICAL_RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9]+$")


class ChangeSetModelValidator(ChangeSetModelVisitor):
    def __init__(self, change_set: ChangeSet):
        self._change_set = change_set

    def validate(self):
        self.visit(self._change_set.update_model.node_template)

    def visit_node_template(self, node_template: NodeTemplate):
        self.visit(node_template.parameters)
        self.visit(node_template.resources)

    def visit_node_parameters(self, node_parameters: NodeParameters) -> PreprocEntityDelta:
        # check that all parameters have values
        invalid_parameters = []
        for node_parameter in node_parameters.parameters:
            self.visit(node_parameter)
            if is_nothing(node_parameter.default_value.value) and is_nothing(
                node_parameter.dynamic_value.value
            ):
                invalid_parameters.append(node_parameter.name)

        if invalid_parameters:
            raise ValidationError(f"Parameters: [{','.join(invalid_parameters)}] must have values")

        # continue visiting
        return super().visit_node_parameters(node_parameters)

    def visit_node_resource(self, node_resource: NodeResource) -> PreprocEntityDelta:
        if not VALID_LOGICAL_RESOURCE_ID_RE.match(node_resource.name):
            raise ValidationError(
                f"Template format error: Resource name {node_resource.name} is non alphanumeric."
            )
        return super().visit_node_resource(node_resource)
