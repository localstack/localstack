from botocore.exceptions import ParamValidationError

from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeProperty,
    NodeResource,
    NodeTemplate,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_static_preproc import (
    ChangeSetModelStaticPreproc,
    PreprocEntityDelta,
)
from localstack.services.cloudformation.engine.validations import ValidationError


class ChangeSetModelValidator(ChangeSetModelStaticPreproc):
    def validate(self):
        self.process()

    def visit_node_template(self, node_template: NodeTemplate):
        self.visit(node_template.mappings)
        self.visit(node_template.resources)
        self.visit(node_template.parameters)

    def visit_node_resource(self, node_resource: NodeResource) -> PreprocEntityDelta:
        if is_nothing(node_resource.type_.value):
            raise ValidationError(
                f"Template format error: [{node_resource.scope}] Every Resources object must contain a Type member."
            )
        try:
            if delta := super().visit_node_resource(node_resource):
                return delta
            return super().visit_node_properties(node_resource.properties)
        except RuntimeError:
            return super().visit_node_properties(node_resource.properties)

    def visit_node_property(self, node_property: NodeProperty) -> PreprocEntityDelta:
        try:
            return super().visit_node_property(node_property)
        except ParamValidationError:
            return self.visit(node_property.value)

    # ignore errors from dynamic replacements
    def _maybe_perform_dynamic_replacements(self, delta: PreprocEntityDelta) -> PreprocEntityDelta:
        try:
            return super()._maybe_perform_dynamic_replacements(delta)
        except Exception:
            return delta
