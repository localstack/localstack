from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeParameters,
    NodeTemplate,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
)
from localstack.services.cloudformation.engine.validations import ValidationError


class ChangeSetModelValidator(ChangeSetModelPreproc):
    def validate(self):
        self.process()

    def visit_node_template(self, node_template: NodeTemplate):
        self.visit(node_template.parameters)
        self.visit(node_template.mappings)
        self.visit(node_template.resources)

    def visit_node_parameters(self, node_parameters: NodeParameters) -> PreprocEntityDelta:
        # check that all parameters have values
        invalid_parameters = []
        for node_parameter in node_parameters.parameters:
            parameter_value = self.visit(node_parameter)
            if is_nothing(parameter_value.before) and is_nothing(parameter_value.after):
                invalid_parameters.append(node_parameter.name)

        if invalid_parameters:
            raise ValidationError(f"Parameters: [{','.join(invalid_parameters)}] must have values")

        # continue visiting
        return super().visit_node_parameters(node_parameters)
