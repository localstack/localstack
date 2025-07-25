from typing import Final

from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeParameters,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
)
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.v2.entities import ChangeSet


class ChangeSetModelValidator(ChangeSetModelPreproc):
    _before_parameters: Final[dict]
    _after_parameters: Final[dict]

    def __init__(
        self,
        change_set: ChangeSet,
        before_parameters: dict,
        after_parameters: dict,
    ):
        super().__init__(change_set)
        self._before_parameters = before_parameters
        self._after_parameters = after_parameters

    def validate(self):
        # validate parameters are all given
        self.visit(self._change_set.update_model.node_template.parameters)

    def visit_node_parameters(self, node_parameters: NodeParameters) -> PreprocEntityDelta:
        delta = super().visit_node_parameters(node_parameters)
        # assert before
        if self._before_parameters:
            missing_values = [key for key in delta.before if delta.before[key] is None]
            if missing_values:
                raise ValidationError()
        if self._after_parameters:
            missing_values = [key for key in delta.after if delta.before[key] is None]
            if missing_values:
                raise ValidationError()

        return delta
