from localstack.services.cloudformation.engine.v2.change_set_model import ChangeSetEntity
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
)


class ChangeSetModelValidator(ChangeSetModelPreproc):
    def validate(self):
        self.visit(self._node_template)

    def visit(self, change_set_entity: ChangeSetEntity):
        scope = change_set_entity.scope
        if scope in self._processed:
            return
        change_set_entity.validate(change_set_entity)
