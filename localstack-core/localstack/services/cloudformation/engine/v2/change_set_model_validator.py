from localstack.services.cloudformation.engine.v2.change_set_model import (
    Maybe,
    NodeIntrinsicFunction,
    NodeTemplate,
    Nothing,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
)


class ChangeSetModelValidator(ChangeSetModelPreproc):
    def validate(self):
        self.process()

    def visit_node_template(self, node_template: NodeTemplate):
        self.visit(node_template.mappings)
        self.visit(node_template.resources)

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_arguments: Maybe[str | list[str]] = arguments_delta.before
        after_arguments: Maybe[str | list[str]] = arguments_delta.after

        before = self._before_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(before) and not is_nothing(before_arguments):
            before = ".".join(before_arguments)

        after = self._after_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(after) and not is_nothing(after_arguments):
            after = ".".join(after_arguments)

        return PreprocEntityDelta(before=before, after=after)
