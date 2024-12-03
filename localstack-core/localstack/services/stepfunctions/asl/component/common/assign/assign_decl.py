from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.assign.assign_decl_binding import (
    AssignDeclBinding,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class AssignDecl(EvalComponent):
    declaration_bindings: Final[list[AssignDeclBinding]]

    def __init__(self, declaration_bindings: list[AssignDeclBinding]):
        super().__init__()
        self.declaration_bindings = declaration_bindings

    def _eval_body(self, env: Environment) -> None:
        declarations: dict[str, Any] = dict()
        for declaration_binding in self.declaration_bindings:
            declaration_binding.eval(env=env)
            binding: dict[str, Any] = env.stack.pop()
            declarations.update(binding)
        for identifier, value in declarations.items():
            env.variable_store.set(variable_identifier=identifier, variable_value=value)
