import copy
from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    VariableDeclarations,
    compose_jsonata_expression,
    eval_jsonata_expression,
)
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class ItemsPath(EvalComponent):
    DEFAULT_PATH: Final[str] = "$"
    path: Final[str]

    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path

    def _eval_body(self, env: Environment) -> None:
        value = copy.deepcopy(env.stack[-1])
        if self.path != ItemsPath.DEFAULT_PATH:
            value = extract_json(self.path, value)
        env.stack.append(value)


class ItemsPathContextObject(ItemsPath):
    def __init__(self, path: str):
        path_tail = path[1:]
        super().__init__(path=path_tail)

    def _eval_body(self, env: Environment) -> None:
        value = extract_json(self.path, env.states.context_object.context_object_data)
        env.stack.append(copy.deepcopy(value))


class ItemsPathVar(ItemsPath):
    def _eval_body(self, env: Environment) -> None:
        variable_declarations: VariableDeclarations = env.variable_store.get_variable_declarations()
        jsonata_expression = compose_jsonata_expression(
            final_jsonata_expression=self.path,  # noqa
            variable_declarations_list=[variable_declarations],
        )
        value = eval_jsonata_expression(jsonata_expression=jsonata_expression)
        env.stack.append(copy.deepcopy(value))
