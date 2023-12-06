from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument import (
    FunctionArgument,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class FunctionArgumentJsonPath(FunctionArgument):
    _value: str

    def __init__(self, json_path: str):
        super().__init__()
        self._json_path: str = json_path

    def _eval_body(self, env: Environment) -> None:
        inp = env.stack[-1]
        self._value = JSONPathUtils.extract_json(self._json_path, inp)
        super()._eval_body(env=env)
