import copy
from typing import Final, Optional

from jsonpath_ng import parse

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ResultPath(EvalComponent):
    DEFAULT_PATH: Final[str] = "$"

    result_path_src: Final[Optional[str]]

    def __init__(self, result_path_src: Optional[str]):
        self.result_path_src = result_path_src

    def _eval_body(self, env: Environment) -> None:
        state_input = copy.deepcopy(env.inp)

        # Discard task output if there is one, and set the output ot be the state's input.
        if self.result_path_src is None:
            env.stack.clear()
            env.stack.append(state_input)
            return

        # Transform the output with the input.
        current_output = env.stack.pop()
        result_expr = parse(self.result_path_src)
        state_output = result_expr.update_or_create(state_input, copy.deepcopy(current_output))
        env.stack.append(state_output)
