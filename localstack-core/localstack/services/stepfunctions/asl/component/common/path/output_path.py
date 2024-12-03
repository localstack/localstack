import abc
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class OutputPath(EvalComponent, abc.ABC): ...


class OutputPathBase(OutputPath):
    DEFAULT_PATH: Final[str] = "$"

    output_path: Final[Optional[str]]

    def __init__(self, output_path: Optional[str]):
        self.output_path = output_path

    def _eval_body(self, env: Environment) -> None:
        if self.output_path is None:
            env.states.reset(input_value=dict())
        else:
            current_output = env.stack.pop()
            state_output = extract_json(self.output_path, current_output)
            env.states.reset(input_value=state_output)


class OutputPathContextObject(OutputPathBase):
    def __init__(self, output_path: str):
        output_path_tail = output_path[1:]
        super().__init__(output_path=output_path_tail)

    def _eval_body(self, env: Environment) -> None:
        env.stack.pop()  # Discards the state output in favour of the context object path.
        value = extract_json(self.output_path, env.states.context_object.context_object_data)
        env.states.reset(input_value=value)


class OutputPathVar(OutputPath):
    variable_sample: Final[VariableSample]

    def __init__(self, variable_sample: VariableSample):
        self.variable_sample = variable_sample

    def _eval_body(self, env: Environment) -> None:
        self.variable_sample.eval(env=env)
        value = env.stack.pop()
        env.states.reset(input_value=value)
