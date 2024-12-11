import abc
import copy
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_terminal import (
    JSONataTemplateValueTerminalExpression,
)
from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.intrinsic.intrinsic_parser import IntrinsicParser
from localstack.services.stepfunctions.asl.utils.json_path import extract_json

_CREDENTIALS_ROLE_ARN_KEY: Final[str] = "RoleArn"
ComputedCredentials = dict


class RoleArn(EvalComponent, abc.ABC): ...


class RoleArnConst(RoleArn):
    value: Final[str]

    def __init__(self, value: str):
        self.value = value

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.value)


class RoleArnJSONata(RoleArn):
    jsonata_template_value_terminal_expression: Final[JSONataTemplateValueTerminalExpression]

    def __init__(
        self, jsonata_template_value_terminal_expression: JSONataTemplateValueTerminalExpression
    ):
        super().__init__()
        self.jsonata_template_value_terminal_expression = jsonata_template_value_terminal_expression

    def _eval_body(self, env: Environment) -> None:
        self.jsonata_template_value_terminal_expression.eval(env=env)


class RoleArnVar(RoleArn):
    variable_sample: Final[VariableSample]

    def __init__(self, variable_sample: VariableSample):
        self.variable_sample = variable_sample

    def _eval_body(self, env: Environment) -> None:
        self.variable_sample.eval(env=env)


class RoleArnPath(RoleArnConst):
    def _eval_body(self, env: Environment) -> None:
        current_output = env.stack[-1]
        arn = extract_json(self.value, current_output)
        env.stack.append(arn)


class RoleArnContextObject(RoleArnConst):
    def _eval_body(self, env: Environment) -> None:
        value = extract_json(self.value, env.states.context_object.context_object_data)
        env.stack.append(copy.deepcopy(value))


class RoleArnIntrinsicFunction(RoleArnConst):
    function: Final[Function]

    def __init__(self, value: str) -> None:
        super().__init__(value=value)
        self.function, _ = IntrinsicParser.parse(value)

    def _eval_body(self, env: Environment) -> None:
        self.function.eval(env=env)


class Credentials(EvalComponent):
    role_arn: Final[RoleArn]

    def __init__(self, role_arn: RoleArn):
        self.role_arn = role_arn

    @staticmethod
    def get_role_arn_from(computed_credentials: ComputedCredentials) -> Optional[str]:
        return computed_credentials.get(_CREDENTIALS_ROLE_ARN_KEY)

    def _eval_body(self, env: Environment) -> None:
        self.role_arn.eval(env=env)
        role_arn = env.stack.pop()
        computes_credentials: ComputedCredentials = {_CREDENTIALS_ROLE_ARN_KEY: role_arn}
        env.stack.append(computes_credentials)
