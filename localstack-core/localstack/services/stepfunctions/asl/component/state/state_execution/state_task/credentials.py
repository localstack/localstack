from dataclasses import dataclass
from typing import Final

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringExpression,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


@dataclass
class StateCredentials:
    role_arn: str


class RoleArn(EvalComponent):
    string_expression: Final[StringExpression]

    def __init__(self, string_expression: StringExpression):
        self.string_expression = string_expression

    def _eval_body(self, env: Environment) -> None:
        self.string_expression.eval(env=env)


class Credentials(EvalComponent):
    role_arn: Final[RoleArn]

    def __init__(self, role_arn: RoleArn):
        self.role_arn = role_arn

    def _eval_body(self, env: Environment) -> None:
        self.role_arn.eval(env=env)
        role_arn = env.stack.pop()
        computes_credentials = StateCredentials(role_arn=role_arn)
        env.stack.append(computes_credentials)
