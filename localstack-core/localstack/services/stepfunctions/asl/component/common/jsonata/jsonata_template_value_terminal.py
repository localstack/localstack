import abc
from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value import (
    JSONataTemplateValue,
)
from localstack.services.stepfunctions.asl.component.intrinsic.jsonata import (
    get_intrinsic_functions_declarations,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    JSONataExpression,
    VariableDeclarations,
    VariableReference,
    compose_jsonata_expression,
    eval_jsonata_expression,
    extract_jsonata_variable_references,
)
from localstack.services.stepfunctions.asl.jsonata.validations import (
    validate_jsonata_expression_output,
)


class JSONataTemplateValueTerminal(JSONataTemplateValue, abc.ABC): ...


class JSONataTemplateValueTerminalLit(JSONataTemplateValueTerminal):
    value: Final[Any]

    def __init__(self, value: Any):
        super().__init__()
        self.value = value

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.value)


class JSONataTemplateValueTerminalExpression(JSONataTemplateValueTerminal):
    expression: Final[str]

    def __init__(self, expression: str):
        super().__init__()
        # TODO: check for illegal functions ($, $$, $eval)
        self.expression = expression

    def _eval_body(self, env: Environment) -> None:
        # Get the variables sampled in the jsonata expression.
        expression_variable_references: set[VariableReference] = (
            extract_jsonata_variable_references(self.expression)
        )

        # Sample declarations for used intrinsic functions. Place this at the start allowing users to
        # override these identifiers with custom variable declarations.
        functions_variable_declarations: VariableDeclarations = (
            get_intrinsic_functions_declarations(variable_references=expression_variable_references)
        )

        # Sample $states values into expression.
        states_variable_declarations: VariableDeclarations = env.states.to_variable_declarations(
            variable_references=expression_variable_references
        )

        # Sample Variable store values in to expression.
        # TODO: this could be optimised by sampling only those invoked.
        variable_declarations: VariableDeclarations = env.variable_store.get_variable_declarations()

        rich_jsonata_expression: JSONataExpression = compose_jsonata_expression(
            final_jsonata_expression=self.expression,
            variable_declarations_list=[
                functions_variable_declarations,
                states_variable_declarations,
                variable_declarations,
            ],
        )
        result = eval_jsonata_expression(rich_jsonata_expression)

        validate_jsonata_expression_output(env, self.expression, rich_jsonata_expression, result)

        env.stack.append(result)
