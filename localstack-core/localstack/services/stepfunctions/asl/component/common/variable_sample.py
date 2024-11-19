from typing import Final

from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguageMode
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    JSONataExpression,
    VariableDeclarations,
    VariableReference,
    compose_jsonata_expression,
    eval_jsonata_expression,
    extract_jsonata_variable_references,
)


class VariableSample(EvalComponent):
    query_language_mode: Final[QueryLanguageMode]
    expression: Final[str]

    def __init__(self, query_language_mode: QueryLanguageMode, expression: str):
        super().__init__()
        # TODO: check for illegal functions ($, $$, $eval)
        self.query_language_mode = query_language_mode
        self.expression = expression

    def _eval_body(self, env: Environment) -> None:
        # Get the variables sampled in the jsonata expression.
        expression_variable_references: set[VariableReference] = (
            extract_jsonata_variable_references(self.expression)
        )
        variable_declarations_list = list()
        if self.query_language_mode == QueryLanguageMode.JSONata:
            # Sample $states values into expression.
            states_variable_declarations: VariableDeclarations = (
                env.states.to_variable_declarations(
                    variable_references=expression_variable_references
                )
            )
            variable_declarations_list.append(states_variable_declarations)

        # Sample Variable store values in to expression.
        # TODO: this could be optimised by sampling only those invoked.
        variable_declarations: VariableDeclarations = env.variable_store.get_variable_declarations()
        variable_declarations_list.append(variable_declarations)

        rich_jsonata_expression: JSONataExpression = compose_jsonata_expression(
            final_jsonata_expression=self.expression,
            variable_declarations_list=variable_declarations_list,
        )
        result = eval_jsonata_expression(rich_jsonata_expression)
        env.stack.append(result)
