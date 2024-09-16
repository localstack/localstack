import json
from typing import Any, Final

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.services.stepfunctions.asl.utils.json_path import extract_json
from localstack.testing.pytest.stepfunctions.utils import await_execution_success
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.choiceoperators.choice_operators_templates import (
    ChoiceOperatorTemplate as COT,
)

TYPE_COMPARISONS: Final[list[tuple[Any, bool]]] = [
    (None, True),  # 0
    (None, False),  # 1
    (0, True),  # 2
    (0, False),  # 3
    (0.0, True),  # 4
    (0.0, False),  # 5
    (1, True),  # 6
    (1, False),  # 7
    (1.1, True),  # 8
    (1.1, False),  # 9
    ("", True),  # 10
    ("", False),  # 11
    (" ", True),  # 12
    (" ", False),  # 13
    ("HelloWorld", True),  # 14
    ("HelloWorld", False),  # 15
    ("2012-10-09T19:00:55", True),  # 16
    ("2012-10-09T19:00:55", False),  # 17
    ("2012-10-09T19:00:55Z", True),  # 18
    ("2012-10-09T19:00:55Z", False),  # 19
    ("2012-10-09T19:00:55+01:00", True),  # 20
    ("2012-10-09T19:00:55+01:00", False),  # 21
    ("2023-02-24", True),  # 22
    ("2023-02-24", False),  # 23
    ([], True),  # 24
    ([], False),  # 25
    ([""], True),  # 26
    ([""], False),  # 27
    ({}, True),  # 28
    ({}, False),  # 29
    ({"A": 0}, True),  # 30
    ({"A": 0}, False),  # 31
    (True, True),  # 32
    (False, True),  # 33
    (False, True),  # 34
    (False, False),  # 35
]


def create_and_test_comparison_function(
    stepfunctions_client,
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_snapshot,
    comparison_func_name: str,
    comparisons: list[tuple[Any, Any]],
    add_literal_value: bool = True,
):
    snf_role_arn = create_iam_role_for_sfn()
    sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

    base_sm_name: str = f"statemachine_{short_uid()}"

    definition = COT.load_sfn_template(COT.BASE_TEMPLATE)
    definition_str = json.dumps(definition)
    definition_str = definition_str.replace(
        COT.COMPARISON_OPERATOR_PLACEHOLDER, comparison_func_name
    )

    input_output_cases: list[dict[str, Any]] = list()
    for i, (variable, value) in enumerate(comparisons):
        exec_input = json.dumps({COT.VARIABLE_KEY: variable, COT.VALUE_KEY: value})

        if add_literal_value:
            new_definition_str = definition_str.replace(COT.VALUE_PLACEHOLDER, json.dumps(value))
        else:
            new_definition_str = definition_str

        creation_resp = create_state_machine(
            name=f"{base_sm_name}_{i}", definition=new_definition_str, roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn, input=exec_input
        )
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        exec_hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        output = extract_json("$.events[*].executionSucceededEventDetails.output", exec_hist_resp)
        input_output_cases.append({"input": exec_input, "output": output})
    sfn_snapshot.match("cases", input_output_cases)
