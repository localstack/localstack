import json

import pytest
from jsonpath_ng.ext import parse
from localstack_snapshot.snapshots.transformer import RegexTransformer, TransformContext

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import await_execution_terminated
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.assign.assign_templates import (
    AssignTemplate as AT,
)
from tests.aws.services.stepfunctions.templates.scenarios.scenarios_templates import (
    ScenariosTemplate as ST,
)


class _SfnSortVariableReferences:
    # TODO: adjust intrinsic functions' variable references ordering and remove this normalisation logic.

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        pattern = parse("$..variableReferences")
        variable_references = pattern.find(input_data)
        for variable_reference in variable_references:
            for variable_name_list in variable_reference.value.values():
                variable_name_list.sort()
        return input_data


@markers.snapshot.skip_snapshot_verify(
    paths=["$..tracingConfiguration", "$..encryptionConfiguration"]
)
class TestSfnApiVariableReferences:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [
            AT.BASE_REFERENCE_IN_PARAMETERS,
            AT.BASE_REFERENCE_IN_CHOICE,
            AT.BASE_REFERENCE_IN_WAIT,
            AT.BASE_REFERENCE_IN_ITERATOR_OUTER_SCOPE,
            AT.BASE_REFERENCE_IN_INPUTPATH,
            AT.BASE_REFERENCE_IN_OUTPUTPATH,
            AT.BASE_REFERENCE_IN_INTRINSIC_FUNCTION,
            AT.BASE_REFERENCE_IN_FAIL,
            AT.BASE_ASSIGN_FROM_PARAMETERS,
            AT.BASE_ASSIGN_FROM_RESULT,
            AT.BASE_ASSIGN_FROM_INTRINSIC_FUNCTION,
            AT.BASE_EVALUATION_ORDER_PASS_STATE,
            AT.MAP_STATE_REFERENCE_IN_INTRINSIC_FUNCTION,
            AT.MAP_STATE_REFERENCE_IN_ITEMS_PATH,
            AT.MAP_STATE_REFERENCE_IN_MAX_CONCURRENCY_PATH,
            AT.MAP_STATE_REFERENCE_IN_TOLERATED_FAILURE_PATH,
            AT.MAP_STATE_REFERENCE_IN_ITEM_SELECTOR,
            AT.MAP_STATE_REFERENCE_IN_MAX_ITEMS_PATH,
        ],
        ids=[
            "BASE_REFERENCE_IN_PARAMETERS",
            "BASE_REFERENCE_IN_CHOICE",
            "BASE_REFERENCE_IN_WAIT",
            "BASE_REFERENCE_IN_ITERATOR_OUTER_SCOPE",
            "BASE_REFERENCE_IN_INPUTPATH",
            "BASE_REFERENCE_IN_OUTPUTPATH",
            "BASE_REFERENCE_IN_INTRINSIC_FUNCTION",
            "BASE_REFERENCE_IN_FAIL",
            "BASE_ASSIGN_FROM_PARAMETERS",
            "BASE_ASSIGN_FROM_RESULT",
            "BASE_ASSIGN_FROM_INTRINSIC_FUNCTION",
            "BASE_EVALUATION_ORDER_PASS_STATE",
            "MAP_STATE_REFERENCE_IN_INTRINSIC_FUNCTION",
            "MAP_STATE_REFERENCE_IN_ITEMS_PATH",
            "MAP_STATE_REFERENCE_IN_MAX_CONCURRENCY_PATH",
            "MAP_STATE_REFERENCE_IN_TOLERATED_FAILURE_PATH",
            "MAP_STATE_REFERENCE_IN_ITEM_SELECTOR",
            "MAP_STATE_REFERENCE_IN_MAX_ITEMS_PATH",
        ],
    )
    def test_base_variable_references_in_assign_templates(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client, template_path
    ):
        sfn_snapshot.add_transformer(_SfnSortVariableReferences())
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "sfn_role_arn"))

        definition = AT.load_sfn_template(template_path)
        definition_str = json.dumps(definition)

        creation_response = create_state_machine(
            name=f"sm-{short_uid()}", definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_response, 0))
        state_machine_arn = creation_response["stateMachineArn"]

        describe_response = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=creation_response["stateMachineArn"]
        )
        sfn_snapshot.match("describe_response", describe_response)

        execution_response = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(execution_response, 0))
        execution_arn = execution_response["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        describe_for_execution_response = (
            aws_client.stepfunctions.describe_state_machine_for_execution(
                executionArn=execution_arn
            )
        )
        sfn_snapshot.match("describe_for_execution_response", describe_for_execution_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [
            ST.CHOICE_CONDITION_CONSTANT_JSONATA,
            ST.CHOICE_STATE_UNSORTED_CHOICE_PARAMETERS_JSONATA,
        ],
        ids=[
            "CHOICE_CONDITION_CONSTANT_JSONATA",
            "CHOICE_STATE_UNSORTED_CHOICE_PARAMETERS_JSONATA",
        ],
    )
    def test_base_variable_references_in_jsonata_template(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client, template_path
    ):
        # This test checks that variable references within jsonata expression are not included.
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "sfn_role_arn"))

        definition = AT.load_sfn_template(template_path)
        definition_str = json.dumps(definition)

        creation_response = create_state_machine(
            name=f"sm-{short_uid()}", definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_response, 0))

        describe_response = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=creation_response["stateMachineArn"]
        )
        sfn_snapshot.match("describe_response", describe_response)
