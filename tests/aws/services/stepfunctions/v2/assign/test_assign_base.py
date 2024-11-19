import json

import pytest

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    SfnNoneRecursiveParallelTransformer,
    create_and_record_execution,
)
from tests.aws.services.stepfunctions.templates.assign.assign_templates import AssignTemplate


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        "$..redriveCount",
        "$..redriveStatus",
        "$..RedriveCount",
    ]
)
class TestAssignBase:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [
            AssignTemplate.BASE_EMPTY,
            AssignTemplate.BASE_CONSTANT_LITERALS,
            AssignTemplate.BASE_PATHS,
            AssignTemplate.BASE_VAR,
            AssignTemplate.BASE_SCOPE_MAP,
        ],
        ids=[
            "BASE_EMPTY",
            "BASE_CONSTANT_LITERALS",
            "BASE_PATHS",
            "BASE_VAR",
            "BASE_SCOPE_MAP",
        ],
    )
    def test_base_cases(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, template_path
    ):
        template = AssignTemplate.load_sfn_template(template_path)
        definition = json.dumps(template)
        exec_input = json.dumps({"input_value": "input_value_literal"})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        [
            # TODO: introduce json response formatting to ensure value compatibility, there are some
            #  inconsistencies wrt the separators being used and no trivial reusable logic
            "$..events..executionSucceededEventDetails.output",
            "$..events..stateExitedEventDetails.output",
        ]
    )
    @pytest.mark.parametrize(
        "template_path",
        [AssignTemplate.BASE_SCOPE_PARALLEL],
        ids=["BASE_SCOPE_PARALLEL"],
    )
    def test_base_parallel_cases(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, template_path
    ):
        sfn_snapshot.add_transformer(SfnNoneRecursiveParallelTransformer())
        template = AssignTemplate.load_sfn_template(template_path)
        definition = json.dumps(template)
        exec_input = json.dumps({})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )
