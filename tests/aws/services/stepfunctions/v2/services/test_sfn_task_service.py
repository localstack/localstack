import json

from localstack_snapshot.snapshots.transformer import JsonpathTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
    create_state_machine_with_iam_role,
)
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate as BT
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestTaskServiceSfn:
    @markers.aws.needs_fixing
    def test_start_execution(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output.StartDate",
                replacement="start-date",
                replace_reference=False,
            )
        )

        template_target = BT.load_sfn_template(BT.BASE_PASS_RESULT)
        definition_target = json.dumps(template_target)
        state_machine_arn_target = create_state_machine_with_iam_role(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )

        template = ST.load_sfn_template(ST.SFN_START_EXECUTION)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"StateMachineArn": state_machine_arn_target, "Input": None, "Name": "TestStartTarget"}
        )
        create_and_record_execution(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_start_execution_input_json(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output.StartDate",
                replacement="start-date",
                replace_reference=False,
            )
        )

        template_target = BT.load_sfn_template(BT.BASE_PASS_RESULT)
        definition_target = json.dumps(template_target)
        state_machine_arn_target = create_state_machine_with_iam_role(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )

        template = ST.load_sfn_template(ST.SFN_START_EXECUTION)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "StateMachineArn": state_machine_arn_target,
                "Input": {"Hello": "World"},
                "Name": "TestStartTarget",
            }
        )
        create_and_record_execution(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
