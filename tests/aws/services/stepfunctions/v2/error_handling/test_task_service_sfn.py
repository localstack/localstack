import json

from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create,
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate as BT
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestTaskServiceSfn:
    @markers.aws.validated
    def test_start_execution_no_such_arn(
        self,
        aws_client,
        create_iam_role_for_sfn,
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
        state_machine_arn_target = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )
        aws_client.stepfunctions.delete_state_machine(stateMachineArn=state_machine_arn_target)

        template = ST.load_sfn_template(ST.SFN_START_EXECUTION)
        definition = json.dumps(template)

        random_arn_part = f"NoSuchArn{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(random_arn_part, "<random_arn_part>"))

        exec_input = json.dumps(
            {
                "StateMachineArn": f"{state_machine_arn_target}{random_arn_part}",
                "Input": None,
                "Name": "TestStartTarget",
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
