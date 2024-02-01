import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.utils import await_execution_success


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestUniqueIdGeneration:
    @markers.aws.validated
    def test_uuid(self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = IFT.load_sfn_template(IFT.UUID)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        exec_hist_resp = aws_client.stepfunctions.get_execution_history(executionArn=execution_arn)
        output = JSONPathUtils.extract_json(
            "$..executionSucceededEventDetails..output", exec_hist_resp
        )
        uuid = json.loads(output)[IFT.FUNCTION_OUTPUT_KEY]
        sfn_snapshot.add_transformer(RegexTransformer(uuid, "generated-uuid"))

        sfn_snapshot.match("exec_hist_resp", exec_hist_resp)
