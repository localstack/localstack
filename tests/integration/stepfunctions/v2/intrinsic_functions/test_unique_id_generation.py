import json

import pytest

from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.integration.stepfunctions.utils import await_execution_success, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@pytest.mark.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestUniqueIdGeneration:
    def test_uuid(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = IFT.load_sfn_template(IFT.UUID)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = stepfunctions_client.start_execution(stateMachineArn=state_machine_arn)
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        exec_hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        output = JSONPathUtils.extract_json(
            "$..executionSucceededEventDetails..output", exec_hist_resp
        )
        uuid = json.loads(output)[IFT.FUNCTION_OUTPUT_KEY]
        snapshot.add_transformer(RegexTransformer(uuid, "generated-uuid"))

        snapshot.match("exec_hist_resp", exec_hist_resp)
