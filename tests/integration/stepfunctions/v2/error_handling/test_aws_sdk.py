import json

import pytest

from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)
from tests.integration.stepfunctions.utils import await_execution_success, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


# TODO: test for validation errors, and boundary testing.


@pytest.mark.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestAwsSdk:
    @staticmethod
    def _test_aws_sdk_scenario(
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
        definition,
        execution_input,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))
        snapshot.add_transformer(
            RegexTransformer(
                "Extended Request ID: [a-zA-Z0-9-/=+]+",
                "Extended Request ID: <extended_request_id>",
            )
        )
        snapshot.add_transformer(
            RegexTransformer("Request ID: [a-zA-Z0-9-]+", "Request ID: <request_id>")
        )

        sm_name: str = f"statemachine_{short_uid()}"
        creation_resp = create_state_machine(
            name=sm_name, definition=definition, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn, input=execution_input
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        get_execution_history = stepfunctions_client.get_execution_history(
            executionArn=execution_arn
        )
        snapshot.match("get_execution_history", get_execution_history)

    def test_invalid_secret_name(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        template = EHT.load_sfn_template(EHT.AWS_SDK_TASK_FAILED_SECRETSMANAGER_CREATE_SECRET)
        definition = json.dumps(template)
        exec_input = json.dumps({"Name": "Invalid Name", "SecretString": "HelloWorld"})
        self._test_aws_sdk_scenario(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )

    def test_no_such_bucket(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        template = EHT.load_sfn_template(EHT.AWS_SDK_TASK_FAILED_S3_LIST_OBJECTS)
        definition = json.dumps(template)
        bucket_name = f"someNonexistentBucketName{short_uid()}"
        snapshot.add_transformer(RegexTransformer(bucket_name, "someNonexistentBucketName"))
        exec_input = json.dumps({"Bucket": bucket_name})
        self._test_aws_sdk_scenario(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )
