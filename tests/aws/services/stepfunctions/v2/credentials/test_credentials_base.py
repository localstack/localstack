import json

import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.config import SECONDARY_TEST_AWS_ACCOUNT_ID, TEST_AWS_ACCOUNT_ID
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
    create_state_machine_with_iam_role,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import (
    BaseTemplate as BT,
)
from tests.aws.services.stepfunctions.templates.credentials.credentials_templates import (
    CredentialsTemplates as CT,
)
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
        "$..RedriveCount",
        "$..RedriveStatus",
        "$..RedriveStatusReason",
    ]
)
class TestCredentialsBase:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [CT.EMPTY_CREDENTIALS, CT.INVALID_CREDENTIALS_FIELD],
        ids=["EMPTY_CREDENTIALS", "INVALID_CREDENTIALS_FIELD"],
    )
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message", "$..message"])
    def test_invalid_credentials_field(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
        template_path,
    ):
        snf_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "sfn_role_arn"))

        definition = CT.load_sfn_template(template_path)
        definition_str = json.dumps(definition)

        sm_name = f"statemachine_{short_uid()}"

        with pytest.raises(Exception) as ex:
            create_state_machine(
                aws_client, name=sm_name, definition=definition_str, roleArn=snf_role_arn
            )
        sfn_snapshot.match("invalid_definition", ex.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [
            CT.SFN_START_EXECUTION_SYNC_ROLE_ARN_JSONATA,
            CT.SFN_START_EXECUTION_SYNC_ROLE_ARN_PATH,
            CT.SFN_START_EXECUTION_SYNC_ROLE_ARN_PATH_CONTEXT,
            CT.SFN_START_EXECUTION_SYNC_ROLE_ARN_VARIABLE,
            CT.SFN_START_EXECUTION_SYNC_ROLE_ARN_INTRINSIC,
        ],
        ids=[
            "SFN_START_EXECUTION_SYNC_ROLE_ARN_JSONATA",
            "SFN_START_EXECUTION_SYNC_ROLE_ARN_PATH",
            "SFN_START_EXECUTION_SYNC_ROLE_ARN_PATH_CONTEXT",
            "SFN_START_EXECUTION_SYNC_ROLE_ARN_VARIABLE",
            "SFN_START_EXECUTION_SYNC_ROLE_ARN_INTRINSIC",
        ],
    )
    def test_cross_account_states_start_sync_execution(
        self,
        aws_client,
        secondary_aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        create_cross_account_admin_role_and_policy,
        sfn_snapshot,
        template_path,
    ):
        trusted_role_arn = create_cross_account_admin_role_and_policy(
            trusted_aws_client=aws_client,
            trusting_aws_client=secondary_aws_client,
            trusted_account_id=TEST_AWS_ACCOUNT_ID,
        )
        sfn_snapshot.add_transformer(RegexTransformer(trusted_role_arn, "<trusted_role_arn>"))
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output.StartDate",
                replacement="<start-date>",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output.StopDate",
                replacement="<stop-date>",
                replace_reference=False,
            )
        )
        target_definition = json.dumps(BT.load_sfn_template(BT.BASE_PASS_RESULT))
        target_state_machine_arn = create_state_machine_with_iam_role(
            secondary_aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            target_definition,
        )
        definition = json.dumps(CT.load_sfn_template(template_path))
        exec_input = json.dumps(
            {
                "StateMachineArn": target_state_machine_arn,
                "Input": json.dumps("InputFromTrustedAccount"),
                "Name": "TestTaskTargetWithCredentials",
                "CredentialsRoleArn": trusted_role_arn,
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
        sfn_snapshot.add_transformers_list(
            [
                RegexTransformer(TEST_AWS_ACCOUNT_ID, "<test_aws_account_id>"),
                RegexTransformer(SECONDARY_TEST_AWS_ACCOUNT_ID, "<secondary_test_aws_account_id>"),
            ]
        )

    @markers.aws.validated
    def test_cross_account_lambda_task(
        self,
        aws_client,
        secondary_aws_client,
        create_lambda_function,
        create_state_machine_iam_role,
        create_state_machine,
        create_cross_account_admin_role_and_policy,
        sfn_snapshot,
    ):
        trusted_role_arn = create_cross_account_admin_role_and_policy(
            trusted_aws_client=secondary_aws_client,
            trusting_aws_client=aws_client,
            trusted_account_id=SECONDARY_TEST_AWS_ACCOUNT_ID,
        )
        sfn_snapshot.add_transformer(RegexTransformer(trusted_role_arn, "<trusted_role_arn>"))
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_response = create_lambda_function(
            func_name=function_name, handler_file=ST.LAMBDA_ID_FUNCTION, runtime=Runtime.python3_12
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        template = CT.load_sfn_template(CT.LAMBDA_TASK)
        template["States"]["LambdaTask"]["Resource"] = create_lambda_response[
            "CreateFunctionResponse"
        ]["FunctionArn"]
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "Payload": json.dumps("PayloadFromTrustedAccount"),
                "CredentialsRoleArn": trusted_role_arn,
            }
        )
        create_and_record_execution(
            secondary_aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
        sfn_snapshot.add_transformers_list(
            [
                RegexTransformer(TEST_AWS_ACCOUNT_ID, "<test_aws_account_id>"),
                RegexTransformer(SECONDARY_TEST_AWS_ACCOUNT_ID, "<secondary_test_aws_account_id>"),
            ]
        )

    @markers.aws.validated
    def test_cross_account_service_lambda_invoke(
        self,
        aws_client,
        secondary_aws_client,
        create_lambda_function,
        create_state_machine_iam_role,
        create_state_machine,
        create_cross_account_admin_role_and_policy,
        sfn_snapshot,
    ):
        trusted_role_arn = create_cross_account_admin_role_and_policy(
            trusted_aws_client=secondary_aws_client,
            trusting_aws_client=aws_client,
            trusted_account_id=SECONDARY_TEST_AWS_ACCOUNT_ID,
        )
        sfn_snapshot.add_transformer(RegexTransformer(trusted_role_arn, "<trusted_role_arn>"))
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name, handler_file=ST.LAMBDA_ID_FUNCTION, runtime=Runtime.python3_12
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        template = CT.load_sfn_template(CT.SERVICE_LAMBDA_INVOKE)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "FunctionName": function_name,
                "Payload": json.dumps("PayloadFromTrustedAccount"),
                "CredentialsRoleArn": trusted_role_arn,
            }
        )
        create_and_record_execution(
            secondary_aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
        sfn_snapshot.add_transformers_list(
            [
                RegexTransformer(TEST_AWS_ACCOUNT_ID, "<test_aws_account_id>"),
                RegexTransformer(SECONDARY_TEST_AWS_ACCOUNT_ID, "<secondary_test_aws_account_id>"),
            ]
        )

    @markers.aws.validated
    def test_cross_account_service_lambda_invoke_retry(
        self,
        aws_client,
        secondary_aws_client,
        create_lambda_function,
        create_state_machine_iam_role,
        create_state_machine,
        create_cross_account_admin_role_and_policy,
        sfn_snapshot,
    ):
        trusted_role_arn = create_cross_account_admin_role_and_policy(
            trusted_aws_client=secondary_aws_client,
            trusting_aws_client=aws_client,
            trusted_account_id=SECONDARY_TEST_AWS_ACCOUNT_ID,
        )
        sfn_snapshot.add_transformer(RegexTransformer(trusted_role_arn, "<trusted_role_arn>"))
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        template = CT.load_sfn_template(CT.SERVICE_LAMBDA_INVOKE_RETRY)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "FunctionName": function_name,
                "Payload": json.dumps("PayloadFromTrustedAccount"),
                "CredentialsRoleArn": trusted_role_arn,
            }
        )
        create_and_record_execution(
            secondary_aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
        sfn_snapshot.add_transformers_list(
            [
                RegexTransformer(TEST_AWS_ACCOUNT_ID, "<test_aws_account_id>"),
                RegexTransformer(SECONDARY_TEST_AWS_ACCOUNT_ID, "<secondary_test_aws_account_id>"),
            ]
        )
