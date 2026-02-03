import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
    create_and_record_mocked_execution,
)
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.local_mocked_service_integrations.mocked_service_integrations import (
    MockedServiceIntegrationsLoader,
)
from tests.aws.services.stepfunctions.templates.scenarios.scenarios_templates import (
    ScenariosTemplate,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import ServicesTemplates


@markers.snapshot.skip_snapshot_verify(
    paths=["$..SdkHttpMetadata", "$..SdkResponseMetadata", "$..events..ExecutedVersion"]
)
@markers.requires_in_process
class TestNumberedMockCycling:
    @markers.aws.validated
    def test_numbered_mock_responses_multiple_invocations(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        create_lambda_function,
        account_id,
        region_name,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        """
        Test that numbered mock responses ("0", "1", etc.) cycle correctly
        through multiple successful invocations of the same state,
        e.g. in a repeat-until loop implemented using a choice state.
        """
        template = ScenariosTemplate.load_sfn_template(ScenariosTemplate.LAMBDA_REPEAT_UNTIL_LOOP)
        template["States"]["LambdaState"]["Arguments"]["Payload"] = {
            "status": "{% $exists($status) ? 'completed' : 'running' %}"
        }

        exec_input = json.dumps({})
        function_name = f"lambda_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))

        if is_aws_cloud():
            lambda_creation_response = create_lambda_function(
                func_name=function_name,
                handler_file=ServicesTemplates.LAMBDA_ID_FUNCTION,
                runtime=Runtime.python3_12,
            )
            lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]
            template["States"]["LambdaState"]["Arguments"]["FunctionName"] = lambda_arn
            definition = json.dumps(template)
            create_and_record_execution(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition,
                exec_input,
            )
        else:
            state_machine_name = f"mock_cycling_test_{short_uid()}"
            test_name = "NumberedResponseCyclingTest"

            sfn_snapshot.add_transformer(RegexTransformer(state_machine_name, "state_machine_name"))

            lambda_200_loop_status = MockedServiceIntegrationsLoader.load(
                MockedServiceIntegrationsLoader.MOCKED_RESPONSE_LAMBDA_200_STATUS_CHANGE_BETWEEN_INVOCATIONS
            )
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"LambdaState": "lambda_200_loop_status"}}
                    }
                },
                "MockedResponses": {"lambda_200_loop_status": lambda_200_loop_status},
            }

            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)

            template["States"]["LambdaState"]["Arguments"]["FunctionName"] = (
                arns.lambda_function_arn(
                    function_name=function_name, account_id=account_id, region_name=region_name
                )
            )
            definition = json.dumps(template)

            create_and_record_mocked_execution(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition,
                exec_input,
                state_machine_name,
                test_name,
            )
