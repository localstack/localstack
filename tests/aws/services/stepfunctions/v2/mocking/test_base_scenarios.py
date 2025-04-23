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
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.mocked_responses.mocked_response_loader import (
    MockedResponseLoader,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=["$..SdkHttpMetadata", "$..SdkResponseMetadata", "$..ExecutedVersion"]
)
class TestBaseScenarios:
    @markers.aws.validated
    def test_lambda_service_invoke(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        template = ST.load_sfn_template(ST.LAMBDA_INVOKE)
        definition = json.dumps(template)

        function_name = f"lambda_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))
        exec_input = json.dumps({"FunctionName": function_name, "Payload": {"body": "string body"}})

        if is_aws_cloud():
            create_lambda_function(
                func_name=function_name,
                handler_file=ST.LAMBDA_ID_FUNCTION,
                runtime=Runtime.python3_12,
            )
            create_and_record_execution(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition,
                exec_input,
            )
        else:
            state_machine_name = f"mocked_state_machine_{short_uid()}"
            test_name = "TestCaseName"
            lambda_200_string_body = MockedResponseLoader.load(
                MockedResponseLoader.LAMBDA_200_STRING_BODY
            )
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"Start": "lambda_200_string_body"}}
                    }
                },
                "MockedResponses": {"lambda_200_string_body": lambda_200_string_body},
            }
            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
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
