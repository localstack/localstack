import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    await_execution_terminated,
    create_and_record_execution,
    create_and_record_mocked_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.mocked_responses.mocked_response_loader import (
    MockedResponseLoader,
)
from tests.aws.services.stepfunctions.templates.scenarios.scenarios_templates import (
    ScenariosTemplate,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import ServicesTemplates


@markers.snapshot.skip_snapshot_verify(
    paths=["$..SdkHttpMetadata", "$..SdkResponseMetadata", "$..ExecutedVersion"]
)
class TestBaseScenarios:
    @markers.aws.validated
    def test_lambda_invoke(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        function_name = f"lambda_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))

        template = ServicesTemplates.load_sfn_template(ServicesTemplates.LAMBDA_INVOKE_RESOURCE)
        exec_input = json.dumps({"body": "string body"})

        if is_aws_cloud():
            lambda_creation_response = create_lambda_function(
                func_name=function_name,
                handler_file=ServicesTemplates.LAMBDA_ID_FUNCTION,
                runtime=Runtime.python3_12,
            )
            lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]
            template["States"]["step1"]["Resource"] = lambda_arn
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
            state_machine_name = f"mocked_state_machine_{short_uid()}"
            test_name = "TestCaseName"
            lambda_200_string_body = MockedResponseLoader.load(
                MockedResponseLoader.LAMBDA_200_STRING_BODY
            )
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"step1": "lambda_200_string_body"}}
                    }
                },
                "MockedResponses": {"lambda_200_string_body": lambda_200_string_body},
            }
            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
            template["States"]["step1"]["Resource"] = (
                f"arn:aws:lambda:us-east-1:111111111111:function:{function_name}"
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

    @markers.aws.only_localstack
    def test_lambda_invoke_retries(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        monkeypatch,
        mock_config_file,
    ):
        template = ScenariosTemplate.load_sfn_template(
            ScenariosTemplate.LAMBDA_INVOKE_WITH_RETRY_BASE
        )
        template["States"]["InvokeLambdaWithRetry"]["Resource"] = (
            "arn:aws:lambda:us-east-1:111111111111:function:nosuchfunction"
        )
        definition = json.dumps(template)

        state_machine_name = f"mocked_state_machine_{short_uid()}"
        test_name = "TestCaseName"
        lambda_not_ready_timeout_200_string_body = MockedResponseLoader.load(
            MockedResponseLoader.LAMBDA_NOT_READY_TIMEOUT_200_STRING_BODY
        )
        mock_config = {
            "StateMachines": {
                state_machine_name: {
                    "TestCases": {
                        test_name: {
                            "InvokeLambdaWithRetry": "lambda_not_ready_timeout_200_string_body"
                        }
                    }
                }
            },
            "MockedResponses": {
                "lambda_not_ready_timeout_200_string_body": lambda_not_ready_timeout_200_string_body
            },
        }
        mock_config_file_path = mock_config_file(mock_config)
        monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)

        role_arn = create_state_machine_iam_role(target_aws_client=aws_client)

        state_machine = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=definition,
            roleArn=role_arn,
        )
        state_machine_arn = state_machine["stateMachineArn"]

        sfn_client = aws_client.stepfunctions
        execution = sfn_client.start_execution(
            stateMachineArn=f"{state_machine_arn}#{test_name}", input="{}"
        )
        execution_arn = execution["executionArn"]

        await_execution_terminated(stepfunctions_client=sfn_client, execution_arn=execution_arn)

        execution_history = sfn_client.get_execution_history(
            executionArn=execution_arn, includeExecutionData=True
        )
        events = execution_history["events"]

        event_4 = events[4]
        assert event_4["taskFailedEventDetails"] == {
            "error": "Lambda.ResourceNotReadyException",
            "cause": "This is a mocked lambda error",
        }

        event_7 = events[7]
        assert event_7["taskFailedEventDetails"] == {
            "error": "Lambda.TimeoutException",
            "cause": "This is a mocked lambda error",
        }

        last_event = events[-1]
        assert last_event["type"] == HistoryEventType.ExecutionSucceeded
        assert last_event["executionSucceededEventDetails"]["output"] == '{"Retries":2}'

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
        template = ServicesTemplates.load_sfn_template(ServicesTemplates.LAMBDA_INVOKE)
        definition = json.dumps(template)

        function_name = f"lambda_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))
        exec_input = json.dumps({"FunctionName": function_name, "Payload": {"body": "string body"}})

        if is_aws_cloud():
            create_lambda_function(
                func_name=function_name,
                handler_file=ServicesTemplates.LAMBDA_ID_FUNCTION,
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
