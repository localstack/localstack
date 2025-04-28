import json

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import create_and_run_mock
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.mocked_service_integrations.mocked_service_integrations import (
    MockedServiceIntegrationsLoader,
)
from tests.aws.services.stepfunctions.templates.mocked.mocked_templates import MockedTemplates


class TestBaseScenarios:
    @markers.aws.only_localstack
    def test_lambda_sqs_integration_happy_path(
        self,
        aws_client,
        monkeypatch,
        mock_config_file,
    ):
        execution_arn = create_and_run_mock(
            target_aws_client=aws_client,
            monkeypatch=monkeypatch,
            mock_config_file=mock_config_file,
            mock_config=MockedServiceIntegrationsLoader.load(
                MockedServiceIntegrationsLoader.MOCK_CONFIG_FILE_LAMBDA_SQS_INTEGRATION
            ),
            state_machine_name="LambdaSQSIntegration",
            definition_template=MockedTemplates.load_sfn_template(
                MockedTemplates.LAMBDA_SQS_INTEGRATION
            ),
            execution_input="{}",
            test_name="HappyPath",
        )

        execution_history = aws_client.stepfunctions.get_execution_history(
            executionArn=execution_arn, includeExecutionData=True
        )
        events = execution_history["events"]

        event_4 = events[4]
        assert json.loads(event_4["taskSucceededEventDetails"]["output"]) == {
            "StatusCode": 200,
            "Payload": {"StatusCode": 200, "body": "Hello from Lambda!"},
        }

        event_last = events[-1]
        assert event_last["type"] == "ExecutionSucceeded"

    @markers.aws.only_localstack
    def test_lambda_sqs_integration_retry_path(
        self,
        aws_client,
        monkeypatch,
        mock_config_file,
    ):
        execution_arn = create_and_run_mock(
            target_aws_client=aws_client,
            monkeypatch=monkeypatch,
            mock_config_file=mock_config_file,
            mock_config=MockedServiceIntegrationsLoader.load(
                MockedServiceIntegrationsLoader.MOCK_CONFIG_FILE_LAMBDA_SQS_INTEGRATION
            ),
            state_machine_name="LambdaSQSIntegration",
            definition_template=MockedTemplates.load_sfn_template(
                MockedTemplates.LAMBDA_SQS_INTEGRATION
            ),
            execution_input="{}",
            test_name="RetryPath",
        )

        execution_history = aws_client.stepfunctions.get_execution_history(
            executionArn=execution_arn, includeExecutionData=True
        )
        events = execution_history["events"]

        event_4 = events[4]
        assert event_4["taskFailedEventDetails"] == {
            "error": "Lambda.ResourceNotReadyException",
            "cause": "Lambda resource is not ready.",
        }
        assert event_4["type"] == "TaskFailed"

        event_7 = events[7]
        assert event_7["taskFailedEventDetails"] == {
            "error": "Lambda.TimeoutException",
            "cause": "Lambda timed out.",
        }
        assert event_7["type"] == "TaskFailed"

        event_10 = events[10]
        assert event_10["taskFailedEventDetails"] == {
            "error": "Lambda.TimeoutException",
            "cause": "Lambda timed out.",
        }
        assert event_10["type"] == "TaskFailed"

        event_13 = events[13]
        assert json.loads(event_13["taskSucceededEventDetails"]["output"]) == {
            "StatusCode": 200,
            "Payload": {"StatusCode": 200, "body": "Hello from Lambda!"},
        }

        event_last = events[-1]
        assert event_last["type"] == "ExecutionSucceeded"

    @markers.aws.only_localstack
    def test_lambda_sqs_integration_hybrid_path(
        self,
        aws_client,
        sqs_create_queue,
        monkeypatch,
        mock_config_file,
    ):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        definition_template = MockedTemplates.load_sfn_template(
            MockedTemplates.LAMBDA_SQS_INTEGRATION
        )
        definition_template["States"]["SQSState"]["Parameters"]["QueueUrl"] = queue_url
        execution_arn = create_and_run_mock(
            target_aws_client=aws_client,
            monkeypatch=monkeypatch,
            mock_config_file=mock_config_file,
            mock_config=MockedServiceIntegrationsLoader.load(
                MockedServiceIntegrationsLoader.MOCK_CONFIG_FILE_LAMBDA_SQS_INTEGRATION
            ),
            state_machine_name="LambdaSQSIntegration",
            definition_template=definition_template,
            execution_input="{}",
            test_name="HybridPath",
        )

        execution_history = aws_client.stepfunctions.get_execution_history(
            executionArn=execution_arn, includeExecutionData=True
        )
        events = execution_history["events"]

        event_4 = events[4]
        assert json.loads(event_4["taskSucceededEventDetails"]["output"]) == {
            "StatusCode": 200,
            "Payload": {"StatusCode": 200, "body": "Hello from Lambda!"},
        }

        event_last = events[-1]
        assert event_last["type"] == "ExecutionSucceeded"
        receive_message_res = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        )
        assert len(receive_message_res["Messages"]) == 1

        sqs_message = receive_message_res["Messages"][0]
        print(sqs_message)
        assert json.loads(sqs_message["Body"]) == {
            "StatusCode": 200,
            "Payload": {"StatusCode": 200, "body": "Hello from Lambda!"},
        }
