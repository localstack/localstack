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

    @markers.aws.validated
    def test_sqs_send_message(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        create_lambda_function,
        sqs_create_queue,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())

        template = ServicesTemplates.load_sfn_template(ServicesTemplates.SQS_SEND_MESSAGE)
        definition = json.dumps(template)
        message_body = "test_message_body"

        if is_aws_cloud():
            queue_name = f"queue-{short_uid()}"
            queue_url = sqs_create_queue(QueueName=queue_name)
            sfn_snapshot.add_transformer(RegexTransformer(queue_name, "sqs-queue-name"))
            sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs-queue-url"))

            exec_input = json.dumps({"QueueUrl": queue_url, "MessageBody": message_body})
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
            sqs_200_send_message = MockedResponseLoader.load(
                MockedResponseLoader.SQS_200_SEND_MESSAGE
            )
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"SendSQS": "sqs_200_send_message"}}
                    }
                },
                "MockedResponses": {"sqs_200_send_message": sqs_200_send_message},
            }
            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
            exec_input = json.dumps({"QueueUrl": "sqs-queue-url", "MessageBody": message_body})
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

    @markers.aws.validated
    def test_sns_publish_base(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sns_create_topic,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        template = ServicesTemplates.load_sfn_template(ServicesTemplates.SNS_PUBLISH)
        definition = json.dumps(template)
        message_body = {"message": "string-literal"}

        if is_aws_cloud():
            topic = sns_create_topic()
            topic_arn = topic["TopicArn"]
            sfn_snapshot.add_transformer(RegexTransformer(topic_arn, "topic-arn"))
            exec_input = json.dumps({"TopicArn": topic_arn, "Message": message_body})
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
            sns_200_publish = MockedResponseLoader.load(MockedResponseLoader.SNS_200_PUBLISH)
            mock_config = {
                "StateMachines": {
                    state_machine_name: {"TestCases": {test_name: {"Publish": "sns_200_publish"}}}
                },
                "MockedResponses": {"sns_200_publish": sns_200_publish},
            }
            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
            exec_input = json.dumps({"TopicArn": "topic-arn", "Message": message_body})
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

    @markers.aws.validated
    def test_events_put_events(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        events_to_sqs_queue,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        detail_type = f"detail_type_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(detail_type, "detail-type"))
        entries = [
            {
                "Detail": json.dumps({"Message": "string-literal"}),
                "DetailType": detail_type,
                "Source": "some.source",
            }
        ]

        template = ServicesTemplates.load_sfn_template(ServicesTemplates.EVENTS_PUT_EVENTS)
        definition = json.dumps(template)

        exec_input = json.dumps({"Entries": entries})

        if is_aws_cloud():
            event_pattern = {"detail-type": [detail_type]}
            queue_url = events_to_sqs_queue(event_pattern)
            sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs_queue_url"))
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
            events_200_put_events = MockedResponseLoader.load(
                MockedResponseLoader.EVENTS_200_PUT_EVENTS
            )
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"PutEvents": "events_200_put_events"}}
                    }
                },
                "MockedResponses": {"events_200_put_events": events_200_put_events},
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

    @markers.aws.validated
    def test_dynamodb_put_get_item(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        events_to_sqs_queue,
        dynamodb_create_table,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        template = ServicesTemplates.load_sfn_template(ServicesTemplates.DYNAMODB_PUT_GET_ITEM)
        definition = json.dumps(template)

        table_name = f"sfn_test_table_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(table_name, "table-name"))
        exec_input = json.dumps(
            {
                "TableName": table_name,
                "Item": {"data": {"S": "string-literal"}, "id": {"S": "id1"}},
                "Key": {"id": {"S": "id1"}},
            }
        )

        if is_aws_cloud():
            dynamodb_create_table(
                table_name=table_name, partition_key="id", client=aws_client.dynamodb
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
            dynamodb_200_put_item = MockedResponseLoader.load(
                MockedResponseLoader.DYNAMODB_200_PUT_ITEM
            )
            dynamodb_200_get_item = MockedResponseLoader.load(
                MockedResponseLoader.DYNAMODB_200_GET_ITEM
            )
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {
                            test_name: {
                                "PutItem": "dynamodb_200_put_item",
                                "GetItem": "dynamodb_200_get_item",
                            }
                        }
                    }
                },
                "MockedResponses": {
                    "dynamodb_200_put_item": dynamodb_200_put_item,
                    "dynamodb_200_get_item": dynamodb_200_get_item,
                },
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
