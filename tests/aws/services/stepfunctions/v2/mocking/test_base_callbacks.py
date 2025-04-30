import json

import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack import config
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
    create_and_record_mocked_execution,
    create_state_machine_with_iam_role,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.mocked_service_integrations.mocked_service_integrations import (
    MockedServiceIntegrationsLoader,
)
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.templates.callbacks.callback_templates import (
    CallbackTemplates,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
        "$..ExecutedVersion",
        "$..RedriveCount",
        "$..redriveCount",
        "$..RedriveStatus",
        "$..redriveStatus",
        "$..RedriveStatusReason",
        "$..redriveStatusReason",
        # In an effort to comply with SFN Local's lack of handling of sync operations,
        # we are unable to produce valid TaskSubmittedEventDetails output field, which
        # must include the provided mocked response in the output:
        "$..events..taskSubmittedEventDetails.output",
    ]
)
class TestBaseScenarios:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_file_path, mocked_response_filepath",
        [
            (
                CallbackTemplates.SFN_START_EXECUTION_SYNC,
                MockedServiceIntegrationsLoader.MOCKED_RESPONSE_STATES_200_START_EXECUTION_SYNC,
            ),
            (
                CallbackTemplates.SFN_START_EXECUTION_SYNC2,
                MockedServiceIntegrationsLoader.MOCKED_RESPONSE_STATES_200_START_EXECUTION_SYNC2,
            ),
        ],
        ids=["SFN_SYNC", "SFN_SYNC2"],
    )
    def test_sfn_start_execution_sync(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        monkeypatch,
        mock_config_file,
        sfn_snapshot,
        template_file_path,
        mocked_response_filepath,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output.StartDate",
                replacement="start-date",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output.StopDate",
                replacement="stop-date",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..StateMachineArn",
                replacement="state-machine-arn",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..ExecutionArn",
                replacement="execution-arn",
                replace_reference=False,
            )
        )

        template = CallbackTemplates.load_sfn_template(template_file_path)
        definition = json.dumps(template)

        if is_aws_cloud():
            template_target = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
            definition_target = json.dumps(template_target)
            state_machine_arn_target = create_state_machine_with_iam_role(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition_target,
            )

            exec_input = json.dumps(
                {
                    "StateMachineArn": state_machine_arn_target,
                    "Input": None,
                    "Name": "TestStartTarget",
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
        else:
            state_machine_name = f"mocked_state_machine_{short_uid()}"
            test_name = "TestCaseName"
            mocked_response = MockedServiceIntegrationsLoader.load(mocked_response_filepath)
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"StartExecution": "mocked_response"}}
                    }
                },
                "MockedResponses": {"mocked_response": mocked_response},
            }
            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
            exec_input = json.dumps(
                {"StateMachineArn": "state-machine-arn", "Input": None, "Name": "TestStartTarget"}
            )
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
    def test_sqs_wait_for_task_token(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sqs_create_queue,
        sqs_send_task_success_state_machine,
        sfn_snapshot,
        mock_config_file,
        monkeypatch,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="task_token",
                replace_reference=True,
            )
        )

        template = CallbackTemplates.load_sfn_template(CallbackTemplates.SQS_WAIT_FOR_TASK_TOKEN)
        definition = json.dumps(template)
        message = "string-literal"

        if is_aws_cloud():
            queue_name = f"queue-{short_uid()}"
            queue_url = sqs_create_queue(QueueName=queue_name)
            sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs_queue_url"))
            sqs_send_task_success_state_machine(queue_url)

            exec_input = json.dumps({"QueueUrl": queue_url, "Message": message})
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
            task_success = MockedServiceIntegrationsLoader.load(
                MockedServiceIntegrationsLoader.MOCKED_RESPONSE_CALLBACK_TASK_SUCCESS_STRING_LITERAL
            )
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"SendMessageWithWait": "task_success"}}
                    }
                },
                "MockedResponses": {"task_success": task_success},
            }
            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
            exec_input = json.dumps({"QueueUrl": "sqs_queue_url", "Message": message})
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: skipping events validation because in mock‐failure mode the
            # TaskSubmitted event is never emitted; this causes the events sequence
            # to be shifted by one. Nevertheless, the evaluation of the state machine
            # is still successful.
            "$..events"
        ]
    )
    def test_sqs_wait_for_task_token_task_failure(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sqs_create_queue,
        sqs_send_task_failure_state_machine,
        sfn_snapshot,
        mock_config_file,
        monkeypatch,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="task_token",
                replace_reference=True,
            )
        )

        template = CallbackTemplates.load_sfn_template(
            CallbackTemplates.SQS_WAIT_FOR_TASK_TOKEN_CATCH
        )
        definition = json.dumps(template)
        message = "string-literal"

        if is_aws_cloud():
            queue_name = f"queue-{short_uid()}"
            queue_url = sqs_create_queue(QueueName=queue_name)
            sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs_queue_url"))
            sqs_send_task_failure_state_machine(queue_url)

            exec_input = json.dumps({"QueueUrl": queue_url, "Message": message})
            execution_arn = create_and_record_execution(
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
            task_failure = MockedServiceIntegrationsLoader.load(
                MockedServiceIntegrationsLoader.MOCKED_RESPONSE_CALLBACK_TASK_FAILURE
            )
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"SendMessageWithWait": "task_failure"}}
                    }
                },
                "MockedResponses": {"task_failure": task_failure},
            }
            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
            exec_input = json.dumps({"QueueUrl": "sqs_queue_url", "Message": message})
            execution_arn = create_and_record_mocked_execution(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition,
                exec_input,
                state_machine_name,
                test_name,
            )

        describe_execution_response = aws_client.stepfunctions.describe_execution(
            executionArn=execution_arn
        )
        sfn_snapshot.match("describe_execution_response", describe_execution_response)
