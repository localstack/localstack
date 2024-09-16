import json
import threading

import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.services.stepfunctions.asl.eval.count_down_latch import CountDownLatch
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    await_execution_terminated,
    create,
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate as BT
from tests.aws.services.stepfunctions.templates.callbacks.callback_templates import (
    CallbackTemplates as CT,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.templates.timeouts.timeout_templates import (
    TimeoutTemplates as TT,
)
from tests.aws.test_notifications import PUBLICATION_RETRIES, PUBLICATION_TIMEOUT


def _handle_sqs_task_token_with_heartbeats_and_success(aws_client, queue_url) -> None:
    # Handle the state machine task token published in the sqs queue, by submitting 10 heartbeat
    # notifications and a task success notification. Snapshot the response of each call.

    # Read the expected sqs message and extract the body.
    def _get_message_body():
        receive_message_response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1
        )
        return receive_message_response["Messages"][0]["Body"]

    message_body_str = retry(_get_message_body, retries=100, sleep=1)
    message_body = json.loads(message_body_str)

    # Send the heartbeat notifications.
    task_token = message_body["TaskToken"]
    for i in range(10):
        aws_client.stepfunctions.send_task_heartbeat(taskToken=task_token)

    # Send the task success notification.
    aws_client.stepfunctions.send_task_success(taskToken=task_token, output=message_body_str)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestCallback:
    @markers.aws.needs_fixing
    def test_sqs_wait_for_task_token(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sqs_send_task_success_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="<task_token>",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        sqs_send_task_success_state_machine(queue_url)

        template = CT.load_sfn_template(CT.SQS_WAIT_FOR_TASK_TOKEN)
        definition = json.dumps(template)

        message_txt = "test_message_txt"
        exec_input = json.dumps({"QueueUrl": queue_url, "Message": message_txt})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.needs_fixing
    def test_sqs_wait_for_task_token_timeout(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sqs_send_task_success_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="<task_token>",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = CT.load_sfn_template(CT.SQS_WAIT_FOR_TASK_TOKEN_WITH_TIMEOUT)
        definition = json.dumps(template)

        message_txt = "test_message_txt"
        exec_input = json.dumps({"QueueUrl": queue_url, "Message": message_txt})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.needs_fixing
    def test_sqs_failure_in_wait_for_task_token(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sqs_send_task_failure_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="task_token",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        sqs_send_task_failure_state_machine(queue_url)

        template = CT.load_sfn_template(CT.SQS_WAIT_FOR_TASK_TOKEN)
        definition = json.dumps(template)

        message_txt = "test_message_txt"
        exec_input = json.dumps({"QueueUrl": queue_url, "Message": message_txt})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.needs_fixing
    def test_sqs_wait_for_task_tok_with_heartbeat(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sqs_send_heartbeat_and_task_success_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="<task_token>",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        sqs_send_heartbeat_and_task_success_state_machine(queue_url)

        template = CT.load_sfn_template(TT.SERVICE_SQS_SEND_AND_WAIT_FOR_TASK_TOKEN_WITH_HEARTBEAT)
        template["States"]["SendMessageWithWait"]["HeartbeatSeconds"] = 60
        definition = json.dumps(template)

        message_txt = "test_message_txt"
        exec_input = json.dumps({"QueueUrl": queue_url, "Message": message_txt})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_sns_publish_wait_for_task_token(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sqs_receive_num_messages,
        sns_create_topic,
        sns_allow_topic_sqs_queue,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="task_token",
                replace_reference=True,
            )
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sns_api())

        topic_info = sns_create_topic()
        topic_arn = topic_info["TopicArn"]
        queue_url = sqs_create_queue()
        queue_arn = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        aws_client.sns.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
        )
        sns_allow_topic_sqs_queue(queue_url, queue_arn, topic_arn)

        template = CT.load_sfn_template(CT.SNS_PUBLIC_WAIT_FOR_TASK_TOKEN)
        definition = json.dumps(template)

        exec_input = json.dumps({"TopicArn": topic_arn, "body": {"arg1": "Hello", "arg2": "World"}})

        messages = []

        def record_messages_and_send_task_success():
            messages.clear()
            messages.extend(sqs_receive_num_messages(queue_url, expected_messages=1))
            task_token = json.loads(messages[0]["Message"])["TaskToken"]
            aws_client.stepfunctions.send_task_success(taskToken=task_token, output=json.dumps({}))

        threading.Thread(
            target=retry,
            args=(record_messages_and_send_task_success,),
            kwargs={"retries": PUBLICATION_RETRIES, "sleep": PUBLICATION_TIMEOUT},
        ).start()

        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

        sfn_snapshot.match("messages", messages)

    @markers.aws.validated
    def test_start_execution_sync(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
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

        template_target = BT.load_sfn_template(BT.BASE_PASS_RESULT)
        definition_target = json.dumps(template_target)
        state_machine_arn_target = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )

        template = CT.load_sfn_template(CT.SFN_START_EXECUTION_SYNC)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"StateMachineArn": state_machine_arn_target, "Input": None, "Name": "TestStartTarget"}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_start_execution_sync2(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
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

        template_target = BT.load_sfn_template(BT.BASE_PASS_RESULT)
        definition_target = json.dumps(template_target)
        state_machine_arn_target = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )

        template = CT.load_sfn_template(CT.SFN_START_EXECUTION_SYNC2)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"StateMachineArn": state_machine_arn_target, "Input": None, "Name": "TestStartTarget"}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_start_execution_sync_delegate_failure(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
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
                jsonpath="$..cause.StartDate",
                replacement="start-date",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..cause.StopDate",
                replacement="stop-date",
                replace_reference=False,
            )
        )

        template_target = BT.load_sfn_template(BT.BASE_RAISE_FAILURE)
        definition_target = json.dumps(template_target)
        state_machine_arn_target = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )

        template = CT.load_sfn_template(CT.SFN_START_EXECUTION_SYNC)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"StateMachineArn": state_machine_arn_target, "Input": None, "Name": "TestStartTarget"}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_start_execution_sync_delegate_timeout(
        self,
        aws_client,
        create_lambda_function,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
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
                jsonpath="$..cause.StartDate",
                replacement="start-date",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..cause.StopDate",
                replacement="stop-date",
                replace_reference=False,
            )
        )

        function_name = f"lambda_1_func_{short_uid()}"
        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TT.LAMBDA_WAIT_60_SECONDS,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_1_name>"))
        lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]

        template_target = TT.load_sfn_template(TT.LAMBDA_WAIT_WITH_TIMEOUT_SECONDS)
        template_target["States"]["Start"]["Resource"] = lambda_arn
        definition_target = json.dumps(template_target)

        state_machine_arn_target = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )

        template = CT.load_sfn_template(CT.SFN_START_EXECUTION_SYNC)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "StateMachineArn": state_machine_arn_target,
                "Input": {"Payload": None},
                "Name": "TestStartTarget",
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @pytest.mark.skip(reason="Skipped until flaky behaviour can be rectified.")
    def test_multiple_heartbeat_notifications(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="task_token",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs_queue_url"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "sqs_queue_name"))

        task_token_consumer_thread = threading.Thread(
            target=_handle_sqs_task_token_with_heartbeats_and_success, args=(aws_client, queue_url)
        )
        task_token_consumer_thread.start()

        template = CT.load_sfn_template(
            TT.SERVICE_SQS_SEND_AND_WAIT_FOR_TASK_TOKEN_WITH_HEARTBEAT_PATH
        )
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"QueueUrl": queue_url, "Message": "txt", "HeartbeatSecondsPath": 120}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

        task_token_consumer_thread.join(timeout=300)

    @markers.aws.validated
    @pytest.mark.skip(reason="Skipped until flaky behaviour can be rectified.")
    def test_multiple_executions_and_heartbeat_notifications(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="a_task_token",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..MessageId",
                replacement="a_message_id",
                replace_reference=False,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs_queue_url"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "sqs_queue_name"))

        sfn_role_arn = create_iam_role_for_sfn()

        template = CT.load_sfn_template(
            TT.SERVICE_SQS_SEND_AND_WAIT_FOR_TASK_TOKEN_WITH_HEARTBEAT_PATH
        )
        definition = json.dumps(template)

        creation_response = create_state_machine(
            name=f"state_machine_{short_uid()}", definition=definition, roleArn=sfn_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_response, 0))
        state_machine_arn = creation_response["stateMachineArn"]

        exec_input = json.dumps(
            {"QueueUrl": queue_url, "Message": "txt", "HeartbeatSecondsPath": 120}
        )

        # Launch multiple execution of the same state machine.
        execution_count = 6
        execution_arns = list()
        for _ in range(execution_count):
            execution_arn = aws_client.stepfunctions.start_execution(
                stateMachineArn=state_machine_arn, input=exec_input
            )["executionArn"]
            execution_arns.append(execution_arn)

        # Launch one sqs task token handler per each execution, and await for all the terminate handling the task.
        task_token_handler_latch = CountDownLatch(execution_count)

        def _sqs_task_token_handler():
            _handle_sqs_task_token_with_heartbeats_and_success(aws_client, queue_url)
            task_token_handler_latch.count_down()

        for _ in range(execution_count):
            inner_handler_thread = threading.Thread(target=_sqs_task_token_handler, args=())
            inner_handler_thread.start()

        task_token_handler_latch.wait()

        # For each execution, await terminate and record the event executions.
        for i, execution_arn in enumerate(execution_arns):
            await_execution_terminated(
                stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
            )
            execution_history = aws_client.stepfunctions.get_execution_history(
                executionArn=execution_arn
            )
            sfn_snapshot.match(f"execution_history_{i}", execution_history)

    @markers.aws.validated
    def test_sqs_wait_for_task_token_call_chain(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sqs_send_task_success_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..MessageId",
                replacement="message_id",
                replace_reference=True,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="task_token",
                replace_reference=True,
            )
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs_queue_url"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "sqs_queue_name"))

        sqs_send_task_success_state_machine(queue_url)

        template = CT.load_sfn_template(CT.SQS_WAIT_FOR_TASK_TOKEN_CALL_CHAIN)
        definition = json.dumps(template)

        exec_input = json.dumps({"QueueUrl": queue_url, "Message": "HelloWorld"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_sqs_wait_for_task_token_no_token_parameter(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sqs_send_task_success_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs_queue_url"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "sqs_queue_name"))

        template = CT.load_sfn_template(CT.SQS_WAIT_FOR_TASK_TOKEN_NO_TOKEN_PARAMETER)
        definition = json.dumps(template)

        exec_input = json.dumps({"QueueUrl": queue_url})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template",
        [CT.SQS_PARALLEL_WAIT_FOR_TASK_TOKEN, CT.SQS_WAIT_FOR_TASK_TOKEN_CATCH],
        ids=["SQS_PARALLEL_WAIT_FOR_TASK_TOKEN", "SQS_WAIT_FOR_TASK_TOKEN_CATCH"],
    )
    def test_sqs_failure_in_wait_for_task_tok_no_error_field(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sfn_snapshot,
        template,
        request,
    ):
        if (
            not is_aws_cloud()
            and request.node.name
            == "test_sqs_failure_in_wait_for_task_tok_no_error_field[SQS_PARALLEL_WAIT_FOR_TASK_TOKEN]"
        ):
            # TODO: The conditions in which TaskStateAborted error events are logged requires further investigations.
            #  These appear to be logged for Task state workers but only within Parallel states. The behaviour with
            #  other 'Abort' errors should also be investigated.
            pytest.skip("Investigate occurrence logic of 'TaskStateAborted' errors")

        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="task_token",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        def _empty_send_task_failure_on_sqs_message():
            def _get_message_body():
                receive_message_response = aws_client.sqs.receive_message(
                    QueueUrl=queue_url, MaxNumberOfMessages=1
                )
                return receive_message_response["Messages"][0]["Body"]

            message_body_str = retry(_get_message_body, retries=60, sleep=1)
            message_body = json.loads(message_body_str)
            task_token = message_body["TaskToken"]
            aws_client.stepfunctions.send_task_failure(taskToken=task_token)

        thread_send_task_failure = threading.Thread(
            target=_empty_send_task_failure_on_sqs_message,
            args=(),
            name="Thread_empty_send_task_failure_on_sqs_message",
        )
        thread_send_task_failure.daemon = True
        thread_send_task_failure.start()

        template = CT.load_sfn_template(template)
        definition = json.dumps(template)

        exec_input = json.dumps({"QueueUrl": queue_url, "Message": "test_message_txt"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_sync_with_task_token(
        self,
        aws_client,
        sqs_create_queue,
        sqs_send_task_success_state_machine,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        # This tests simulates a sync integration pattern interrupt via a manual
        # SendTaskSuccess command about the task's TaskToken.

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
                jsonpath="$..MessageId",
                replacement="message_id",
                replace_reference=True,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..TaskToken",
                replacement="task_token",
                replace_reference=True,
            )
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())

        # Set up the queue on which the worker sending SendTaskSuccess requests will be listening for
        # TaskToken values to accept.
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "sqs_queue_url"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "sqs_queue_name"))
        # Start the worker which requests SendTaskSuccess about the incoming TaskToken values on the queue.
        sqs_send_task_success_state_machine(queue_url)

        # Create the child state machine, which receives the parent's TaskToken, forwards it to the SendTaskSuccess
        # worker and simulates a long-lasting task by waiting.
        template_target = BT.load_sfn_template(ST.SQS_SEND_MESSAGE_AND_WAIT)
        definition_target = json.dumps(template_target)
        state_machine_arn_target = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )

        # Create the parent state machine, which starts the child state machine with a sync integration pattern.
        template = CT.load_sfn_template(CT.SFN_START_EXECUTION_SYNC_WITH_TASK_TOKEN)
        definition = json.dumps(template)

        # Start the stack and record the behaviour of the parent state machine. The events recorded
        # should show the sync integration pattern about the child state machine being interrupted
        # by the SendTaskSuccess state machine.
        exec_input = json.dumps(
            {
                "StateMachineArn": state_machine_arn_target,
                "Name": "TestStartTarget",
                "QueueUrl": queue_url,
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
