import json
import threading

from localstack_snapshot.snapshots import JsonpathTransformer, RegexTransformer

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate as BT
from tests.aws.services.stepfunctions.templates.callbacks.callback_templates import (
    CallbackTemplates as CT,
)
from tests.aws.services.stepfunctions.templates.timeouts.timeout_templates import (
    TimeoutTemplates as TT,
)
from tests.aws.services.stepfunctions.utils import create, create_and_record_execution
from tests.aws.test_notifications import PUBLICATION_RETRIES, PUBLICATION_TIMEOUT


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestCallback:
    @markers.snapshot.skip_snapshot_verify(paths=["$..MD5OfMessageBody"])
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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())
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

    @markers.snapshot.skip_snapshot_verify(paths=["$..MD5OfMessageBody"])
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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())
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

    @markers.snapshot.skip_snapshot_verify(paths=["$..MD5OfMessageBody"])
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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())
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

    @markers.snapshot.skip_snapshot_verify(paths=["$..MD5OfMessageBody"])
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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())
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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())
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
