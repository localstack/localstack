import json

from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.timeouts.timeout_templates import (
    TimeoutTemplates as TT,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestHeartbeats:
    @markers.aws.validated
    def test_heartbeat_timeout(
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
                replacement="task_token",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = TT.load_sfn_template(TT.SERVICE_SQS_SEND_AND_WAIT_FOR_TASK_TOKEN_WITH_HEARTBEAT)
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
    def test_heartbeat_path_timeout(
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
                replacement="task_token",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = TT.load_sfn_template(
            TT.SERVICE_SQS_SEND_AND_WAIT_FOR_TASK_TOKEN_WITH_HEARTBEAT_PATH
        )
        definition = json.dumps(template)

        message_txt = "test_message_txt"
        exec_input = json.dumps(
            {"QueueUrl": queue_url, "Message": message_txt, "HeartbeatSecondsPath": 5}
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
    def test_heartbeat_no_timeout(
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
                replacement="task_token",
                replace_reference=True,
            )
        )

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = TT.load_sfn_template(TT.SERVICE_SQS_SEND_AND_WAIT_FOR_TASK_TOKEN_WITH_HEARTBEAT)
        del template["States"]["SendMessageWithWait"]["TimeoutSeconds"]
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
