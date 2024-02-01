import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.sqs import MessageSystemAttributeNameForSends
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
        # TODO: investigate `cause` construction issues with reported LS's SQS errors.
        "$..cause",
        "$..Cause",
    ]
)
class TestTaskServiceSqs:
    @markers.aws.needs_fixing
    def test_send_message(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = ST.load_sfn_template(ST.SQS_SEND_MESSAGE)
        definition = json.dumps(template)

        message_body = "test_message_body"
        exec_input = json.dumps({"QueueUrl": queue_url, "MessageBody": message_body})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

        receive_message_res = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert len(receive_message_res["Messages"]) == 1
        assert receive_message_res["Messages"][0]["Body"] == message_body

    @markers.aws.needs_fixing
    def test_send_message_unsupported_parameters(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = ST.load_sfn_template(ST.SQS_SEND_MESSAGE)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "QueueUrl": queue_url,
                "MessageBody": "test",
                "MessageSystemAttribute": {
                    MessageSystemAttributeNameForSends.AWSTraceHeader: "test"
                },
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
