import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.sqs import MessageSystemAttributeNameForSends
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())

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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())

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

    @markers.aws.validated
    def test_send_message_attributes(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = ST.load_sfn_template(ST.SQS_SEND_MESSAGE_ATTRIBUTES)
        definition = json.dumps(template)

        message_body = "test_message_body"
        message_attr_1 = "Hello"
        message_attr_2 = "World"

        exec_input = json.dumps(
            {
                "QueueUrl": queue_url,
                "Message": message_body,
                "MessageAttributeValue1": message_attr_1,
                "MessageAttributeValue2": message_attr_2,
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

        receive_message_res = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        )
        assert len(receive_message_res["Messages"]) == 1

        sqs_message = receive_message_res["Messages"][0]
        assert sqs_message["Body"] == message_body

        sqs_message_attributes = sqs_message["MessageAttributes"]
        assert len(sqs_message_attributes) == 2

        assert sqs_message_attributes["my_attribute_no_1"]["StringValue"] == message_attr_1
        assert sqs_message_attributes["my_attribute_no_1"]["DataType"] == "String"

        assert sqs_message_attributes["my_attribute_no_2"]["StringValue"] == message_attr_2
        assert sqs_message_attributes["my_attribute_no_2"]["DataType"] == "String"
