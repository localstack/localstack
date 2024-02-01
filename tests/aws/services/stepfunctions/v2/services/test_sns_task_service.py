import json
import threading

import pytest

from localstack.testing.pytest import markers
from localstack.utils.sync import retry
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution
from tests.aws.test_notifications import PUBLICATION_RETRIES, PUBLICATION_TIMEOUT


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestTaskServiceSns:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "message", ["HelloWorld", {"message": "HelloWorld"}, 1, True, None, ""]
    )
    def test_publish_base(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sns_create_topic,
        sfn_snapshot,
        message,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())

        sns_topic = sns_create_topic()
        topic_arn = sns_topic["TopicArn"]

        template = ST.load_sfn_template(ST.SNS_PUBLISH)
        definition = json.dumps(template)

        exec_input = json.dumps({"TopicArn": topic_arn, "Message": {"Message": "HelloWorld!"}})
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
        "message_value", ["HelloWorld", json.dumps("HelloWorld"), json.dumps({}), {}]
    )
    def test_publish_message_attributes(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sqs_receive_num_messages,
        sns_create_topic,
        sns_allow_topic_sqs_queue,
        sfn_snapshot,
        message_value,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sns_api())
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())

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

        template = ST.load_sfn_template(ST.SNS_PUBLISH_MESSAGE_ATTRIBUTES)
        definition = json.dumps(template)

        messages = []

        def record_messages():
            messages.clear()
            messages.extend(sqs_receive_num_messages(queue_url, expected_messages=1))

        threading.Thread(
            target=retry,
            args=(record_messages,),
            kwargs={"retries": PUBLICATION_RETRIES, "sleep": PUBLICATION_TIMEOUT},
        ).start()

        exec_input = json.dumps(
            {
                "TopicArn": topic_arn,
                "Message": message_value,
                "MessageAttributeValue1": "Hello",
                "MessageAttributeValue2": "World!",
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

        sfn_snapshot.match("messages", messages)

    @markers.aws.validated
    def test_publish_base_error_topic_arn(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sns_create_topic,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())

        sns_topic = sns_create_topic()
        topic_arn = sns_topic["TopicArn"]
        aws_client.sns.delete_topic(TopicArn=topic_arn)

        template = ST.load_sfn_template(ST.SNS_PUBLISH)
        definition = json.dumps(template)

        exec_input = json.dumps({"TopicArn": topic_arn, "Message": {"Message": "HelloWorld!"}})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
