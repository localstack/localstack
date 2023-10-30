import json

import pytest

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


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
    def test_publish_message_attributes(
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

        template = ST.load_sfn_template(ST.SNS_PUBLISH_MESSAGE_ATTRIBUTES)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "TopicArn": topic_arn,
                "Message": "HelloWorld!",
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
