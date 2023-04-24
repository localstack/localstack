import json

import pytest

from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.integration.stepfunctions.utils import create_and_record_execution, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@pytest.mark.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestTaskServiceSqs:
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..events..executionSucceededEventDetails.output.SdkHttpMetadata",
            "$..events..executionSucceededEventDetails.output.SdkResponseMetadata",
            "$..events..stateExitedEventDetails.output.SdkHttpMetadata",
            "$..events..stateExitedEventDetails.output.SdkResponseMetadata",
            "$..events..taskSucceededEventDetails.output.SdkHttpMetadata",
            "$..events..taskSucceededEventDetails.output.SdkResponseMetadata",
        ]
    )
    def test_send_message(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))
        snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = ST.load_sfn_template(ST.SQS_SEND_MESSAGE)
        definition = json.dumps(template)

        message_body = "test_message_body"
        exec_input = json.dumps({"QueueUrl": queue_url, "MessageBody": message_body})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )

        receive_message_res = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert len(receive_message_res["Messages"]) == 1
        assert receive_message_res["Messages"][0]["Body"] == message_body
