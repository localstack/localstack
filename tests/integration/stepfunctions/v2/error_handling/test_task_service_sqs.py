import json

import pytest

from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
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
    def test_send_message_no_such_queue(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())

        queue_name = f"queue-{short_uid()}"
        queue_url = f"http://no-such-queue-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(queue_url, "<no_such_sqs_queue_url>"))
        snapshot.add_transformer(RegexTransformer(queue_name, "<sqs_queue_name>"))

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_SQS_SEND_MSG_CATCH)
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
