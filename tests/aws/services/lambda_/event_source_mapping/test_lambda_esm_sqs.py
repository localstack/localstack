import json

import aws_cdk as cdk
import aws_cdk.aws_lambda_event_sources as eventsources
import pytest
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_sqs as sqs

from aws.services.lambda_.event_source_mapping.test_lambda_integration_sqs import (
    LAMBDA_SQS_INTEGRATION_FILE,
)
from localstack.testing.aws.lambda_utils import _await_event_source_mapping_enabled
from localstack.testing.pytest import markers
from localstack.utils.files import load_file

STACK_NAME = "LambdaEventSourceMappingSqsStack"


# Taken from tests.aws.services.lambda_.test_lambda_integration_sqs._snapshot_transformers
@pytest.fixture(autouse=True)
def _snapshot_transformers(snapshot):
    # manual transformers since we are passing SQS attributes through lambdas and back again
    snapshot.add_transformer(snapshot.transform.key_value("QueueUrl"))
    snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
    snapshot.add_transformer(snapshot.transform.key_value("SenderId", reference_replacement=False))
    snapshot.add_transformer(snapshot.transform.key_value("SequenceNumber"))
    snapshot.add_transformer(snapshot.transform.resource_name())
    # body contains dynamic attributes so md5 hash changes
    snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
    # lower-case for when messages are rendered in lambdas
    snapshot.add_transformer(snapshot.transform.key_value("receiptHandle"))
    snapshot.add_transformer(snapshot.transform.key_value("md5OfBody"))


class TestLambdaEsmSqs:
    """Lambda Event Source Mapping test for the scenario: SQS => Lambda using an SQS destination queue for validation"""

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace=STACK_NAME)
        stack = cdk.Stack(infra.cdk_app, STACK_NAME)

        # Source (including IAM, outputs, etc)
        source_queue = sqs.Queue(stack, "SourceQueue")
        cdk.CfnOutput(stack, "SourceQueueUrl", value=source_queue.queue_url)

        destination_queue = sqs.Queue(stack, "DestinationQueue")
        cdk.CfnOutput(stack, "DestinationQueueUrl", value=destination_queue.queue_url)

        target_function = lambda_.Function(
            stack,
            "TargetFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            code=lambda_.InlineCode(code=load_file(LAMBDA_SQS_INTEGRATION_FILE)),
            handler="index.handler",
        )
        destination_queue.grant_send_messages(target_function)

        # Event Source Mapping:
        # https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_lambda.EventSourceMapping.html
        # > The SqsEventSource class will automatically create the mapping, and will also modify the Lambda's
        # > execution role so it can consume messages from the queue.
        event_source = eventsources.SqsEventSource(source_queue, batch_size=1)
        target_function.add_event_source(event_source)
        cdk.CfnOutput(
            stack,
            "LambdaEventSourceMappingUUID",
            value=event_source.event_source_mapping_id,
        )

        # TODO for dev: skip_teardown=True
        with infra.provisioner() as prov:
            yield prov

    @markers.aws.validated
    def test_lambda_event_source_mapping_sqs(
        self, aws_client, infrastructure, s3_empty_bucket, cleanups, snapshot
    ):
        outputs = infrastructure.get_stack_outputs(stack_name=STACK_NAME)
        snapshot.add_transformer(
            snapshot.transform.regex(outputs["DestinationQueueUrl"], "<queue-url>")
        )

        # TODO: needed? requires UUID, which is a lazy CDK token failing upon outputting via CF
        # TODO: Do we really need to wait for ESM to be enabled here to mitigate flakes or does CloudFormation does this automatically? at least in AWS?
        _await_event_source_mapping_enabled(
            aws_client.lambda_, outputs["LambdaEventSourceMappingUUID"]
        )

        # Send event to the source
        event = {
            "message": "event1",
            "destination": outputs["DestinationQueueUrl"],
            "fail_attempts": 0,
        }
        aws_client.sqs.send_message(
            QueueUrl=outputs["SourceQueueUrl"],
            MessageBody=json.dumps(event),
        )

        # Wait for the first invocation result
        first_response = aws_client.sqs.receive_message(
            QueueUrl=outputs["DestinationQueueUrl"], WaitTimeSeconds=15, MaxNumberOfMessages=1
        )
        snapshot.match("first_attempt", first_response)
