import aws_cdk as cdk
import aws_cdk.aws_lambda_event_sources as eventsources
import pytest
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_sqs as sqs
from localstack_ext.services.pipes.senders.sqs_sender import SqsSender

from localstack.testing.aws.lambda_utils import _await_event_source_mapping_enabled
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from tests.aws.services.lambda_.test_lambda_integration_sqs import LAMBDA_SQS_INTEGRATION_FILE

STACK_NAME = "LambdaEventSourceMappingsStack"

# # TODO: consolidate with tests/aws/services/pipes/test_pipes.py and fix this local HACK
# PIPES_FOLDER = Path("/Users/joe/Projects/LocalStack/localstack-ext/tests/aws/services/pipes")
# TEST_LAMBDA_PYTHON_S3_INTEGRATION = os.path.join(PIPES_FOLDER, "functions/target_s3_integration.py")


# Stolen from tests.aws.services.lambda_.test_lambda_integration_sqs._snapshot_transformers
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


class TestEventSourceMappingSqs:
    """Lambda Event Source Mapping test for the scenario: SQS => Lambda using an SQS destination queue for validation"""

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace=STACK_NAME)
        stack = cdk.Stack(infra.cdk_app, STACK_NAME)

        # Source (including IAM, outputs, etc)
        source_queue = sqs.Queue(stack, "SourceQueue")
        cdk.CfnOutput(stack, "SourceArn", value=source_queue.queue_arn)

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
        # TODO: fix CDK token resolving because this throws the error:
        # @jsii/kernel.RuntimeError: Error: SqsEventSource is not yet bound to an event source mapping
        # Now it works magically?!
        cdk.CfnOutput(
            stack,
            "LambdaEventSourceMappingUUID",
            value=event_source.event_source_mapping_id,
        )

        # # ALTERNATIVE: fix permissions when not using the high-level util (which does not yield a return value :upside)
        # event_source_mapping = target_function.add_event_source_mapping(
        #     event_source_arn=source_queue.queue_arn,
        #     id="LambdaEventSourceMapping",
        #     batch_size=1,
        # )
        # cdk.CfnOutput(
        #     stack,
        #     "LambdaEventSourceMappingUUID",
        #     value=event_source_mapping.event_source_mapping_id,
        # )

        # TODO for dev: skip_teardown=True
        with infra.provisioner() as prov:
            yield prov

    @markers.aws.validated
    def test_event_source_mappings_sqs(
        self, aws_client, infrastructure, s3_empty_bucket, cleanups, snapshot
    ):
        outputs = infrastructure.get_stack_outputs(stack_name=STACK_NAME)
        snapshot.add_transformer(
            snapshot.transform.regex(outputs["DestinationQueueUrl"], "<queue-url>")
        )

        # TODO: needed? requires UUID, which is a lazy CDK token failing upon outputting via CF
        _await_event_source_mapping_enabled(
            aws_client.lambda_, outputs["LambdaEventSourceMappingUUID"]
        )

        # Send event to the source
        events_to_send = [
            {
                "message": "event1",
                "destination": outputs["DestinationQueueUrl"],
                "fail_attempts": 0,
            }
        ]
        sqs_sender = SqsSender(outputs["SourceArn"], target_client=aws_client.sqs)
        sqs_sender.send_events(events_to_send)

        # TODO: do we need to wait for ESM to be enabled here to mitigate flakes or does CF does this automatically (at least in AWS)?!

        # Wait for the first invocation result
        first_response = aws_client.sqs.receive_message(
            QueueUrl=outputs["DestinationQueueUrl"], WaitTimeSeconds=15, MaxNumberOfMessages=1
        )
        snapshot.match("first_attempt", first_response)
