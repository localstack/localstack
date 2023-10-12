import aws_cdk as cdk
import pytest
from aws_cdk import aws_sqs as sqs

from localstack.testing.pytest import markers


class TestSomethingSimple:
    STACK_NAME = "TestStack"

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, infrastructure_setup):
        infra = infrastructure_setup("VerySimpleSample")

        stack = cdk.Stack(infra.cdk_app, self.STACK_NAME)

        queue = sqs.Queue(stack, "TestQueue")

        cdk.CfnOutput(stack, "QueueName", value=queue.queue_name)
        cdk.CfnOutput(stack, "QueueURL", value=queue.queue_url)

        with infra.provisioner() as prov:
            yield prov

    @markers.aws.validated
    def test_setup(self, infrastructure, aws_client):
        outputs = infrastructure.get_stack_outputs(self.STACK_NAME)
        queue_name = outputs["QueueName"]
        queue_url = outputs["QueueURL"]

        retrieved_url = aws_client.sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
        assert queue_url == retrieved_url
