import aws_cdk as cdk
import pytest

from localstack.testing.pytest import markers


class TestDemo:

    # fixture
    @pytest.fixture(scope="class")
    def infrastructure(self, infrastructure_setup, aws_client):
        infra = infrastructure_setup(namespace="TestDemo", force_synth=True)

        stack = cdk.Stack(infra.cdk_app, "DemoTest")
        topic = cdk.aws_sns.Topic(stack, "MyTopic")
        cdk.CfnOutput(stack, "TopicArn", value=topic.topic_arn)

        stack2 = cdk.Stack(infra.cdk_app, "DemoTest2")
        topic2 = cdk.aws_sns.Topic(
            stack2,
            "MyTopic",
            topic_name=cdk.Fn.join("-", [topic.topic_name, "demosuffix", stack2.account]),
        )
        cdk.CfnOutput(stack2, "TopicArn", value=topic2.topic_arn)

        with infra.provisioner(skip_deployment=True) as prov:
            yield prov

    # testing
    @markers.aws.validated
    def test_stuff(self, infrastructure, aws_client, snapshot):
        outputs = infrastructure.get_stack_outputs("DemoTest")
        topic_arn = outputs["TopicArn"]
        response = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("topic1_response", response)

        outputs2 = infrastructure.get_stack_outputs("DemoTest2")
        topic_2_arn = outputs2["TopicArn"]
        aws_client.sns.get_topic_attributes(TopicArn=topic_2_arn)
        snapshot.match("topic2_response", response)

        assert topic_2_arn == f"{topic_arn}-demosuffix"
