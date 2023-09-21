import aws_cdk as cdk
import pytest

from localstack.testing.pytest import markers


class TestInterDependency:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, infra_provisioner):
        provisioner = infra_provisioner(
            namespace="StackInterDependencyCdkTest", force_template_update=True
        )
        stack1 = cdk.Stack(provisioner.cdk_app, "Stack11")
        stack2 = cdk.Stack(provisioner.cdk_app, "Stack22")
        topic1 = cdk.aws_sns.Topic(stack1, "topic")
        cdk.aws_ssm.StringParameter(stack1, "param", string_value="test")
        topic2 = cdk.aws_sns.Topic(
            stack2, "topic", topic_name=cdk.Fn.join("-", [topic1.topic_name, "suffix"])
        )
        cdk.CfnOutput(stack1, "TopicName", value=topic1.topic_name)
        cdk.CfnOutput(stack2, "TopicName", value=topic2.topic_name)

        with provisioner.provisioner() as prov:
            yield prov

    @markers.aws.validated
    def test_scenario_validate_infra(self, aws_client, infrastructure):
        outputs1 = infrastructure.get_stack_outputs(stack_name="Stack11")
        assert "TopicName" in outputs1
        outputs2 = infrastructure.get_stack_outputs(stack_name="Stack22")
        assert "TopicName" in outputs2

        topic1 = outputs1["TopicName"]
        topic2 = outputs2["TopicName"]

        assert topic2.startswith(topic1)
