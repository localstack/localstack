import os.path

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@markers.aws.validated
def test_sns_topic_fifo_with_deduplication(deploy_cfn_template, aws_client):
    topic_name = f"topic-{short_uid()}.fifo"

    deploy_cfn_template(
        parameters={"TopicName": topic_name},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_fifo_dedup.yaml"
        ),
    )

    topics = aws_client.sns.list_topics()["Topics"]
    topic_arns = [t["TopicArn"] for t in topics]

    assert len([t for t in topic_arns if topic_name in t]) == 1


@markers.aws.needs_fixing
def test_sns_topic_fifo_without_suffix_fails(deploy_cfn_template, aws_client):
    stack_name = f"stack-{short_uid()}"
    topic_name = f"topic-{short_uid()}"
    path = os.path.join(
        os.path.dirname(__file__),
        "../../../templates/sns_topic_fifo_dedup.yaml",
    )

    with pytest.raises(Exception) as ex:
        deploy_cfn_template(
            stack_name=stack_name, template_path=path, parameters={"TopicName": topic_name}
        )
    assert ex.typename == "StackDeployError"

    stack = aws_client.cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
    if is_aws_cloud():
        assert stack.get("StackStatus") in ["ROLLBACK_COMPLETED", "ROLLBACK_IN_PROGRESS"]
    else:
        assert stack.get("StackStatus") == "CREATE_FAILED"


@markers.aws.validated
def test_sns_subscription(deploy_cfn_template, aws_client):
    topic_name = f"topic-{short_uid()}"
    queue_name = f"topic-{short_uid()}"
    stack = deploy_cfn_template(
        parameters={"TopicName": topic_name, "QueueName": queue_name},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_subscription.yaml"
        ),
    )

    topic_arn = stack.outputs["TopicArnOutput"]
    assert topic_arn is not None

    subscriptions = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
    assert len(subscriptions["Subscriptions"]) > 0


@markers.aws.validated
def test_deploy_stack_with_sns_topic(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/deploy_template_2.yaml"
        ),
        parameters={"CompanyName": "MyCompany", "MyEmail1": "my@email.com"},
    )
    assert len(stack.outputs) == 3

    topic_arn = stack.outputs["MyTopic"]
    rs = aws_client.sns.list_topics()

    # Topic resource created
    topics = [tp for tp in rs["Topics"] if tp["TopicArn"] == topic_arn]
    assert len(topics) == 1

    stack.destroy()

    # assert topic resource removed
    rs = aws_client.sns.list_topics()
    topics = [tp for tp in rs["Topics"] if tp["TopicArn"] == topic_arn]
    assert not topics
