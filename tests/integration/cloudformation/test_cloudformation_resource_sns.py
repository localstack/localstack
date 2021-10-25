import jinja2

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_sns_topic_fifo_with_deduplication(
    cfn_client,
    sns_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    topic_name = f"topic-{short_uid()}.fifo"
    template_rendered = jinja2.Template(load_template_raw("sns_topic_fifo_dedup.yaml")).render(
        sns_topic=topic_name
    )

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        topics = sns_client.list_topics()["Topics"]
        topic_arns = [t["TopicArn"] for t in topics]

        assert len([t for t in topic_arns if topic_name in t]) == 1

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


def test_sns_topic_fifo_without_suffix_fails(
    cfn_client,
    sns_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    """topic name needs .fifo suffix to be valid"""
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    topic_name = f"topic-{short_uid()}"
    template_rendered = jinja2.Template(load_template_raw("sns_topic_fifo_dedup.yaml")).render(
        sns_topic=topic_name
    )

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        stack = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
        assert stack.get("StackStatus") == "CREATE_FAILED"  # TODO: might be different on AWS, check
    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


def test_sns_subscription(
    cfn_client,
    sns_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    topic_name = f"topic-{short_uid()}"
    queue_name = f"topic-{short_uid()}"
    template_rendered = jinja2.Template(load_template_raw("sns_topic_subscription.yaml")).render(
        topic_name=topic_name, queue_name=queue_name
    )
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        outputs = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
        assert len(outputs) == 1 and outputs[0]["OutputKey"] == "TopicArnOutput"
        topic_arn = outputs[0]["OutputValue"]
        assert topic_arn is not None

        subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        assert len(subscriptions["Subscriptions"]) > 0

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
