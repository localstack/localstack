import os.path

import aws_cdk as cdk
import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Attributes.DeliveryPolicy",
        "$..Attributes.EffectiveDeliveryPolicy",
        "$..Attributes.Policy.Statement..Action",  # SNS:Receive is added by moto but not returned in AWS
    ]
)
def test_sns_topic_fifo_with_deduplication(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.key_value("TopicArn"))
    topic_name = f"topic-{short_uid()}.fifo"

    deploy_cfn_template(
        parameters={"TopicName": topic_name},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_fifo_dedup.yaml"
        ),
    )

    topics = aws_client.sns.list_topics()["Topics"]
    topic_arns = [t["TopicArn"] for t in topics]

    filtered_topics = [t for t in topic_arns if topic_name in t]
    assert len(filtered_topics) == 1

    # assert that the topic is properly created as Fifo
    topic_attrs = aws_client.sns.get_topic_attributes(TopicArn=filtered_topics[0])
    snapshot.match("get-topic-attrs", topic_attrs)


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


@markers.aws.validated
def test_update_subscription(snapshot, deploy_cfn_template, aws_client, sqs_queue, sns_topic):
    topic_arn = sns_topic["Attributes"]["TopicArn"]
    queue_url = sqs_queue
    queue_arn = aws_client.sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    stack = deploy_cfn_template(
        parameters={"TopicArn": topic_arn, "QueueArn": queue_arn},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_subscription.yml"
        ),
    )
    sub_arn = stack.outputs["SubscriptionArn"]
    subscription = aws_client.sns.get_subscription_attributes(SubscriptionArn=sub_arn)
    snapshot.match("subscription-1", subscription)

    deploy_cfn_template(
        parameters={"TopicArn": topic_arn, "QueueArn": queue_arn},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_subscription_update.yml"
        ),
        stack_name=stack.stack_name,
        is_update=True,
    )
    subscription_updated = aws_client.sns.get_subscription_attributes(SubscriptionArn=sub_arn)
    snapshot.match("subscription-2", subscription_updated)
    snapshot.add_transformer(snapshot.transform.cloudformation_api())


@markers.aws.validated
def test_sns_topic_with_attributes(infrastructure_setup, aws_client, snapshot):
    infra = infrastructure_setup(namespace="SnsTests")
    stack_name = f"stack-{short_uid()}"
    stack = cdk.Stack(infra.cdk_app, stack_name=stack_name)

    # Add more configurations here conform they are needed to be tested
    topic = cdk.aws_sns.Topic(stack, id="Topic", fifo=True, message_retention_period_in_days=30)

    cdk.CfnOutput(stack, "TopicArn", value=topic.topic_arn)
    with infra.provisioner() as prov:
        outputs = prov.get_stack_outputs(stack_name=stack_name)
        response = aws_client.sns.get_topic_attributes(
            TopicArn=outputs["TopicArn"],
        )
        snapshot.match("topic-archive-policy", response["Attributes"]["ArchivePolicy"])


@markers.aws.validated
def test_sns_subscription_region(
    snapshot,
    deploy_cfn_template,
    aws_client,
    sqs_queue,
    aws_client_factory,
    region_name,
    secondary_region_name,
    cleanups,
):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.regex(secondary_region_name, "<region2>"))
    topic_name = f"topic-{short_uid()}"
    # we create a topic in a secondary region, different from the stack
    sns_client = aws_client_factory(region_name=secondary_region_name).sns
    topic_arn = sns_client.create_topic(Name=topic_name)["TopicArn"]
    cleanups.append(lambda: sns_client.delete_topic(TopicArn=topic_arn))

    queue_url = sqs_queue
    queue_arn = aws_client.sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    # we want to deploy the Stack in a different region than the Topic, to see how CloudFormation properly does the
    # `Subscribe` call in the `Region` parameter of the Subscription resource
    stack = deploy_cfn_template(
        parameters={
            "TopicArn": topic_arn,
            "QueueArn": queue_arn,
            "TopicRegion": secondary_region_name,
        },
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_subscription_cross_region.yml"
        ),
    )
    sub_arn = stack.outputs["SubscriptionArn"]
    subscription = sns_client.get_subscription_attributes(SubscriptionArn=sub_arn)
    snapshot.match("subscription-1", subscription)


@markers.aws.unknown
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Attributes.DeliveryPolicy",
        "$..Attributes.EffectiveDeliveryPolicy",
        "$..Attributes.Policy.Statement..Action",  # SNS:Receive is added by moto but not returned in AWS
    ]
)
def test_sns_topic_update_attributes(deploy_cfn_template, aws_client, snapshot):
    """Test updating SNS Topic DisplayName and Tags."""
    snapshot.add_transformer(snapshot.transform.key_value("TopicArn"))
    topic_name = f"test-topic-{short_uid()}"

    stack = deploy_cfn_template(
        parameters={"TopicName": topic_name},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_update.yaml"
        ),
    )

    topic_arn = stack.outputs["TopicArn"]

    initial_attrs = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
    snapshot.match("initial-topic-attributes", initial_attrs)
    assert initial_attrs["Attributes"]["DisplayName"] == "Initial Display Name"

    initial_tags = aws_client.sns.list_tags_for_resource(ResourceArn=topic_arn)
    snapshot.match("initial-topic-tags", initial_tags)

    tag_dict = {tag["Key"]: tag["Value"] for tag in initial_tags["Tags"]}
    assert tag_dict["Environment"] == "test"
    assert tag_dict["Project"] == "localstack"

    deploy_cfn_template(
        parameters={
            "TopicName": topic_name,
            "DisplayName": "Updated Display Name",
            "Environment": "production",  # tag
            "Project": "backend",  # tag
        },
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_update.yaml"
        ),
        stack_name=stack.stack_name,
        is_update=True,
    )

    updated_attrs = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
    snapshot.match("updated-topic-attributes", updated_attrs)

    updated_tags = aws_client.sns.list_tags_for_resource(ResourceArn=topic_arn)
    snapshot.match("updated-topic-tags", updated_tags)

    assert updated_attrs["Attributes"]["DisplayName"] == "Updated Display Name"

    updated_tag_dict = {tag["Key"]: tag["Value"] for tag in updated_tags["Tags"]}
    assert updated_tag_dict["Environment"] == "production"
    assert updated_tag_dict["Project"] == "backend"


@markers.aws.unknown
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Attributes.DeliveryPolicy",
        "$..Attributes.EffectiveDeliveryPolicy",
        "$..Attributes.Policy.Statement..Action",
        "$..Subscriptions..SubscriptionArn",
    ]
)
def test_sns_topic_update_name(deploy_cfn_template, aws_client, snapshot):
    """Test updating SNS Topic with TopicName change (requires resource replacement)."""
    snapshot.add_transformer(snapshot.transform.key_value("TopicArn"))
    initial_topic_name = f"test-topic-{short_uid()}"

    stack = deploy_cfn_template(
        parameters={"TopicName": initial_topic_name},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_update.yaml"
        ),
    )

    initial_topic_arn = stack.outputs["TopicArn"]

    initial_attrs = aws_client.sns.get_topic_attributes(TopicArn=initial_topic_arn)
    snapshot.match("initial-topic-attributes", initial_attrs)
    assert initial_attrs["Attributes"]["DisplayName"] == "Initial Display Name"

    # Store initial tags to verify they are preserved
    initial_tags = aws_client.sns.list_tags_for_resource(ResourceArn=initial_topic_arn)
    snapshot.match("initial-topic-tags", initial_tags)
    initial_tag_dict = {tag["Key"]: tag["Value"] for tag in initial_tags["Tags"]}

    # Subscribe to the topic to test subscription preservation
    aws_client.sns.subscribe(
        TopicArn=initial_topic_arn, Protocol="email", Endpoint="test@example.com"
    )

    # Get initial subscriptions
    initial_subscriptions = aws_client.sns.list_subscriptions_by_topic(TopicArn=initial_topic_arn)
    snapshot.match("initial-subscriptions", initial_subscriptions)

    new_topic_name = f"test-topic-new-{short_uid()}"

    # Update the stack with new TopicName
    deploy_cfn_template(
        parameters={
            "TopicName": new_topic_name,
            "DisplayName": "Updated Display Name",
            "Environment": "production",
        },
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_update.yaml"
        ),
        stack_name=stack.stack_name,
        is_update=True,
    )

    # Build the expected new ARN using the format: arn:aws:sns:REGION:ACCOUNT_ID:TOPIC_NAME
    arn_parts = initial_topic_arn.split(":")
    region = arn_parts[3]
    account_id = arn_parts[4]
    new_topic_arn = f"arn:aws:sns:{region}:{account_id}:{new_topic_name}"

    assert new_topic_arn is not None
    assert new_topic_arn != initial_topic_arn  # Confirm topic was replaced

    # Verify new topic state
    new_attrs = aws_client.sns.get_topic_attributes(TopicArn=new_topic_arn)
    snapshot.match("new-topic-attributes", new_attrs)
    assert new_attrs["Attributes"]["DisplayName"] == "Updated Display Name"

    # Verify tags were preserved and updated
    new_tags = aws_client.sns.list_tags_for_resource(ResourceArn=new_topic_arn)
    snapshot.match("new-topic-tags", new_tags)
    new_tag_dict = {tag["Key"]: tag["Value"] for tag in new_tags["Tags"]}

    # Assert tags were preserved (Project tag should still exist)
    assert "Project" in new_tag_dict
    assert new_tag_dict["Project"] == initial_tag_dict["Project"]  # Should be "localstack"

    # Assert Environment tag was updated
    assert new_tag_dict["Environment"] == "production"

    # Verify subscriptions were preserved
    new_subscriptions = aws_client.sns.list_subscriptions_by_topic(TopicArn=new_topic_arn)
    snapshot.match("new-subscriptions", new_subscriptions)

    # Assert subscription was preserved with same endpoint and protocol
    assert len(new_subscriptions["Subscriptions"]) == 1
    new_subscription = new_subscriptions["Subscriptions"][0]
    assert new_subscription["Protocol"] == "email"
    assert new_subscription["Endpoint"] == "test@example.com"
    assert new_subscription["TopicArn"] == new_topic_arn

    # Verify old topic was deleted
    try:
        aws_client.sns.get_topic_attributes(TopicArn=initial_topic_arn)
        raise AssertionError("Old topic should have been deleted")
    except aws_client.sns.exceptions.NotFoundException:
        # Expected - old topic should be deleted
        pass
