import os.path

import aws_cdk as cdk
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.aws.api.cloudformation import Stack
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import parse_arn
from localstack.utils.common import short_uid
from localstack.utils.sync import wait_until


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


@markers.aws.validated
@skip_if_legacy_engine()
def test_sns_topic_fifo_without_suffix_fails(cleanups, aws_client, snapshot):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"cs-{short_uid()}"
    topic_name = f"topic-{short_uid()}"

    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"))

    path = os.path.join(
        os.path.dirname(__file__),
        "../../../templates/sns_topic_fifo_dedup.yaml",
    )
    with open(path) as infile:
        template_body = infile.read()

    delay = 1
    max_attempts = 30
    if is_aws_cloud():
        delay = 5
        max_attempts = 100
    waiter_config = {"Delay": delay, "MaxAttempts": max_attempts}

    change_set = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_body,
        ChangeSetType="CREATE",
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": topic_name}],
    )
    change_set_id = change_set["Id"]
    stack_id = change_set["StackId"]
    aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
        ChangeSetName=change_set_id,
        StackName=stack_name,
        WaiterConfig=waiter_config,
    )

    def _cleanup():
        aws_client.cloudformation.delete_stack(StackName=stack_id)
        aws_client.cloudformation.get_waiter("stack_delete_complete").wait(
            StackName=stack_id, WaiterConfig=waiter_config
        )

    cleanups.append(_cleanup)

    aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id, StackName=stack_id)

    # we cannot use a waiter here since they all check for success
    def describe_stack() -> Stack:
        result = aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0]
        return result

    assert wait_until(
        lambda: describe_stack()["StackStatus"] in {"ROLLBACK_COMPLETE", "CREATE_FAILED"},
        strategy="static",
        wait=delay,
        max_retries=max_attempts,
    )

    stack = describe_stack()
    snapshot.match("describe-stack", stack)


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
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Statement..Action",  # TODO: see https://github.com/getmoto/moto/pull/9041
    ]
)
def test_sns_topic_policy_resets_to_default(
    sns_topic, infrastructure_setup, aws_client, snapshot, account_id
):
    """Tests the delete statement of a ``AWS::SNS::TopicPolicy`` resource, which should reset the topic's policy to the
    default policy."""
    # simulate a pre-existing topic
    existing_topic_arn = sns_topic["Attributes"]["TopicArn"]
    existing_topic_name = parse_arn(existing_topic_arn)["resource"]
    snapshot.add_transformer(snapshot.transform.regex(existing_topic_name, "<topic-name>"))

    # create the stack
    stack_name = "SnsTopicPolicyStack"
    infra = infrastructure_setup(namespace="SnsTests")
    # persisting the stack means persisting the existing_topic_arn reference, but that changes every test run
    infra.persist_output = False
    stack = cdk.Stack(infra.cdk_app, stack_name=stack_name)

    # get the existing topic
    topic = cdk.aws_sns.Topic.from_topic_arn(stack, "Topic", existing_topic_arn)

    # add the topic policy resource
    topic_policy = cdk.aws_sns.TopicPolicy(stack, "CustomTopicPolicy", topics=[topic])
    topic_policy.document.add_statements(
        cdk.aws_iam.PolicyStatement(
            effect=cdk.aws_iam.Effect.ALLOW,
            principals=[cdk.aws_iam.AnyPrincipal()],
            actions=["sns:Publish"],
            resources=[topic.topic_arn],
            conditions={"StringEquals": {"aws:SourceAccount": account_id}},
        )
    )

    # snapshot its policy
    default = aws_client.sns.get_topic_attributes(TopicArn=existing_topic_arn)
    snapshot.match("default-topic-attributes", default["Attributes"]["Policy"])

    # deploy the stack
    cdk.CfnOutput(stack, "TopicArn", value=topic.topic_arn)
    with infra.provisioner() as prov:
        assert prov.get_stack_outputs(stack_name=stack_name)["TopicArn"] == existing_topic_arn

        modified = aws_client.sns.get_topic_attributes(TopicArn=existing_topic_arn)
        snapshot.match("modified-topic-attributes", modified["Attributes"]["Policy"])

    # now that it's destroyed, get the topic attributes again
    reverted = aws_client.sns.get_topic_attributes(TopicArn=existing_topic_arn)
    snapshot.match("reverted-topic-attributes", reverted["Attributes"]["Policy"])


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


@markers.aws.validated
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
    snapshot.add_transformer(
        snapshot.transform.key_value(
            "SubscriptionArn", "PendingConfirmation", reference_replacement=False
        ),
    )

    topic_name = f"test-topic-{short_uid()}"

    stack = deploy_cfn_template(
        parameters={
            "TopicName": topic_name,
            "DisplayName": "Initial Display Name",
            "Environment": "test",  # tag
            "Project": "localstack",  # tag
        },
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_update.yaml"
        ),
    )

    topic_arn = stack.outputs["TopicArn"]

    initial_attrs = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
    snapshot.match("initial-topic-attributes", initial_attrs)

    initial_tags = aws_client.sns.list_tags_for_resource(ResourceArn=topic_arn)
    tag_dict = {tag["Key"]: tag["Value"] for tag in initial_tags["Tags"]}
    assert tag_dict["Environment"] == "test"
    assert tag_dict["Project"] == "localstack"

    initial_subscriptions = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
    snapshot.match("initial-subscriptions", initial_subscriptions)

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
    updated_tag_dict = {tag["Key"]: tag["Value"] for tag in updated_tags["Tags"]}
    assert updated_tag_dict["Environment"] == "production"
    assert updated_tag_dict["Project"] == "backend"

    # Subscriptions should be preserved
    new_subscriptions = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
    snapshot.match("new-subscriptions", new_subscriptions)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Attributes.DeliveryPolicy",
        "$..Attributes.EffectiveDeliveryPolicy",
        "$..Attributes.Policy.Statement..Action",
    ]
)
def test_sns_topic_update_name(deploy_cfn_template, aws_client, snapshot):
    """Test updating SNS Topic with TopicName change (requires resource replacement)."""
    snapshot.add_transformer(snapshot.transform.key_value("TopicArn"))
    snapshot.add_transformer(
        snapshot.transform.key_value(
            "SubscriptionArn", "PendingConfirmation", reference_replacement=False
        ),
    )

    initial_topic_name = f"test-topic-{short_uid()}"

    stack = deploy_cfn_template(
        parameters={
            "TopicName": initial_topic_name,
            "DisplayName": "Initial Display Name",
            "Environment": "test",  # tag
            "Project": "localstack",  # tag
        },
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_update.yaml"
        ),
    )

    initial_topic_arn = stack.outputs["TopicArn"]

    initial_attrs = aws_client.sns.get_topic_attributes(TopicArn=initial_topic_arn)
    snapshot.match("initial-topic-attributes", initial_attrs)

    # Store initial tags to verify they are preserved
    initial_tags = aws_client.sns.list_tags_for_resource(ResourceArn=initial_topic_arn)
    initial_tag_dict = {tag["Key"]: tag["Value"] for tag in initial_tags["Tags"]}
    assert initial_tag_dict["Environment"] == "test"
    assert initial_tag_dict["Project"] == "localstack"

    # Get initial subscriptions
    initial_subscriptions = aws_client.sns.list_subscriptions_by_topic(TopicArn=initial_topic_arn)
    snapshot.match("initial-subscriptions", initial_subscriptions)

    new_topic_name = f"test-topic-new-{short_uid()}"

    # Update the stack with new TopicName
    updated_stack = deploy_cfn_template(
        parameters={
            "TopicName": new_topic_name,
            "DisplayName": "Updated Display Name",
            "Environment": "production",  # tag
            "Project": "localstack",  # tag
        },
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_update.yaml"
        ),
        stack_name=stack.stack_name,
        is_update=True,
    )

    new_topic_arn = updated_stack.outputs["TopicArn"]
    assert new_topic_arn != initial_topic_arn  # Confirm topic was replaced

    # Verify new topic state
    new_attrs = aws_client.sns.get_topic_attributes(TopicArn=new_topic_arn)
    snapshot.match("new-topic-attributes", new_attrs)

    # Verify tags were preserved and updated
    new_tags = aws_client.sns.list_tags_for_resource(ResourceArn=new_topic_arn)
    new_tag_dict = {tag["Key"]: tag["Value"] for tag in new_tags["Tags"]}

    # Assert tags were preserved (Project tag should still exist)
    assert "Project" in new_tag_dict
    assert new_tag_dict["Project"] == initial_tag_dict["Project"]  # Should be "localstack"
    # Assert Environment tag was updated
    assert new_tag_dict["Environment"] == "production"

    # Verify subscriptions were preserved
    new_subscriptions = aws_client.sns.list_subscriptions_by_topic(TopicArn=new_topic_arn)
    snapshot.match("new-subscriptions", new_subscriptions)

    # Verify old topic was deleted
    try:
        aws_client.sns.get_topic_attributes(TopicArn=initial_topic_arn)
        raise AssertionError("Old topic should have been deleted")
    except aws_client.sns.exceptions.NotFoundException:
        # Expected - old topic should be deleted
        pass
