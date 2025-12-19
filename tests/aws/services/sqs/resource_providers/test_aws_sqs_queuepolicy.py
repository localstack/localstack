import os

from localstack.testing.pytest import markers


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    """
    Helper function to deploy a CloudFormation stack using a template file. This exists to reduce
    boilerplate in the test cases.
    """
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_sqs_queue_policy(deploy_cfn_template, aws_client, snapshot):
    result = deploy_stack(deploy_cfn_template, "sqs_with_queuepolicy.yml")
    queue_url = result.outputs["Queue1Url"]

    snapshot.match(
        "policy", aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    )
    snapshot.add_transformer(snapshot.transform.key_value("Resource"))


@markers.aws.validated
def test_update_sqs_queuepolicy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_with_queuepolicy.yml")
    policy = aws_client.sqs.get_queue_attributes(
        QueueUrl=stack.outputs["Queue1Url"], AttributeNames=["Policy"]
    )
    snapshot.match("policy1", policy["Attributes"]["Policy"])

    updated_stack = deploy_stack(
        deploy_cfn_template,
        "sqs_with_queuepolicy_updated.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    policy = aws_client.sqs.get_queue_attributes(
        QueueUrl=updated_stack.outputs["Queue1Url"], AttributeNames=["Policy"]
    )

    snapshot.match("policy2", policy["Attributes"]["Policy"])
    snapshot.add_transformer(snapshot.transform.cloudformation_api())


@markers.aws.validated
def test_update_add_two_additional_queues_to_policy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_with_queuepolicy.yml")
    queue_1_url = stack.outputs["Queue1Url"]
    queue_2_url = stack.outputs["Queue2Url"]
    queue_3_url = stack.outputs["Queue3Url"]
    snapshot.match(
        "queue_1_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_1_url, AttributeNames=["Policy"]),
    )
    snapshot.match(
        "queue_2_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_2_url, AttributeNames=["Policy"]),
    )
    snapshot.match(
        "queue_3_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_3_url, AttributeNames=["Policy"]),
    )

    deploy_stack(
        deploy_cfn_template,
        "sqs_with_queuepolicy_for_3_queues.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )
    snapshot.match(
        "queue_1_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_1_url, AttributeNames=["Policy"]),
    )
    snapshot.match(
        "queue_2_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_2_url, AttributeNames=["Policy"]),
    )
    snapshot.match(
        "queue_3_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_3_url, AttributeNames=["Policy"]),
    )
    snapshot.add_transformer(snapshot.transform.key_value("Resource"))


@markers.aws.validated
def test_update_remove_two_queues_from_policy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_with_queuepolicy_for_3_queues.yml")
    queue_1_url = stack.outputs["Queue1Url"]
    queue_2_url = stack.outputs["Queue2Url"]
    queue_3_url = stack.outputs["Queue3Url"]
    snapshot.match(
        "queue_1_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_1_url, AttributeNames=["Policy"]),
    )
    snapshot.match(
        "queue_2_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_2_url, AttributeNames=["Policy"]),
    )
    snapshot.match(
        "queue_3_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_3_url, AttributeNames=["Policy"]),
    )

    deploy_stack(
        deploy_cfn_template,
        "sqs_with_queuepolicy.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )
    snapshot.match(
        "queue_1_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_1_url, AttributeNames=["Policy"]),
    )
    snapshot.match(
        "queue_2_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_2_url, AttributeNames=["Policy"]),
    )
    snapshot.match(
        "queue_3_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_3_url, AttributeNames=["Policy"]),
    )
    snapshot.add_transformer(snapshot.transform.key_value("Resource"))


@markers.aws.validated
def test_update_to_remove_queuepolicy_from_template(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_with_queuepolicy.yml")
    queue_url = stack.outputs["Queue1Url"]
    snapshot.match(
        "policy_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]),
    )

    deploy_stack(
        deploy_cfn_template,
        "sqs_without_queuepolicy.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    snapshot.match(
        "policy_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]),
    )
    snapshot.add_transformer(snapshot.transform.key_value("Resource"))
