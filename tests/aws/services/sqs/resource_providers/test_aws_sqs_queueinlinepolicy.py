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
def test_create_sqs_with_inlinepolicy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_with_queueinlinepolicy.yml")
    queue_url = stack.outputs["QueueUrl"]

    snapshot.match(
        "policy", aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    )
    snapshot.add_transformer(snapshot.transform.key_value("Resource"))


@markers.aws.validated
def test_update_sqs_with_inlinepolicy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_with_queueinlinepolicy.yml")
    queue_url = stack.outputs["QueueUrl"]

    snapshot.match(
        "policy_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]),
    )

    deploy_stack(
        deploy_cfn_template,
        "sqs_with_queueinlinepolicy_variant_1.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )
    snapshot.match(
        "policy_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]),
    )
    snapshot.add_transformer(snapshot.transform.key_value("Resource"))


@markers.aws.validated
def test_update_sqs_remove_inlinepolicy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_with_queueinlinepolicy.yml")
    queue_url = stack.outputs["QueueUrl"]

    snapshot.match(
        "policy_before",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]),
    )

    deploy_stack(
        deploy_cfn_template,
        "sqs_without_queueinlinepolicy.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    snapshot.match(
        "policy_after",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]),
    )
    snapshot.add_transformer(snapshot.transform.key_value("Resource"))
