import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.testing.pytest.fixtures import StackDeployError


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    """
    Helper function to deploy a CloudFormation stack using a template file. This exists to reduce
    boilerplate in the test cases.
    """
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_create_standard_queue_with_required_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_standard_queue_required_properties.yml")
    (queue_url, queue_arn) = (stack.outputs["QueueUrl"], stack.outputs["QueueArn"])

    snapshot.match(
        "attributes",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]),
    )
    snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))

    # auto-generated name check
    assert "StandardQueue" in queue_url
    assert not queue_url.endswith(".fifo")


@markers.aws.validated
def test_create_standard_queue_with_all_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_standard_queue_all_properties.yml")
    (queue_url, queue_arn, dlq_queue_url, dlq_queue_arn) = (
        stack.outputs["QueueUrl"],
        stack.outputs["QueueArn"],
        stack.outputs["DeadLetterQueueUrl"],
        stack.outputs["DeadLetterQueueArn"],
    )

    snapshot.match(
        "attributes",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]),
    )
    snapshot.match("tags", aws_client.sqs.list_queue_tags(QueueUrl=queue_url))
    snapshot.match(
        "dlq_attributes",
        aws_client.sqs.get_queue_attributes(
            QueueUrl=dlq_queue_url, AttributeNames=["RedriveAllowPolicy"]
        ),
    )
    snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))
    snapshot.add_transformer(snapshot.transform.regex(dlq_queue_arn, "<dlq-queue-arn>"))


@markers.aws.validated
def test_create_fifo_queue_with_required_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_fifo_queue_required_properties.yml")
    (queue_url, queue_arn) = (stack.outputs["QueueUrl"], stack.outputs["QueueArn"])

    snapshot.match(
        "attributes",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]),
    )
    snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))

    # auto-generated name check
    assert "FifoQueue" in queue_url
    assert queue_url.endswith(".fifo")


@markers.aws.validated
def test_create_fifo_queue_with_all_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_fifo_queue_all_properties.yml")
    (queue_url, queue_arn, dlq_queue_url, dlq_queue_arn) = (
        stack.outputs["QueueUrl"],
        stack.outputs["QueueArn"],
        stack.outputs["DeadLetterQueueUrl"],
        stack.outputs["DeadLetterQueueArn"],
    )

    snapshot.match(
        "attributes",
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]),
    )
    snapshot.match("tags", aws_client.sqs.list_queue_tags(QueueUrl=queue_url))
    snapshot.match(
        "dlq_attributes",
        aws_client.sqs.get_queue_attributes(
            QueueUrl=dlq_queue_url, AttributeNames=["RedriveAllowPolicy"]
        ),
    )
    snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))
    snapshot.add_transformer(snapshot.transform.regex(dlq_queue_arn, "<dlq-queue-arn>"))


@markers.aws.validated
def test_update_standard_queue_modify_properties_in_place(
    deploy_cfn_template, aws_client, snapshot
):
    stack = deploy_stack(deploy_cfn_template, "sqs_standard_queue_all_properties.yml")
    queue_url = stack.outputs["QueueUrl"]

    # Update the stack to add optional properties
    updated_stack = deploy_stack(
        deploy_cfn_template,
        "sqs_standard_queue_all_properties_variant_1.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )
    updated_queue_url = updated_stack.outputs["QueueUrl"]
    assert queue_url == updated_queue_url

    snapshot.match(
        "updated_attributes",
        aws_client.sqs.get_queue_attributes(QueueUrl=updated_queue_url, AttributeNames=["All"]),
    )
    snapshot.match("updated_tags", aws_client.sqs.list_queue_tags(QueueUrl=updated_queue_url))
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["QueueArn"], "<queue-arn>"))
    snapshot.add_transformer(
        snapshot.transform.regex(stack.outputs["DeadLetterQueueArn"], "<dlq-queue-arn>")
    )


@markers.aws.validated
def test_update_standard_queue_add_properties_with_replacement(
    deploy_cfn_template, aws_client, snapshot
):
    stack = deploy_stack(deploy_cfn_template, "sqs_standard_queue_all_properties.yml")
    (queue_url, dlq_queue_url) = (stack.outputs["QueueUrl"], stack.outputs["DeadLetterQueueUrl"])

    # Update the stack to rename the queue - this will cause the resource to be replaced, rather than
    # updating the existing queue in place
    updated_stack = deploy_stack(
        deploy_cfn_template,
        "sqs_standard_queue_all_properties_variant_2.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )
    (updated_queue_url, updated_dlq_queue_url) = (
        updated_stack.outputs["QueueUrl"],
        updated_stack.outputs["DeadLetterQueueUrl"],
    )
    assert queue_url != updated_queue_url
    assert dlq_queue_url == updated_dlq_queue_url

    snapshot.match(
        "updated_attributes",
        aws_client.sqs.get_queue_attributes(QueueUrl=updated_queue_url, AttributeNames=["All"]),
    )
    snapshot.match("updated_tags", aws_client.sqs.list_queue_tags(QueueUrl=updated_queue_url))
    snapshot.add_transformer(snapshot.transform.key_value("deadLetterTargetArn", "<dlq-queue-arn>"))

    # confirm that the original queue has been deleted
    with pytest.raises(ClientError) as exc:
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
    snapshot.match("error", exc.value.response)


@markers.aws.validated
def test_update_standard_queue_remove_some_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_standard_queue_all_properties.yml")
    queue_url = stack.outputs["QueueUrl"]

    # Update the stack with modified properties
    updated_stack = deploy_stack(
        deploy_cfn_template,
        "sqs_standard_queue_some_properties.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )
    updated_queue_url = updated_stack.outputs["QueueUrl"]
    assert queue_url == updated_queue_url

    snapshot.match(
        "updated_attributes",
        aws_client.sqs.get_queue_attributes(QueueUrl=updated_queue_url, AttributeNames=["All"]),
    )
    snapshot.match("updated_tags", aws_client.sqs.list_queue_tags(QueueUrl=updated_queue_url))
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["QueueArn"], "<queue-arn>"))
    snapshot.add_transformer(snapshot.transform.key_value("deadLetterTargetArn", "<dlq-queue-arn>"))


@markers.aws.validated
def test_update_completely_remove_resource(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_standard_queue_all_properties.yml")
    queue_url = stack.outputs["QueueUrl"]

    # Delete the queue by updating the stack to remove the resource
    deploy_stack(
        deploy_cfn_template,
        "sqs_standard_queue_no_resource.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    # expect an exception to be thrown because the resource is deleted
    with pytest.raises(ClientError) as exc:
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
    snapshot.match("error", exc.value.response)


@markers.aws.validated
def test_update_standard_queue_without_explicit_name(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_standard_queue_required_properties.yml")
    queue_url = stack.outputs["QueueUrl"]

    # Update the stack to add optional properties, but expect the same queue name to be used.
    updated_stack = deploy_stack(
        deploy_cfn_template,
        "sqs_standard_queue_some_properties_without_name.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )
    updated_queue_url = updated_stack.outputs["QueueUrl"]
    assert queue_url == updated_queue_url

    snapshot.match(
        "updated_attributes",
        aws_client.sqs.get_queue_attributes(QueueUrl=updated_queue_url, AttributeNames=["All"]),
    )
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["QueueArn"], "<queue-arn>"))


@pytest.mark.skip(reason="SQS service in LocalStack does not correctly fail on invalid parameters")
@markers.aws.needs_fixing
def test_error_invalid_parameter(deploy_cfn_template, aws_client, snapshot):
    with pytest.raises(StackDeployError) as exc:
        deploy_stack(
            deploy_cfn_template,
            "sqs_standard_queue_all_properties_with_error.yml",
        )
    snapshot.match("error", exc.value)
