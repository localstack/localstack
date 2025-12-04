import os

from localstack.testing.pytest import markers
from localstack.utils.sync import wait_until


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
    queue_url = result.outputs["QueueUrlOutput"]

    snapshot.match(
        "policy", aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    )
    snapshot.add_transformer(snapshot.transform.key_value("Resource"))


@markers.aws.validated
def test_update_sqs_queuepolicy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sqs_with_queuepolicy.yml")
    policy = aws_client.sqs.get_queue_attributes(
        QueueUrl=stack.outputs["QueueUrlOutput"], AttributeNames=["Policy"]
    )
    snapshot.match("policy1", policy["Attributes"]["Policy"])

    updated_stack = deploy_stack(
        deploy_cfn_template,
        "sqs_with_queuepolicy_updated.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    def check_policy_updated():
        policy_updated = aws_client.sqs.get_queue_attributes(
            QueueUrl=updated_stack.outputs["QueueUrlOutput"], AttributeNames=["Policy"]
        )
        assert policy_updated["Attributes"]["Policy"] != policy["Attributes"]["Policy"]
        return policy_updated

    wait_until(check_policy_updated)

    policy = aws_client.sqs.get_queue_attributes(
        QueueUrl=updated_stack.outputs["QueueUrlOutput"], AttributeNames=["Policy"]
    )

    snapshot.match("policy2", policy["Attributes"]["Policy"])
    snapshot.add_transformer(snapshot.transform.cloudformation_api())


# TODO: add the following test cases:
#  - update to add two additional queues (1 -> 3)
#  - update to remove two of the queues (3 -> 1)
#  - Update to remove queuepolicy from the template.
