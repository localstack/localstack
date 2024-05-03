import os

import pytest

from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until


@pytest.fixture
def wait_stack_set_operation(aws_client):
    def waiter(stack_set_name: str, operation_id: str):
        def _operation_is_ready():
            operation = aws_client.cloudformation.describe_stack_set_operation(
                StackSetName=stack_set_name,
                OperationId=operation_id,
            )
            return operation["StackSetOperation"]["Status"] not in ["RUNNING", "STOPPING"]

        wait_until(_operation_is_ready)

    return waiter


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Parameters..NoEcho",
        "$..Parameters..ParameterConstraints",
        "$..Parameters..DefaultValue",
    ],
)
def test_create_stack_set_with_stack_instances(
    account_id,
    aws_client,
    snapshot,
    wait_stack_set_operation,
):
    snapshot.add_transformer(snapshot.transform.key_value("StackSetId", "stack-set-id"))

    stack_set_name = f"StackSet-{short_uid()}"

    template_body = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    topic_name = f"topic-{short_uid()}"
    result = aws_client.cloudformation.create_stack_set(
        StackSetName=stack_set_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": topic_name}],
    )

    snapshot.match("create_stack_set", result)

    template_summary = aws_client.cloudformation.get_template_summary(
        StackSetName=stack_set_name,
    )
    snapshot.match("template-summary", template_summary)

    regions = ["us-west-2", "eu-north-1"]

    create_instances_result = aws_client.cloudformation.create_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=regions,
    )

    snapshot.match("create_stack_instances", create_instances_result)

    wait_stack_set_operation(stack_set_name, create_instances_result["OperationId"])

    # make sure additional calls do not result in errors
    # even the stack already exists, but returns operation id instead
    recreate_instances_result = aws_client.cloudformation.create_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=regions,
    )

    snapshot.match("recreate_stack_instances", recreate_instances_result)

    wait_stack_set_operation(stack_set_name, recreate_instances_result["OperationId"])

    delete_instances_result = aws_client.cloudformation.delete_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=regions,
        RetainStacks=False,
    )
    wait_stack_set_operation(stack_set_name, delete_instances_result["OperationId"])

    aws_client.cloudformation.delete_stack_set(StackSetName=stack_set_name)
