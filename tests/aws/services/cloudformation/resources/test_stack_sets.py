import os

import pytest
from botocore.exceptions import ClientError
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.config import SECONDARY_TEST_AWS_ACCOUNT_ID, SECONDARY_TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import long_uid, short_uid
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


@markers.aws.manual_setup_required
def test_create_stack_set_with_stack_instances(
    account_id,
    region_name,
    aws_client,
    snapshot,
    wait_stack_set_operation,
):
    """ "Account <...> should have 'AWSCloudFormationStackSetAdministrationRole' role with trust relationship to CloudFormation service."""
    snapshot.add_transformer(snapshot.transform.key_value("StackSetId", "stack-set-id"))

    stack_set_name = f"StackSet-{short_uid()}"

    template_body = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/s3_cors_bucket.yaml")
    )

    result = aws_client.cloudformation.create_stack_set(
        StackSetName=stack_set_name,
        TemplateBody=template_body,
    )

    snapshot.match("create_stack_set", result)

    create_instances_result = aws_client.cloudformation.create_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=[region_name],
    )

    snapshot.match("create_stack_instances", create_instances_result)

    wait_stack_set_operation(stack_set_name, create_instances_result["OperationId"])

    # make sure additional calls do not result in errors
    # even the stack already exists, but returns operation id instead
    create_instances_result = aws_client.cloudformation.create_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=[region_name],
    )

    assert "OperationId" in create_instances_result

    wait_stack_set_operation(stack_set_name, create_instances_result["OperationId"])

    delete_instances_result = aws_client.cloudformation.delete_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=[region_name],
        RetainStacks=False,
    )
    wait_stack_set_operation(stack_set_name, delete_instances_result["OperationId"])

    aws_client.cloudformation.delete_stack_set(StackSetName=stack_set_name)


@skip_if_legacy_engine()
@markers.aws.validated
def test_delete_nonexistent_stack_set(aws_client, snapshot):
    # idempotent
    aws_client.cloudformation.delete_stack_set(
        StackSetName="non-existent-stack-set-id",
    )

    bad_stack_set_id = f"foo:{long_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(bad_stack_set_id, "<stack-id>"))

    aws_client.cloudformation.delete_stack_set(
        StackSetName=bad_stack_set_id,
    )


@skip_if_legacy_engine()
@markers.aws.validated
def test_fetch_non_existent_stack_set_instances(aws_client, snapshot):
    with pytest.raises(ClientError) as e:
        aws_client.cloudformation.create_stack_instances(
            StackSetName="non-existent-stack-set-id",
            Accounts=[SECONDARY_TEST_AWS_ACCOUNT_ID],
            Regions=[SECONDARY_TEST_AWS_REGION_NAME],
        )

    snapshot.match("non-existent-stack-set-name", e.value)

    bad_stack_set_id = f"foo:{long_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(bad_stack_set_id, "<stack-id>"))

    with pytest.raises(ClientError) as e:
        aws_client.cloudformation.create_stack_instances(
            StackSetName=bad_stack_set_id,
            Accounts=[SECONDARY_TEST_AWS_ACCOUNT_ID],
            Regions=[SECONDARY_TEST_AWS_REGION_NAME],
        )

    snapshot.match("non-existent-stack-set-id", e.value)
