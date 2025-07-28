import os

import pytest
from botocore.exceptions import ClientError

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.config import SECONDARY_TEST_AWS_ACCOUNT_ID, SECONDARY_TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import long_uid, short_uid
from localstack.utils.sync import wait_until

pytestmark = pytest.mark.skipif(
    condition=not is_v2_engine() and not is_aws_cloud(),
    reason="Only targeting the new engine",
)


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


@pytest.fixture(scope="session")
def setup_account_for_stack_sets(aws_client):
    template_path = os.path.join(
        os.path.dirname(__file__),
        "../../../../../templates/AWSCloudFormationStackSetAdministrationRole.yml",
    )
    assert os.path.isfile(template_path)

    # replicating deploy_cfn_template since it's a function scoped fixture
    stack_name = f"stack-{short_uid()}"
    with open(template_path) as infile:
        template_body = infile.read()
    stack = aws_client.cloudformation.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    stack_id = stack["StackId"]
    aws_client.cloudformation.get_waiter("stack_create_complete").wait(
        StackName=stack_id,
        WaiterConfig={
            # 5 minutes
            "Delay": 3,
            "MaxAttempts": 100,
        },
    )
    yield
    aws_client.cloudformation.delete_stack(StackName=stack_id)
    aws_client.cloudformation.get_waiter("stack_delete_complete").wait(
        StackName=stack_id,
        WaiterConfig={
            # 5 minutes
            "Delay": 3,
            "MaxAttempts": 100,
        },
    )


@markers.aws.validated
@pytest.mark.usefixtures("setup_account_for_stack_sets")
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..LastOperationId",
        "$..OrganizationalUnitId",
        "$..ParameterOverrides",
        "$..StatusReason",
    ]
)
def test_create_stack_set_with_stack_instances(
    account_id,
    region_name,
    aws_client,
    snapshot,
    wait_stack_set_operation,
):
    snapshot.add_transformer(snapshot.transform.key_value("StackSetId"))
    snapshot.add_transformer(snapshot.transform.key_value("StackId"))

    stack_set_name = f"StackSet-{short_uid()}"

    template_body = load_file(
        os.path.join(os.path.dirname(__file__), "../../../../../templates/s3_cors_bucket.yaml")
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

    # check the resources actually exist
    stack_instance = aws_client.cloudformation.describe_stack_instance(
        StackSetName=stack_set_name,
        StackInstanceAccount=account_id,
        StackInstanceRegion=region_name,
    )["StackInstance"]
    snapshot.match("describe-stack-instance", stack_instance)

    stack_instance_stack_id = stack_instance["StackId"]
    aws_client.cloudformation.get_waiter("stack_create_complete").wait(
        StackName=stack_instance_stack_id,
        WaiterConfig={
            "Delay": 3,
            "MaxAttempts": 100,
        },
    )
    outputs = aws_client.cloudformation.describe_stacks(StackName=stack_instance_stack_id)[
        "Stacks"
    ][0]["Outputs"]
    bucket_names = [
        output["OutputValue"]
        for output in outputs
        if output["OutputKey"] in {"BucketNameAllParameters", "BucketNameOnlyRequired"}
    ]
    for bucket_name in bucket_names:
        aws_client.s3.head_bucket(Bucket=bucket_name)

    delete_instances_result = aws_client.cloudformation.delete_stack_instances(
        StackSetName=stack_set_name,
        Accounts=[account_id],
        Regions=[region_name],
        RetainStacks=False,
    )
    wait_stack_set_operation(stack_set_name, delete_instances_result["OperationId"])

    aws_client.cloudformation.delete_stack_set(StackSetName=stack_set_name)


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
