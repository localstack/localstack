import jinja2
import pytest

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


@pytest.mark.parametrize(
    ("intrinsic_fn", "parameter_1", "parameter_2", "expected_bucket_created"),
    [
        ("Fn::And", "0", "0", False),
        ("Fn::And", "0", "1", False),
        ("Fn::And", "1", "0", False),
        ("Fn::And", "1", "1", True),
        ("Fn::Or", "0", "0", False),
        ("Fn::Or", "0", "1", True),
        ("Fn::Or", "1", "0", True),
        ("Fn::Or", "1", "1", True),
    ],
)
def test_intrinsic_functions(
    cfn_client,
    s3_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
    intrinsic_fn,
    parameter_1,
    parameter_2,
    expected_bucket_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    bucket_name = f"ls-bucket-{short_uid()}"
    template_rendered = jinja2.Template(load_template_raw("cfn_intrinsic_functions.yaml")).render(
        bucket_name=bucket_name,
        intrinsic_fn=intrinsic_fn,
    )
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
        Parameters=[
            {"ParameterKey": "Param1", "ParameterValue": parameter_1},
            {"ParameterKey": "Param2", "ParameterValue": parameter_2},
        ],
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        buckets = s3_client.list_buckets()
        bucket_names = [b["Name"] for b in buckets["Buckets"]]

        assert (bucket_name in bucket_names) == expected_bucket_created

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
