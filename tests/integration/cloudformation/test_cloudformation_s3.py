import jinja2
import pytest

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_bucketpolicy(
    cfn_client,
    s3_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    bucket_name = f"ls-bucket-{short_uid()}"
    template_rendered = jinja2.Template(load_template_raw("s3_bucketpolicy.yaml")).render(
        bucket_name=bucket_name,
        include_policy=True,
    )

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"]
        assert bucket_policy

        nopolicy_template = jinja2.Template(load_template_raw("s3_bucketpolicy.yaml")).render(
            bucket_name=bucket_name,
            include_policy=False,
        )
        nopolicy_changeset_name = f"change-set-{short_uid()}"
        response = cfn_client.create_change_set(
            StackName=stack_name,
            ChangeSetName=nopolicy_changeset_name,
            TemplateBody=nopolicy_template,
            ChangeSetType="UPDATE",
        )
        change_set_id = response["Id"]
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(
            is_stack_created(stack_id)
        )  # TODO: fix cloudformation update status when using changesets

        with pytest.raises(Exception) as err:
            s3_client.get_bucket_policy(Bucket=bucket_name).get("Policy")

        assert err.value.response["Error"]["Code"] == "NoSuchBucketPolicy"

    finally:
        # pass
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


def test_bucket_autoname(
    cfn_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"STACK-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw("s3_bucket_autoname.yaml"),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        descr_response = cfn_client.describe_stacks(StackName=stack_id)
        output = descr_response["Stacks"][0]["Outputs"][0]

        assert output["OutputKey"] == "BucketNameOutput"
        assert stack_name.lower() in output["OutputValue"]

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
