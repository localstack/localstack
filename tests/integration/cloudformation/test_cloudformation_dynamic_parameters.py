import jinja2 as jinja2
import pytest as pytest

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_resolve_ssm(
    ssm_client,
    cfn_client,
    is_change_set_created_and_available,
    is_stack_created,
    cleanup_changesets,
    cleanup_stacks,
    create_parameter,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"
    create_parameter(Name=parameter_key, Value=parameter_value, Type="String")
    template_rendered = jinja2.Template(load_template_raw("resolve_ssm.yaml")).render(
        parameter_key=parameter_key,
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
        describe_result = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
        assert describe_result["StackStatus"] == "CREATE_COMPLETE"

        topic_name = [
            o["OutputValue"] for o in describe_result["Outputs"] if o["OutputKey"] == "TopicName"
        ][0]
        assert topic_name == parameter_value

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


def test_resolve_ssm_withversion(
    ssm_client,
    cfn_client,
    is_change_set_created_and_available,
    is_stack_created,
    cleanup_changesets,
    cleanup_stacks,
    create_parameter,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    parameter_key = f"param-key-{short_uid()}"
    parameter_value_v0 = f"param-value-{short_uid()}"
    parameter_value_v1 = f"param-value-{short_uid()}"
    parameter_value_v2 = f"param-value-{short_uid()}"

    create_parameter(Name=parameter_key, Type="String", Value=parameter_value_v0)
    v1 = ssm_client.put_parameter(
        Name=parameter_key, Overwrite=True, Type="String", Value=parameter_value_v1
    )
    ssm_client.put_parameter(
        Name=parameter_key, Overwrite=True, Type="String", Value=parameter_value_v2
    )

    template_rendered = jinja2.Template(load_template_raw("resolve_ssm_withversion.yaml")).render(
        parameter_key=parameter_key, parameter_version=str(v1["Version"])
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
        describe_result = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
        assert describe_result["StackStatus"] == "CREATE_COMPLETE"

        topic_name = [
            o["OutputValue"] for o in describe_result["Outputs"] if o["OutputKey"] == "TopicName"
        ][0]
        assert topic_name == parameter_value_v1

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


def test_resolve_ssm_secure(
    ssm_client,
    cfn_client,
    is_change_set_created_and_available,
    is_stack_created,
    cleanup_changesets,
    cleanup_stacks,
    create_parameter,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"

    create_parameter(Name=parameter_key, Value=parameter_value, Type="SecureString")

    template_rendered = jinja2.Template(load_template_raw("resolve_ssm_secure.yaml")).render(
        parameter_key=parameter_key,
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
        describe_result = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
        assert describe_result["StackStatus"] == "CREATE_COMPLETE"

        topic_name = [
            o["OutputValue"] for o in describe_result["Outputs"] if o["OutputKey"] == "TopicName"
        ][0]
        assert topic_name == parameter_value

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


@pytest.mark.parametrize(
    "template_name", ["resolve_secretsmanager_full.yaml", "resolve_secretsmanager.yaml"]
)
def test_resolve_secretsmanager(
    secretsmanager_client,
    cfn_client,
    is_change_set_created_and_available,
    is_stack_created,
    create_secret,
    create_parameter,
    cleanup_changesets,
    cleanup_stacks,
    template_name,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"

    create_secret(Name=parameter_key, SecretString=parameter_value)

    template_rendered = jinja2.Template(load_template_raw(template_name)).render(
        parameter_key=parameter_key,
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
        describe_result = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
        assert describe_result["StackStatus"] == "CREATE_COMPLETE"

        topic_name = [
            o["OutputValue"] for o in describe_result["Outputs"] if o["OutputKey"] == "TopicName"
        ][0]
        assert topic_name == parameter_value

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
