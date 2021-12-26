import jinja2
import pytest

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_parameter_defaults(
    cfn_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
    is_stack_deleted,
    ssm_client,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    ssm_parameter_value = f"custom-{short_uid()}"
    template_rendered = jinja2.Template(load_template_raw("ssm_parameter_defaultname.yaml")).render(
        ssm_parameter_value=ssm_parameter_value
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

        stack = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
        parameter_name = stack["Outputs"][0]["OutputValue"]

        assert "CustomParameter" in parameter_name
        param = ssm_client.get_parameter(Name=parameter_name)
        assert param["Parameter"]["Value"] == ssm_parameter_value

        # make sure parameter is deleted
        cfn_client.delete_stack(StackName=stack_id)
        wait_until(is_stack_deleted(stack_id))
        with pytest.raises(Exception) as ctx:
            ssm_client.get_parameter(Name=parameter_name)
        ctx.match("ParameterNotFound")

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
