import os.path

import pytest

from localstack.utils.common import short_uid


def test_parameter_defaults(ssm_client, deploy_cfn_template):
    ssm_parameter_value = f"custom-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/ssm_parameter_defaultname.yaml"
        ),
        parameters={"Input": ssm_parameter_value},
    )

    parameter_name = stack.outputs["CustomParameterOutput"]
    assert "CustomParameter" in parameter_name
    param = ssm_client.get_parameter(Name=parameter_name)
    assert param["Parameter"]["Value"] == ssm_parameter_value

    # make sure parameter is deleted
    stack.destroy()

    with pytest.raises(Exception) as ctx:
        ssm_client.get_parameter(Name=parameter_name)
    ctx.match("ParameterNotFound")


@pytest.mark.aws_validated
def test_update_ssm_parameters(deploy_cfn_template, ssm_client):
    ssm_parameter_value = f"custom-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/ssm_parameter_defaultname.yaml"
        ),
        parameters={"Input": ssm_parameter_value},
    )

    ssm_parameter_value = f"new-custom-{short_uid()}"
    deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/ssm_parameter_defaultname.yaml"
        ),
        parameters={"Input": ssm_parameter_value},
    )

    parameter_name = stack.outputs["CustomParameterOutput"]
    param = ssm_client.get_parameter(Name=parameter_name)
    assert param["Parameter"]["Value"] == ssm_parameter_value
