import os.path

import pytest

from localstack.utils.common import short_uid


def test_parameter_defaults(ssm_client, deploy_cfn_template):
    ssm_parameter_value = f"custom-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/ssm_parameter_defaultname.yaml"
        ),
        template_mapping={"ssm_parameter_value": ssm_parameter_value},
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
