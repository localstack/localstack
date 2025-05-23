import os

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message", "$..message"])
def test_single_resource(deploy_cfn_template, aws_client, snapshot):
    value = short_uid()
    value2 = short_uid()
    snapshot.add_transformer(snapshot.transform.regex(value, "<value-1>"))
    snapshot.add_transformer(snapshot.transform.regex(value2, "<value-2>"))
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/ssm_parameter_defaultname.yaml"
        ),
        parameters={"Input": value},
    )

    parameter_name = stack.outputs["CustomParameterOutput"]
    snapshot.add_transformer(snapshot.transform.regex(parameter_name, "<parameter-name>"))
    value = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]
    snapshot.match("get-value", value)

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/ssm_parameter_defaultname.yaml"
        ),
        parameters={"Input": value2},
        is_update=True,
        stack_name=stack.stack_id,
    )

    value = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]
    snapshot.match("get-value-2", value)

    stack.destroy()

    with pytest.raises(aws_client.ssm.exceptions.ParameterNotFound) as exc_info:
        aws_client.ssm.get_parameter(Name=parameter_name)

    snapshot.match("exc-value", exc_info.value.response)
