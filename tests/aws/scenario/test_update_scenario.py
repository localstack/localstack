import time

import aws_cdk as cdk
import aws_cdk.aws_ecs as ecs
import pytest
import requests

from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner


class TestUpdateScenario:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        app = cdk.App()
        stack = cdk.Stack(app, "TestUpdateStack")

        param = cdk.aws_ssm.StringParameter(stack, 'param', string_value="hello world 2")

        cdk.CfnOutput(stack, "ParamValue", value=param.string_value)
        cdk.CfnOutput(stack, "ParamName", value=param.parameter_name)

        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        with provisioner.provisioner(skip_teardown=True) as prov:
            yield prov

    @markers.aws.unknown
    def test_scenario_validate_infra(self, aws_client, infrastructure):
        outputs = infrastructure.get_stack_outputs(stack_name="TestUpdateStack")
        param_value = outputs["ParamValue"]
        param_name = outputs["ParamName"]
        ssm_param = aws_client.ssm.get_parameter(Name=param_name)
        assert ssm_param['Parameter']['Name'] == param_name
        assert ssm_param['Parameter']['Value'] == param_value
        assert ssm_param['Parameter']['Value'] == "hello world 2"
