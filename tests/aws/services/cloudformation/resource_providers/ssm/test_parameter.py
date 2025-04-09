import copy
import json
import os

import pytest
from botocore.exceptions import ClientError

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestBasicCRD:
    @markers.snapshot.skip_snapshot_verify(paths=["$..error-message"])
    @markers.aws.validated
    def test_black_box(self, deploy_cfn_template, aws_client: ServiceLevelClientFactory, snapshot):
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "templates/aws_ssm_parameter_minimal.yaml",
            ),
        )

        # TODO: implement fetching the resource and performing any required validations here
        parameter_name = stack.outputs["MyRef"]
        snapshot.add_transformer(snapshot.transform.regex(parameter_name, "<parameter>"))

        res = aws_client.ssm.get_parameter(Name=stack.outputs["MyRef"])
        snapshot.match("describe-resource", res)

        stack.destroy()

        # TODO: fetch the resource again and assert that it no longer exists
        with pytest.raises(ClientError) as exc_info:
            aws_client.ssm.get_parameter(Name=stack.outputs["MyRef"])

        snapshot.match("deleted-resource", {"error-message": str(exc_info.value)})


class TestUpdates:
    @markers.aws.validated
    def test_ssm_parameter_update(self, deploy_cfn_template, aws_client, snapshot):
        value1 = short_uid()
        value2 = short_uid()
        snapshot.add_transformer(snapshot.transform.regex(value1, "<value-1>"))
        snapshot.add_transformer(snapshot.transform.regex(value2, "<value-2>"))

        t1 = {
            "Resources": {
                "MyParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": value1,
                    },
                },
            },
            "Outputs": {
                "ParameterName": {
                    "Value": {"Ref": "MyParameter"},
                },
            },
        }
        t2 = copy.deepcopy(t1)
        t2["Resources"]["MyParameter"]["Properties"]["Value"] = value2

        stack = deploy_cfn_template(template=json.dumps(t1))
        parameter_name = stack.outputs["ParameterName"]
        snapshot.add_transformer(snapshot.transform.regex(parameter_name, "<parameter-name>"))

        res = aws_client.ssm.get_parameter(Name=parameter_name)
        snapshot.match("describe-resource-before-update", res)

        deploy_cfn_template(stack_name=stack.stack_id, template=json.dumps(t2), is_update=True)
        res = aws_client.ssm.get_parameter(Name=parameter_name)
        snapshot.match("describe-resource-after-update", res)

    @pytest.mark.skip(reason="TODO")
    @markers.aws.validated
    def test_update_without_replacement(self, deploy_cfn_template, aws_client, snapshot):
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "templates/aws_ssm_parameter_update_without_replacement.yaml",
            ),
            parameters={"AttributeValue": "first"},
        )

        # TODO: implement fetching the resource and performing any required validations here
        res = aws_client.ssm.get_parameter(Name=stack.outputs["MyRef"])
        snapshot.match("describe-resource-before-update", res)

        # TODO: update the stack
        deploy_cfn_template(
            stack_name=stack.stack_name,
            template_path=os.path.join(
                os.path.dirname(__file__),
                "templates/aws_ssm_parameter_update_without_replacement.yaml",
            ),
            parameters={"AttributeValue": "second"},
            is_update=True,
        )

        # TODO: check the value has changed
        res = aws_client.ssm.get_parameter(Name=stack.outputs["MyRef"])
        snapshot.match("describe-resource-after-update", res)
