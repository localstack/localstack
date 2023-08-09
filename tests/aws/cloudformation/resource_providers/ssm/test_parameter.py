import os

import pytest
from botocore.exceptions import ClientError

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.pytest import markers


class TestBasicCRD:
    @pytest.mark.skip(reason="re-enable after fixing schema extraction")
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
