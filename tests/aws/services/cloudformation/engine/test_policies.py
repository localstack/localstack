import os

import pytest
from botocore.exceptions import ClientError
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestDeletionPolicyHandling:
    @markers.aws.validated
    def test_deletion_policy_with_deletion(self, aws_client, deploy_cfn_template):
        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../../templates/deletion_policy.yaml",
        )
        parameter_value = short_uid()
        stack = deploy_cfn_template(
            template_path=template_path,
            parameters={
                "EnvType": "dev",
                "ParameterValue": parameter_value,
            },
        )

        parameter_name = stack.outputs["ParameterName"]
        value = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
        assert value == parameter_value

        stack.destroy()

        with pytest.raises(ClientError):
            aws_client.ssm.get_parameter(Name=parameter_name)

        # TODO: provider parity issue with error message
        # snapshot.match("error", exc_info.value)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..PhysicalResourceId",
        ]
    )
    @skip_if_legacy_engine()
    def test_deletion_policy_with_retain(
        self, aws_client, deploy_cfn_template, capture_per_resource_events, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../../templates/deletion_policy.yaml",
        )
        parameter_value = short_uid()
        stack = deploy_cfn_template(
            template_path=template_path,
            parameters={
                "EnvType": "prod",
                "ParameterValue": parameter_value,
            },
        )

        snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "<stack-name>"))

        parameter_name = stack.outputs["ParameterName"]
        value = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
        assert value == parameter_value

        stack.destroy()

        value = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
        assert value == parameter_value

        events = capture_per_resource_events(stack.stack_id)
        snapshot.match("per-resource-events", events)


class TestUpdatePolicyHandling:
    @markers.aws.validated
    @skip_if_legacy_engine()
    def test_update_replace_policy_deletion(self, deploy_cfn_template, aws_client):
        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../../templates/update_retain_policy.yaml",
        )
        parameter_value = short_uid()
        parameter_name = f"param-{short_uid()}"
        stack = deploy_cfn_template(
            template_path=template_path,
            parameters={
                "ParameterValue": parameter_value,
                "ParameterName": parameter_name,
                "PolicyType": "Delete",
            },
        )
        assert (
            aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
            == parameter_value
        )

        # force deletion by changing the resource name
        new_parameter_name = f"param-{short_uid()}"
        deploy_cfn_template(
            template_path=template_path,
            parameters={
                "ParameterValue": parameter_value,
                "ParameterName": new_parameter_name,
                "PolicyType": "Delete",
            },
            stack_name=stack.stack_id,
            is_update=True,
        )
        assert (
            aws_client.ssm.get_parameter(Name=new_parameter_name)["Parameter"]["Value"]
            == parameter_value
        )

        # check the previous parameter was deleted
        with pytest.raises(ClientError):
            aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..PhysicalResourceId",
        ]
    )
    @skip_if_legacy_engine()
    def test_update_replace_policy_retain(
        self, deploy_cfn_template, aws_client, snapshot, capture_per_resource_events
    ):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../../templates/update_retain_policy.yaml",
        )
        parameter_value = short_uid()
        parameter_name = f"param-{short_uid()}"
        stack = deploy_cfn_template(
            template_path=template_path,
            parameters={
                "ParameterValue": parameter_value,
                "ParameterName": parameter_name,
                "PolicyType": "Retain",
            },
        )
        snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "<stack-name>"))
        assert (
            aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
            == parameter_value
        )

        # force deletion by changing the resource name
        new_parameter_name = f"param-{short_uid()}"
        deploy_cfn_template(
            template_path=template_path,
            parameters={
                "ParameterValue": parameter_value,
                "ParameterName": new_parameter_name,
                "PolicyType": "Retain",
            },
            stack_name=stack.stack_id,
            is_update=True,
        )
        assert (
            aws_client.ssm.get_parameter(Name=new_parameter_name)["Parameter"]["Value"]
            == parameter_value
        )

        # check the previous parameter was not deleted
        aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]

        events = capture_per_resource_events(stack.stack_id)
        snapshot.match("per-resource-events", events)
