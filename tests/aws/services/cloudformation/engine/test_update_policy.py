import os

import pytest
from botocore.exceptions import ClientError
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.snapshot.skip_snapshot_verify(
    paths=[
        # our message is different. The AWS message does not seem to include the parameter
        # name but ours does
        "$..message",
    ]
)
@markers.aws.validated
@skip_if_legacy_engine()
def test_update_replace_policy_deletion(deploy_cfn_template, aws_client, snapshot):
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
        aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"] == parameter_value
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
    with pytest.raises(ClientError) as exc_info:
        aws_client.ssm.get_parameter(Name=parameter_name)

    snapshot.match("error", {"message": str(exc_info.value)})


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..PhysicalResourceId",
    ]
)
@skip_if_legacy_engine()
def test_update_replace_policy_retain(
    deploy_cfn_template, aws_client, snapshot, capture_per_resource_events, cleanups
):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    template_path = os.path.join(
        os.path.dirname(__file__),
        "../../../templates/update_retain_policy.yaml",
    )
    parameter_value = short_uid()
    parameter_name = f"param-{short_uid()}"
    # make sure we clean up the parameter when the test finishes
    cleanups.append(lambda: aws_client.ssm.delete_parameter(Name=parameter_name))

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
        aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"] == parameter_value
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
    assert (
        aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"] == parameter_value
    )

    events = capture_per_resource_events(stack.stack_id)
    snapshot.match("per-resource-events", events)
