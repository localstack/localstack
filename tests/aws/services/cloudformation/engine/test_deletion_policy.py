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
def test_deletion_policy_with_deletion(aws_client, deploy_cfn_template, snapshot):
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
def test_deletion_policy_with_retain(
    aws_client, deploy_cfn_template, capture_per_resource_events, snapshot, cleanups
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

    # make sure we clean up the parameter
    cleanups.append(lambda: aws_client.ssm.delete_parameter(Name=parameter_name))

    value = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
    assert value == parameter_value

    stack.destroy()

    value = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
    assert value == parameter_value

    events = capture_per_resource_events(stack.stack_id)
    snapshot.match("per-resource-events", events)
