import json

import pytest

from localstack.testing.pytest import markers

pytestmark = pytest.mark.skip("Validations are currently disabled")


@markers.aws.validated
@pytest.mark.parametrize(
    "outputs",
    [
        {
            "MyOutput": {
                "Value": None,
            },
        },
        {
            "MyOutput": {
                "Value": None,
                "AnotherValue": None,
            },
        },
        {
            "MyOutput": {},
        },
    ],
    ids=["none-value", "missing-def", "multiple-nones"],
)
def test_invalid_output_structure(deploy_cfn_template, snapshot, aws_client, outputs):
    template = {
        "Resources": {
            "Foo": {
                "Type": "AWS::SNS::Topic",
            },
        },
        "Outputs": outputs,
    }
    with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
        deploy_cfn_template(template=json.dumps(template))

    snapshot.match("validation-error", e.value.response)


@markers.aws.validated
def test_missing_resources_block(deploy_cfn_template, snapshot, aws_client):
    with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
        deploy_cfn_template(template=json.dumps({}))

    snapshot.match("validation-error", e.value.response)


@markers.aws.validated
@pytest.mark.parametrize(
    "properties",
    [
        {
            "Properties": {},
        },
        {
            "Type": "AWS::SNS::Topic",
            "Invalid": 10,
        },
    ],
    ids=[
        "missing-type",
        "invalid-key",
    ],
)
def test_resources_blocks(deploy_cfn_template, snapshot, aws_client, properties):
    template = {"Resources": {"A": properties}}
    with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
        deploy_cfn_template(template=json.dumps(template))

    snapshot.match("validation-error", e.value.response)
