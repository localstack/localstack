import json

import pytest

from localstack.testing.pytest import markers


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
def test_validations_for_invalid_output_structure(
    deploy_cfn_template, snapshot, aws_client, outputs
):
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
