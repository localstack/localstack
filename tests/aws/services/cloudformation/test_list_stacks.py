import json

from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

pytestmark = skip_if_legacy_engine(reason="Requires the V2 engine")


@markers.aws.validated
def test_listing_stacks(aws_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(snapshot.transform.key_value("StackId"))
    snapshot.add_transformer(snapshot.transform.key_value("StackName"))

    template = {
        "Parameters": {
            "ParameterValue": {
                "Type": "String",
            }
        },
        "Resources": {
            "MyParameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Type": "String",
                    "Value": {"Ref": "ParameterValue"},
                },
            },
        },
    }

    s1 = f"stack-1-{short_uid()}"
    s2 = f"stack-2-{short_uid()}"
    s3 = f"stack-3-{short_uid()}"

    p1 = f"1-{short_uid()}"
    p2 = f"2-{short_uid()}"
    p3 = f"3-{short_uid()}"

    deploy_cfn_template(
        stack_name=s1, template=json.dumps(template), parameters={"ParameterValue": p1}
    )
    deploy_cfn_template(
        stack_name=s2, template=json.dumps(template), parameters={"ParameterValue": p2}
    )
    deploy_cfn_template(
        stack_name=s3, template=json.dumps(template), parameters={"ParameterValue": p3}
    )

    stacks = aws_client.cloudformation.list_stacks()["StackSummaries"]

    # filter stacks to only include the ones we have captured
    # TODO: use the stack ids instead to be clear in the unlikely event of a collision
    stacks = [stack for stack in stacks if stack["StackName"] in (s1, s2, s3)]
    stacks.sort(key=lambda stack: stack["StackName"])
    snapshot.match("stacks", stacks)
