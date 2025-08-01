import json
import os

import pytest
from botocore.exceptions import ClientError
from tests.aws.services.cloudformation.conftest import skip_if_v1_provider

from localstack.testing.pytest import markers


@skip_if_v1_provider(reason="Not implemented for v1")
@markers.aws.validated
def test_describe_non_existent_stack(aws_client, deploy_cfn_template, snapshot):
    with pytest.raises(ClientError) as err:
        aws_client.cloudformation.describe_stack_resource(
            StackName="not-a-valid-stack", LogicalResourceId="not-a-valid-resource"
        )

    snapshot.match("error", err.value)


@markers.aws.validated
def test_describe_non_existent_resource(aws_client, deploy_cfn_template, snapshot):
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/ssm_parameter_defaultname.yaml"
    )
    stack = deploy_cfn_template(template_path=template_path, parameters={"Input": "myvalue"})
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_id, "<stack-id>"))

    with pytest.raises(ClientError) as err:
        aws_client.cloudformation.describe_stack_resource(
            StackName=stack.stack_id, LogicalResourceId="not-a-valid-resource"
        )

    snapshot.match("error", err.value)


@skip_if_v1_provider(reason="Not implemented for v1")
@markers.aws.validated
def test_invalid_logical_resource_id(deploy_cfn_template, snapshot):
    template = {
        "Resources": {
            "my-bad-resource-id": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Type": "String",
                    "Value": "Foo",
                },
            }
        }
    }
    with pytest.raises(ClientError) as err:
        deploy_cfn_template(template=json.dumps(template))

    snapshot.match("error", err.value)
