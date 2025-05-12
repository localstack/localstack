import json
from typing import Callable

import pytest

from localstack.services.cloudformation.autogen import generation, patches, specs
from localstack.testing.pytest import markers


@pytest.fixture
def autogen_resource():
    def _autogen(resource_type: str) -> dict:
        spec = specs.read_spec_for(resource_type)
        spec = patches.apply_patch_for(spec)
        resource = generation.generate_resource_from_spec(spec)

        return {
            "Resources": {
                "MyResource": resource,
            },
            "Outputs": {
                "MyResourceRef": {
                    "Value": {"Ref": "MyResource"},
                },
            },
        }

    return _autogen


@markers.aws.only_localstack
@pytest.mark.parametrize(
    "resource_type",
    [
        "AWS::DynamoDB::Table",
        "AWS::SNS::Topic",
        "AWS::S3::Bucket",
    ],
)
def test_autogen(
    autogen_resource: Callable[[str], dict],
    deploy_cfn_template,
    resource_type: str,
):
    template = autogen_resource(resource_type)
    stack = deploy_cfn_template(template=json.dumps(template))
    ref = stack.outputs["MyResourceRef"]
    _ = ref
