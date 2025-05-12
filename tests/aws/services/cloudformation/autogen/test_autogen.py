import json
from typing import Callable

import pytest

from localstack import config
from localstack.services.cloudformation.autogen import generation, patches, specs
from localstack.services.cloudformation.autogen.generation import generate_resources_from_spec
from localstack.testing.pytest import markers

SUPPORTED_RESOURCES = [
    "AWS::DynamoDB::Table",
    "AWS::SNS::Topic",
    "AWS::S3::Bucket",
]
NON_HOST_MODE_RESOURCES = {"AWS::DynamoDB::Table"}


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


@pytest.fixture
def autogen_template():
    def _autogen(resource_types: list[str], count: tuple[int, int] = (1, 5)) -> dict:
        resources = generate_resources_from_spec(resource_types, count)
        return {
            "Resources": resources,
        }

    return _autogen


@markers.aws.only_localstack
@pytest.mark.parametrize(
    "resource_type",
    SUPPORTED_RESOURCES,
)
def test_autogen_resource(
    autogen_resource: Callable[[str], dict],
    deploy_cfn_template,
    resource_type: str,
):
    if resource_type == "AWS::DynamoDB::Table" and not config.is_in_docker:
        pytest.skip(reason="DynamoDB tables not supported in host mode")

    template = autogen_resource(resource_type)
    stack = deploy_cfn_template(template=json.dumps(template))
    ref = stack.outputs["MyResourceRef"]
    _ = ref


@markers.aws.only_localstack
def test_autogen_template(
    autogen_template: Callable[[list[str]], dict],
    deploy_cfn_template,
):
    resources = SUPPORTED_RESOURCES
    if not config.is_in_docker:
        resources = list(set(SUPPORTED_RESOURCES) - NON_HOST_MODE_RESOURCES)
    template = autogen_template(resources)
    deploy_cfn_template(template=json.dumps(template))
