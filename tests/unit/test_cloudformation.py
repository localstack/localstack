import re
from typing import Dict

from localstack.services.cloudformation.api_utils import is_local_service_url
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    remove_none_values,
)
from localstack.services.cloudformation.engine import template_deployer
from localstack.services.cloudformation.engine.entities import Stack
from localstack.services.cloudformation.models.stepfunctions import _apply_substitutions


def test_resolve_references():
    ref = {
        "Fn::Join": [
            "",
            [
                "arn:",
                {"Ref": "AWS::Partition"},
                ":apigateway:",
                {"Ref": "AWS::Region"},
                ":lambda:path/2015-03-31/functions/",
                "test:lambda:arn",
                "/invocations",
            ],
        ]
    }
    result = _resolve_refs_in_template(ref)
    pattern = r"arn:aws:apigateway:.*:lambda:path/2015-03-31/functions/test:lambda:arn/invocations"
    assert re.match(pattern, result)


def test_sub_numeric_value():
    template = {"test": {"Sub": "${TestNumValue}"}}
    result = _resolve_refs_in_template(template, stack_params={"TestNumValue": 1234})
    assert result == {"test": "1234"}


def test_is_local_service_url():
    local_urls = [
        "http://localhost",
        "https://localhost",
        "http://localhost:4566",
        "https://localhost:4566",
        "http://localhost.localstack.cloud:4566",
        "https://s3.localhost.localstack.cloud",
        "http://mybucket.s3.localhost.localstack.cloud:4566",
        "https://mybucket.s3.localhost",
    ]
    remote_urls = [
        "https://mybucket.s3.amazonaws.com",
        "http://mybucket.s3.us-east-1.amazonaws.com",
    ]
    for url in local_urls:
        assert is_local_service_url(url)
    for url in remote_urls:
        assert not is_local_service_url(url)


def test_apply_substitutions():
    blubstr = "something ${foo} and ${test} + ${foo}"
    subs = {"foo": "bar", "test": "resolved"}

    assert _apply_substitutions(blubstr, subs) == "something bar and resolved + bar"


def test_remove_none_values():
    template = {
        "Properties": {
            "prop1": 123,
            "nested": {"test1": PLACEHOLDER_AWS_NO_VALUE, "test2": None},
            "list": [1, 2, PLACEHOLDER_AWS_NO_VALUE, 3, None],
        }
    }
    result = remove_none_values(template)
    assert result == {"Properties": {"prop1": 123, "nested": {}, "list": [1, 2, 3]}}


def _resolve_refs_in_template(template, stack_params: Dict = None):
    stack = Stack({"StackName": "test"})
    stack.stack_parameters()
    stack_params = stack_params or {}
    stack_params = [{"ParameterKey": k, "ParameterValue": v} for k, v in stack_params.items()]
    stack.metadata["Parameters"].extend(stack_params)
    return template_deployer.resolve_refs_recursively(stack, template)
