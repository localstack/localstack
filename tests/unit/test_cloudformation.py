import re

from localstack.services.cloudformation.cloudformation_api import Stack
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    remove_none_values,
)
from localstack.services.cloudformation.models.stepfunctions import _apply_substitutions
from localstack.utils.cloudformation import template_deployer, template_preparer


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
    stack_name = "test"
    stack = Stack({"StackName": stack_name})
    result = template_deployer.resolve_refs_recursively(stack, ref)
    pattern = r"arn:aws:apigateway:.*:lambda:path/2015-03-31/functions/test:lambda:arn/invocations"
    assert re.match(pattern, result)


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
        assert template_preparer.is_local_service_url(url)
    for url in remote_urls:
        assert not template_preparer.is_local_service_url(url)


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
