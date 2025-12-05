import textwrap

import pytest

from localstack import config
from localstack.services.cloudformation.engine.v2 import (
    change_set_resource_support_checker as support_checker_module,
)
from localstack.services.cloudformation.engine.v2.change_set_resource_support_checker import (
    ChangeSetResourceSupportChecker,
)
from localstack.testing.pytest import markers
from localstack.utils.catalog.catalog import (
    AwsServicesSupportStatus,
    CatalogPlugin,
    CfnResourceSupportStatus,
)
from localstack.utils.catalog.common import (
    AwsServicesSupportInLatest,
    AwsServiceSupportAtRuntime,
    CloudFormationResourcesSupportAtRuntime,
    CloudFormationResourcesSupportInLatest,
)
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

UNSUPPORTED_RESOURCE_CASES = [
    (
        "AWS::TestService::UnsupportedLatest",
        CloudFormationResourcesSupportInLatest.NOT_SUPPORTED,
        "testservice",
    ),
    (
        "AWS::RuntimeService::NotImplemented",
        CloudFormationResourcesSupportAtRuntime.NOT_IMPLEMENTED,
        "runtimeservice",
    ),
    (
        "AWS::LicenseRuntime::RequiresUpgrade",
        AwsServiceSupportAtRuntime.AVAILABLE_WITH_LICENSE_UPGRADE,
        "licenseruntime",
    ),
    (
        "AWS::RuntimeService::Missing",
        AwsServiceSupportAtRuntime.NOT_IMPLEMENTED,
        "runtimeservice",
    ),
    (
        "AWS::LatestService::RequiresUpgrade",
        AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE,
        "latestservice",
    ),
    (
        "AWS::LatestService::NotSupported",
        AwsServicesSupportInLatest.NOT_SUPPORTED,
        "latestservice",
    ),
]


class _TestingCatalogPlugin(CatalogPlugin):
    name = "testing-catalog"

    def __init__(self):
        self._unsupported_resources = {
            resource: status for resource, status, _ in UNSUPPORTED_RESOURCE_CASES
        }

    def get_aws_service_status(
        self, service_name: str, operation_name: str | None = None
    ) -> AwsServicesSupportStatus | None:
        return AwsServicesSupportInLatest.SUPPORTED

    def get_cloudformation_resource_status(
        self, resource_name: str, service_name: str, is_pro_resource: bool = False
    ) -> CfnResourceSupportStatus | AwsServicesSupportInLatest | None:
        return self._unsupported_resources.get(
            resource_name, CloudFormationResourcesSupportAtRuntime.AVAILABLE
        )


@pytest.fixture
def testing_catalog(monkeypatch):
    plugin = _TestingCatalogPlugin()
    monkeypatch.setattr(support_checker_module, "get_aws_catalog", lambda: plugin)
    return plugin


@markers.aws.only_localstack
@pytest.mark.parametrize(
    "unsupported_resource, expected_service",
    [(resource, expected_service) for resource, _, expected_service in UNSUPPORTED_RESOURCE_CASES],
)
def test_catalog_reports_unsupported_resources_in_stack_status(
    testing_catalog, aws_client, unsupported_resource, expected_service, monkeypatch, cleanups
):
    monkeypatch.setattr(config, "CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES", False)
    template_body = textwrap.dedent(
        f"""
        AWSTemplateFormatVersion: '2010-09-09'
        Resources:
          Unsupported:
            Type: {unsupported_resource}
        """
    )

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    response = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        ChangeSetType="CREATE",
    )

    change_set_id = response["Id"]
    stack_id = response["StackId"]

    def _describe_failed_change_set():
        result = aws_client.cloudformation.describe_change_set(ChangeSetName=change_set_id)
        status = result["Status"]
        if status == "FAILED":
            return result
        if status == "CREATE_COMPLETE":
            pytest.fail("expected change set creation to fail for unsupported resource")
        raise Exception("gave up on waiting for change set creation to fail")

    change_set = retry(_describe_failed_change_set, retries=20, sleep=2)

    status_reason = change_set.get("StatusReason", "")
    assert ChangeSetResourceSupportChecker.TITLE_MESSAGE in status_reason
    assert unsupported_resource in status_reason

    def _describe_failed_stack():
        stack = aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0]
        stack_status = stack["StackStatus"]
        if stack_status in {"CREATE_FAILED", "ROLLBACK_COMPLETE"}:
            return stack
        raise Exception("gave on waiting for stack creation to fail for unsupported resource")

    stack_description = retry(_describe_failed_stack, retries=30, sleep=2)
    stack_status_reason = stack_description.get("StackStatusReason", "")
    assert ChangeSetResourceSupportChecker.TITLE_MESSAGE in stack_status_reason
    assert unsupported_resource in stack_status_reason
    assert expected_service in stack_status_reason.lower()

    cleanups.append(
        lambda: aws_client.cloudformation.delete_change_set(ChangeSetName=change_set_id)
    )
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_id))
