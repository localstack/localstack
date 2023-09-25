import os

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestExtensionsModules:
    @pytest.mark.skip(reason="feature not supported")
    @markers.aws.validated
    def test_module_usage(self, deploy_cfn_template, register_extension, snapshot, aws_client):
        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/modules/localstack-testing-testmodule-module.zip",
        )
        register_extension(
            extension_type="MODULE",
            extension_name="LocalStack::Testing::TestModule::MODULE",
            artifact_path=artifact_path,
        )

        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../../templates/registry/module.yml",
        )

        module_bucket_name = f"bucket-module-{short_uid()}"
        stack = deploy_cfn_template(
            template_path=template_path,
            parameters={"BucketName": module_bucket_name},
            max_wait=300,
        )
        resources = aws_client.cloudformation.describe_stack_resources(StackName=stack.stack_name)[
            "StackResources"
        ]

        snapshot.add_transformer(snapshot.transform.regex(module_bucket_name, "bucket-name-"))
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.match("resource_description", resources[0])
