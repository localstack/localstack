import os

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestExtensionsResourceTypes:
    @pytest.mark.skip(reason="feature not implemented")
    @markers.aws.validated
    def test_deploy_resource_type(
        self, deploy_cfn_template, register_extension, snapshot, aws_client
    ):
        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/resourcetypes/localstack-testing-deployableresource.zip",
        )

        register_extension(
            extension_type="RESOURCE",
            extension_name="LocalStack::Testing::DeployableResource",
            artifact_path=artifact_path,
        )

        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../../templates/registry/resource-provider.yml",
        )

        resource_name = f"name-{short_uid()}"
        stack = deploy_cfn_template(
            template_path=template_path, parameters={"Name": resource_name}, max_wait=900
        )
        resources = aws_client.cloudformation.describe_stack_resources(StackName=stack.stack_name)[
            "StackResources"
        ]

        snapshot.add_transformer(snapshot.transform.regex(resource_name, "resource-name"))
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.match("resource_description", resources[0])

        # Make sure to destroy the stack before unregistration
        stack.destroy()
