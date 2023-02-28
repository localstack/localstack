import os

import botocore
import pytest

from localstack.testing.aws.cloudformation_utils import load_template_file
from localstack.utils.strings import short_uid


class TestExtensionsHooks:
    @pytest.mark.skip(reason="test not finished")
    def test_hook_deployment(self, register_extension, cfn_client, snapshot):
        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/hooks/localstack-testing-deployablehook.zip",
        )
        register_extension(
            extension_type="HOOK",
            extension_name="LocalStack::Testing::DeployableHook",
            artifact_path=artifact_path,
        )

        template = load_template_file(
            os.path.join(
                os.path.dirname(__file__),
                "../../templates/s3_bucket_name.yml",
            )
        )

        stack_name = f"stack-{short_uid()}"
        cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": "Name", "ParameterValue": f"bucket-{short_uid()}"}],
        )

        with pytest.raises(botocore.exceptions.WaiterError) as e:
            cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_name)

        snapshot.match("error", e.value)
