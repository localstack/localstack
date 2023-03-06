import json
import os

import botocore.exceptions
import pytest

from localstack.testing.aws.cloudformation_utils import load_template_file
from localstack.utils.strings import short_uid


class TestExtensionsHooks:
    @pytest.mark.skip(reason="feature not implemented")
    @pytest.mark.parametrize("failure_mode", ["FAIL", "WARN"])
    def test_hook_deployment(
        self, failure_mode, register_extension, cfn_client, snapshot, cleanups
    ):
        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/hooks/localstack-testing-deployablehook.zip",
        )
        extension = register_extension(
            extension_type="HOOK",
            extension_name="LocalStack::Testing::DeployableHook",
            artifact_path=artifact_path,
        )

        extension_configuration = json.dumps(
            {
                "CloudFormationConfiguration": {
                    "HookConfiguration": {"TargetStacks": "ALL", "FailureMode": failure_mode}
                }
            }
        )
        cfn_client.set_type_configuration(
            TypeArn=extension["TypeArn"], Configuration=extension_configuration
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
        cleanups.append(lambda: cfn_client.delete_stack(StackName=stack_name))

        if failure_mode == "WARN":
            cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_name)
        else:
            with pytest.raises(botocore.exceptions.WaiterError):
                cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_name)

        events = cfn_client.describe_stack_events(StackName=stack_name)["StackEvents"]

        failed_events = [e for e in events if "HookStatusReason" in e]
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.match("event_error", failed_events[0])
