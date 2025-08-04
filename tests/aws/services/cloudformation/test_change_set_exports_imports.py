import json
import os

from tests.aws.services.cloudformation.conftest import skip_if_v1_provider
from localstack.aws.api.cloudformation import ChangeSetType
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@skip_if_v1_provider(reason="Not supported on V1")
class TestChangeSetImportExport:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Changes..ResourceChange.Details",
            "$..Changes..ResourceChange.Scope",
            "$..IncludeNestedStacks",
            "$..NotificationARNs",
            "$..Parameters",
        ]
    )
    def test_describe_change_set_import(
        self, snapshot, aws_client, deploy_cfn_template, cleanup_stacks, cleanups
    ):
        export_name = f"b-{short_uid()}"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/cfn_function_export.yml"
            ),
            parameters={"BucketExportName": export_name},
        )

        empty_stack_name = f"stack-{short_uid()}"
        change_set_body = {
            "Resources": {
                "MyFoo": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Type": "String", "Value": {"Fn::ImportValue": export_name}},
                }
            }
        }

        change_set_name = f"change-set-{short_uid()}"
        aws_client.cloudformation.create_change_set(
            StackName=empty_stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=json.dumps(change_set_body),
            ChangeSetType=ChangeSetType.CREATE,
        )
        cleanups.append(lambda: cleanup_stacks([empty_stack_name]))

        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=change_set_name, StackName=empty_stack_name, WaiterConfig={"Delay": 2}
        )

        describe = aws_client.cloudformation.describe_change_set(
            StackName=empty_stack_name, ChangeSetName=change_set_name, IncludePropertyValues=False
        )

        describe_with_values = aws_client.cloudformation.describe_change_set(
            StackName=empty_stack_name, ChangeSetName=change_set_name, IncludePropertyValues=True
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("Value"),
                snapshot.transform.key_value("ChangeSetId"),
                snapshot.transform.key_value("ChangeSetName"),
                snapshot.transform.key_value("StackId"),
                snapshot.transform.key_value("StackName"),
            ]
        )

        snapshot.match("describe", describe)
        snapshot.match("describe_with_values", describe_with_values)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Changes..ResourceChange.Details",
            "$..Changes..ResourceChange.Scope",
            "$..IncludeNestedStacks",
            "$..NotificationARNs",
            "$..Parameters",
        ]
    )
    def test_describe_change_set_import_non_existent_export(
        self, snapshot, aws_client, deploy_cfn_template, cleanup_stacks, cleanups
    ):
        export_name = f"b-{short_uid()}"
        empty_stack_name = f"stack-{short_uid()}"
        change_set_body = {
            "Resources": {
                "MyFoo": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Type": "String", "Value": {"Fn::ImportValue": export_name}},
                }
            }
        }

        change_set_name = f"change-set-{short_uid()}"
        aws_client.cloudformation.create_change_set(
            StackName=empty_stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=json.dumps(change_set_body),
            ChangeSetType=ChangeSetType.CREATE,
        )
        cleanups.append(lambda: cleanup_stacks([empty_stack_name]))

        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=change_set_name, StackName=empty_stack_name, WaiterConfig={"Delay": 2}
        )

        describe = aws_client.cloudformation.describe_change_set(
            StackName=empty_stack_name, ChangeSetName=change_set_name, IncludePropertyValues=False
        )

        describe_with_values = aws_client.cloudformation.describe_change_set(
            StackName=empty_stack_name, ChangeSetName=change_set_name, IncludePropertyValues=True
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(export_name, "<export-name>"),
                snapshot.transform.key_value("ChangeSetId"),
                snapshot.transform.key_value("ChangeSetName"),
                snapshot.transform.key_value("StackId"),
                snapshot.transform.key_value("StackName"),
            ]
        )

        snapshot.match("describe", describe)
        snapshot.match("describe_with_values", describe_with_values)
