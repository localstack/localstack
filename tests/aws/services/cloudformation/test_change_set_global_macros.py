import json
import os

from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.testing.pytest.cloudformation.fixtures import _normalise_describe_change_set_output
from localstack.utils.functions import call_safe
from localstack.utils.strings import short_uid


@skip_if_legacy_engine()
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "per-resource-events..*",
        "delete-describe..*",
        #
        # Before/After Context
        "$..Capabilities",
        "$..IncludeNestedStacks",
        "$..Scope",
        "$..Details",
        "$..Parameters",
        "$..Replacement",
        "$..PolicyAction",
    ]
)
class TestChangeSetGlobalMacros:
    @markers.aws.validated
    def test_base_global_macro(
        self,
        aws_client,
        cleanups,
        snapshot,
        deploy_cfn_template,
        create_lambda_function,
        capture_update_process,
    ):
        snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..Outputs..OutputValue",
                replacement="output-value",
                replace_reference=True,
            )
        )
        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../templates/macros/format_template.py"
        )
        macro_name = "SubstitutionMacro"
        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=1,
        )
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name},
        )

        template_1 = {
            "Transform": "SubstitutionMacro",
            "Parameters": {"Substitution": {"Type": "String", "Default": "SubstitutionDefault"}},
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String"},
                }
            },
            "Outputs": {"ParameterName": {"Value": {"Ref": "Parameter"}}},
        }
        template_2 = {
            "Transform": "SubstitutionMacro",
            "Parameters": {"Substitution": {"Type": "String", "Default": "SubstitutionDefault"}},
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String"},
                },
                "Parameter2": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String"},
                },
            },
            "Outputs": {
                "Parameter2Name": {"Value": {"Ref": "Parameter2"}},
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_update_after_macro_for_before_version_is_deleted(
        self,
        aws_client,
        aws_client_no_retry,
        cleanups,
        snapshot,
        deploy_cfn_template,
        create_lambda_function,
    ):
        """
        1. create the macro
        2. deploy the first version of the template including the template
        3. delete the first macro
        4. create a second macro (same implementation)
        5. update the stack adding a second SSM parameter
        6. the deploy should work as the new macro is in place
        """
        snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..Outputs..OutputValue",
                replacement="output-value",
                replace_reference=True,
            )
        )
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        macro_function_path = os.path.join(
            os.path.dirname(__file__), "../../templates/macros/format_template.py"
        )

        # Create the macro to be used in the first version of the template.
        macro_name_first = f"SubstitutionMacroFirst-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(macro_name_first, "<macro-name-first>"))
        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=1,
        )
        macro_stack_first = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name_first},
        )

        # Create the first version of the stack.
        template_1 = {
            "Transform": macro_name_first,
            "Parameters": {"Substitution": {"Type": "String", "Default": "SubstitutionDefault"}},
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String"},
                }
            },
            "Outputs": {"ParameterName": {"Value": {"Ref": "Parameter"}}},
        }
        # Create
        stack_name = f"stack-{short_uid()}"
        change_set_name = f"cs-{short_uid()}"
        change_set_details = aws_client_no_retry.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=json.dumps(template_1),
            ChangeSetType="CREATE",
            Parameters=[],
        )
        stack_id = change_set_details["StackId"]
        change_set_id = change_set_details["Id"]
        aws_client_no_retry.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=change_set_id
        )
        cleanups.append(
            lambda: call_safe(
                aws_client_no_retry.cloudformation.delete_change_set,
                kwargs={"ChangeSetName": change_set_id},
            )
        )
        # Describe
        describe_change_set_with_prop_values = (
            aws_client_no_retry.cloudformation.describe_change_set(
                ChangeSetName=change_set_id, IncludePropertyValues=True
            )
        )
        _normalise_describe_change_set_output(describe_change_set_with_prop_values)
        snapshot.match("describe-change-set-1-prop-values", describe_change_set_with_prop_values)
        # Execute.
        execute_results = aws_client_no_retry.cloudformation.execute_change_set(
            ChangeSetName=change_set_id
        )
        snapshot.match("execute-change-set-1", execute_results)
        aws_client_no_retry.cloudformation.get_waiter("stack_create_complete").wait(
            StackName=stack_id
        )
        # ensure stack deletion
        cleanups.append(
            lambda: call_safe(
                aws_client_no_retry.cloudformation.delete_stack, kwargs={"StackName": stack_id}
            )
        )
        describe = aws_client_no_retry.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][
            0
        ]
        snapshot.match("post-create-1-describe", describe)

        # Delete the macro used in the v1 template.
        macro_stack_first.destroy()

        # Create the macro to be used in the second version of the template.
        macro_name_second = f"SubstitutionMacroSecond-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(macro_name_second, "<macro-name-second>"))
        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=macro_function_path,
            runtime=Runtime.python3_12,
            client=aws_client.lambda_,
            timeout=1,
        )
        macro_stack_second = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/macro_resource.yml"
            ),
            parameters={"FunctionName": func_name, "MacroName": macro_name_second},
        )

        # Update
        template_2 = {
            "Transform": macro_name_second,
            "Parameters": {"Substitution": {"Type": "String", "Default": "SubstitutionDefault"}},
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String"},
                },
                "Parameter2": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": "{Substitution}", "Type": "String"},
                },
            },
            "Outputs": {
                "Parameter2Name": {"Value": {"Ref": "Parameter2"}},
            },
        }
        change_set_details = aws_client_no_retry.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=json.dumps(template_2),
            ChangeSetType="UPDATE",
            Parameters=[],
        )
        stack_id = change_set_details["StackId"]
        change_set_id = change_set_details["Id"]
        aws_client_no_retry.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=change_set_id
        )
        # Describe
        describe_change_set_with_prop_values = (
            aws_client_no_retry.cloudformation.describe_change_set(
                ChangeSetName=change_set_id, IncludePropertyValues=True
            )
        )
        _normalise_describe_change_set_output(describe_change_set_with_prop_values)
        snapshot.match("describe-change-set-2-prop-values", describe_change_set_with_prop_values)
        # Execute
        execute_results = aws_client_no_retry.cloudformation.execute_change_set(
            ChangeSetName=change_set_id
        )
        snapshot.match("execute-change-set-2", execute_results)
        aws_client_no_retry.cloudformation.get_waiter("stack_update_complete").wait(
            StackName=stack_id
        )

        # delete stacks
        macro_stack_second.destroy()
        aws_client_no_retry.cloudformation.delete_stack(StackName=stack_id)
        aws_client_no_retry.cloudformation.get_waiter("stack_delete_complete").wait(
            StackName=stack_id
        )
