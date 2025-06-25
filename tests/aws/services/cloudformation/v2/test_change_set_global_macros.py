import os

import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@pytest.mark.skipif(
    condition=not is_v2_engine() and not is_aws_cloud(), reason="Requires the V2 engine"
)
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "per-resource-events..*",
        "delete-describe..*",
        #
        # Before/After Context
        "$..Capabilities",
        "$..NotificationARNs",
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
            os.path.dirname(__file__), "../../../templates/macros/format_template.py"
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
                os.path.dirname(__file__), "../../../templates/macro_resource.yml"
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
