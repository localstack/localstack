# Stack
import os.path

import pytest
from botocore.exceptions import WaiterError

from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

THIS_DIR = os.path.dirname(__file__)

create_args = {
    "additional_unused_parameter": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/additional_unused_parameter.yaml")
        ),
        "Parameters": [
            {"ParameterKey": "a", "ParameterValue": "b"},
        ],
    },
    "missing_field_in_resource_properties": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/missing_field_in_resource_properties.yaml")
        )
    },
    "additional_field_in_resource_properties_not_in_schema": {
        "TemplateBody": load_file(
            os.path.join(
                THIS_DIR, "./templates/additional_field_in_resource_properties_not_in_schema.yaml"
            )
        ),
    },
    "invalid_intrinsic_function_usage": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/invalid_intrinsic_function_usage.yaml")
        ),
    },
    "ref_nonexisting": {
        "TemplateBody": load_file(os.path.join(THIS_DIR, "./templates/ref_nonexisting.yaml")),
    },
    "import_nonexisting_export": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/import_nonexisting_export.yaml")
        ),
    },
    "missing_item_in_mapping": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/missing_item_in_mapping.yaml")
        ),
    },
    "failing_rule": {
        "TemplateBody": load_file(os.path.join(THIS_DIR, "./templates/failing_rule.yaml")),
        "Parameters": [
            {"ParameterKey": "Param1", "ParameterValue": "HelloWorld"},
            {"ParameterKey": "Param2", "ParameterValue": "HelloWorld"},  # correct: HelloWorld2
        ],
    },
    "invalid_global_transformation": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/invalid_global_transformation.yaml")
        ),
        "Capabilities": ["CAPABILITY_AUTO_EXPAND"],
    },
}


@pytest.mark.parametrize(
    "scenario",
    [
        # "resolve_ssm_parameter_as_stack_parameter_permission_denied",
        # "resolve_ssm_parameter_as_stack_parameter_does_not_exist",
        # "create_resource_permission_denied",
        # "template_invalid_cfn_schema",
        # "template_invalid_yaml_syntax",
        # "missing_required_parameter",
        "additional_unused_parameter",
        "missing_field_in_resource_properties",
        "additional_field_in_resource_properties_not_in_schema",
        "invalid_intrinsic_function_usage",
        "ref_nonexisting",
        "import_nonexisting_export",
        "missing_item_in_mapping",
        "failing_rule",
        "invalid_global_transformation",
    ],
)
def test_skeleton_stack(aws_client, snapshot, cleanups, scenario):
    cfn_client = aws_client.cloudformation
    stack_name = f"cfnv2-test-stack-{short_uid()}"
    try:
        change_set_result = cfn_client.create_stack(
            StackName=stack_name,
            **create_args[scenario],
        )
        stack_arn = change_set_result["StackId"]
        cleanups.append(lambda: cfn_client.delete_stack(StackName=stack_arn))
        try:
            cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_arn)
        except WaiterError:
            pass

        describe_stack = cfn_client.describe_stacks(StackName=stack_arn)
        snapshot.match("describe_stack", describe_stack)
        stack_events = (
            cfn_client.get_paginator("describe_stack_events")
            .paginate(StackName=stack_arn)
            .build_full_result()
        )
        snapshot.match("stack_events", stack_events)
        postcreate_original_template = cfn_client.get_template(
            StackName=stack_name, TemplateStage="Original"
        )
        snapshot.match("postcreate_original_template", postcreate_original_template)
        try:
            postcreate_processed_template = cfn_client.get_template(
                StackName=stack_name, TemplateStage="Processed"
            )
            snapshot.match("postcreate_processed_template", postcreate_processed_template)
        except Exception as e:
            snapshot.match("postcreate_processed_template_exc", e.response)
    except Exception as e:
        snapshot.match("create_stack_exc", e.response)
