import os
import time

import pytest
from botocore.exceptions import ClientError, ParamValidationError, WaiterError

from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

THIS_DIR = os.path.dirname(__file__)

# CreateStack does it fail synchronously when trying to resolve an SSM parameter but it isn't allowed to
# CreateStack - point CFn parameter to an SSM parameter that doesn't exist
# CreateStack - Create a resource that cfn / (or the role) doesn't have access for

# CreateStack - Upload a syntactically wrong template (valid JSON/YAML)
# CreateStack - Upload a syntactically wrong template (invalid JSON/YAML)
# CreateStack - Upload template with missing parameter
# CreateStack - Upload template with a resource having missing fields
# CreateStack - Upload template with a resource having an unspec'ed field

# CreateStack - Upload template with a failure caused by an invalid usage of an intrinsic function
# CreateStack - Ref something that doesn't exist
# CreateStack - Importing non-existing exports

# need more setup (can be done later)
# CreateStack - Create with a failing global transformation
# CreateStack - Missing item in mapping
# CreateStack - Rules (passing / non-passing)

create_args = {
    "resolve_ssm_parameter_as_stack_parameter_permission_denied": {
        "TemplateBody": load_file(
            os.path.join(
                THIS_DIR,
                "./templates/resolve_ssm_parameter_as_stack_parameter_permission_denied.yaml",
            )
        ),
        "Parameters": [
            {"ParameterKey": "TopicName", "ParameterValue": "ssm-parameter-cannot-access"},
        ],
        "denied_services": ["ssm"],
    },
    "resolve_ssm_parameter_as_stack_parameter_does_not_exist": {
        "TemplateBody": load_file(
            os.path.join(
                THIS_DIR, "./templates/resolve_ssm_parameter_as_stack_parameter_does_not_exist.yaml"
            )
        ),
        "Parameters": [
            {"ParameterKey": "TopicName", "ParameterValue": "ssm-parameter-does-not-exist"},
        ],
    },
    "create_resource_permission_denied": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/create_resource_permission_denied.yaml")
        ),
        "Parameters": [
            {"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"},
        ],
        "denied_services": ["sns"],
    },
    "template_invalid_cfn_schema": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/template_invalid_cfn_schema.yaml")
        ),
    },
    "template_invalid_yaml_syntax": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/template_invalid_yaml_syntax.yaml")
        ),
    },
    "missing_required_parameter": {
        "TemplateBody": load_file(
            os.path.join(THIS_DIR, "./templates/missing_required_parameter.yaml")
        ),
    },
}

scenarios = [
    "resolve_ssm_parameter_as_stack_parameter_permission_denied",
    "resolve_ssm_parameter_as_stack_parameter_does_not_exist",
    "create_resource_permission_denied",
    "template_invalid_cfn_schema",
    "template_invalid_yaml_syntax",
    "missing_required_parameter",
    ###
    # "missing_field_in_resource_properties",
    # "additional_field_in_resource_properties_not_in_schema",
    # "invalid_intrinsic_function_usage",
    # "ref_nonexisting",
    # "import_nonexisting_export",
    # "missing_item_in_mapping",
    # "passing_rule",
    # "failing_rule",
    # optional
    # "invalid_global_transformation",
]


@pytest.fixture
def setup_role(create_iam_role_with_policy, aws_client):
    """
    Set up a role with specific deny for services
    """

    def setup(denied_services):
        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        role_definition = {
            "Statement": {
                "Sid": "",
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        }

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["*"],
                    "Resource": ["*"],
                },
                {
                    "Effect": "Deny",
                    "Action": [f"{service}:*" for service in denied_services],
                    "Resource": ["*"],
                },
            ],
        }
        role_arn = create_iam_role_with_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            RoleDefinition=role_definition,
            PolicyDefinition=policy_document,
        )
        return role_arn

    yield setup


@pytest.mark.parametrize("scenario", scenarios)
def test_skeleton_changeset(aws_client, snapshot, cleanups, scenario, setup_role):
    cfn_client = aws_client.cloudformation
    stack_name = f"cfnv2-test-stack-{short_uid()}"
    change_set_name = f"cfnv2-test-changeset-{short_uid()}"

    denied_services = create_args[scenario].pop("denied_services", None)
    if denied_services:
        role_arn = setup_role(denied_services)
        create_args[scenario]["RoleARN"] = role_arn
        time.sleep(15)

    try:
        change_set_result = cfn_client.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            ChangeSetType="CREATE",
            **create_args[scenario],
        )
    except ClientError as e:
        snapshot.match("create_change_set_exc", e.response)
        return
    except ParamValidationError as e:
        snapshot.match("create_change_set_exc", {"args": e.args, "kwargs": e.kwargs})
        return

    change_set_arn = change_set_result["Id"]
    stack_arn = change_set_result["StackId"]
    cleanups.append(lambda: cfn_client.delete_stack(StackName=stack_arn))

    describe_stack = cfn_client.describe_stacks(StackName=stack_arn)
    snapshot.match("describe_stack", describe_stack)
    stack_events = (
        cfn_client.get_paginator("describe_stack_events")
        .paginate(StackName=stack_arn)
        .build_full_result()
    )
    snapshot.match("stack_events", stack_events)
    describe_changeset_byarnalone = cfn_client.describe_change_set(ChangeSetName=change_set_arn)
    snapshot.match("describe_changeset_byarnalone", describe_changeset_byarnalone)
    cfn_client.get_waiter("change_set_create_complete").wait(ChangeSetName=change_set_arn)
    describe_changeset_bynames_postwait = cfn_client.describe_change_set(
        ChangeSetName=change_set_name, StackName=stack_name
    )
    snapshot.match("describe_changeset_bynames_postwait", describe_changeset_bynames_postwait)

    # execute changeset
    try:
        cfn_client.execute_change_set(ChangeSetName=change_set_arn)
        try:
            cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_arn)
        except WaiterError:
            pass

        # capture post-state
        describe_stack_postexecute = cfn_client.describe_stacks(StackName=stack_arn)
        snapshot.match("describe_stack_postexecute", describe_stack_postexecute)
        postcreate_original_template = cfn_client.get_template(
            StackName=stack_name, ChangeSetName=change_set_name, TemplateStage="Original"
        )
        snapshot.match("postcreate_original_template", postcreate_original_template)
        postcreate_processed_template = cfn_client.get_template(
            StackName=stack_name, ChangeSetName=change_set_name, TemplateStage="Processed"
        )
        snapshot.match("postcreate_processed_template", postcreate_processed_template)
    except ClientError as e:
        snapshot.match("execute_change_set_exc", e.response)
        return


@pytest.mark.parametrize("scenario", scenarios)
def test_skeleton_stack(aws_client, snapshot, cleanups, scenario, setup_role):
    cfn_client = aws_client.cloudformation
    stack_name = f"cfnv2-test-stack-{short_uid()}"

    denied_services = create_args[scenario].pop("denied_services", None)
    if denied_services:
        role_arn = setup_role(denied_services)
        create_args[scenario]["RoleARN"] = role_arn
        time.sleep(15)

    try:
        create_stack_result = cfn_client.create_stack(
            StackName=stack_name,
            **create_args[scenario],
        )
    except ClientError as e:
        snapshot.match("create_stack_exc", e.response)
        return
    except ParamValidationError as e:
        snapshot.match("create_stack_exc", {"args": e.args, "kwargs": e.kwargs})
        return

    stack_arn = create_stack_result["StackId"]
    cleanups.append(lambda: cfn_client.delete_stack(StackName=stack_arn))

    try:
        cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_arn)
    except WaiterError:
        pass

    postcreate_original_template = cfn_client.get_template(
        StackName=stack_name, TemplateStage="Original"
    )
    snapshot.match("postcreate_original_template", postcreate_original_template)
    postcreate_processed_template = cfn_client.get_template(
        StackName=stack_name, TemplateStage="Processed"
    )
    snapshot.match("postcreate_processed_template", postcreate_processed_template)
    describe_stack = cfn_client.describe_stacks(StackName=stack_arn)
    snapshot.match("describe_stack", describe_stack)
    stack_events = (
        cfn_client.get_paginator("describe_stack_events")
        .paginate(StackName=stack_arn)
        .build_full_result()
    )
    snapshot.match("stack_events", stack_events)
