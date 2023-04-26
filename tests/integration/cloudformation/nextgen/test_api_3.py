import json
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest
from botocore.exceptions import ClientError, ParamValidationError, WaiterError
from dateutil.parser import parse as parse_datetime

from localstack.utils.files import load_file as _load_file
from localstack.utils.strings import short_uid

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_cloudtrail import LookupEventsPaginator


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


def load_file(path):
    contents = _load_file(path)
    if not contents:
        raise ValueError(f"could not load from {path}")

    return contents


create_args = {
    "resolve_ssm_parameter_as_stack_parameter_permission_denied": {
        "Parameters": [
            {"ParameterKey": "TopicName", "ParameterValue": "ssm-parameter-cannot-access"},
        ],
        "denied_services": ["ssm"],
    },
    "resolve_ssm_parameter_as_stack_parameter_does_not_exist": {
        "Parameters": [
            {"ParameterKey": "TopicName", "ParameterValue": "ssm-parameter-does-not-exist"},
        ],
    },
    "create_resource_permission_denied": {
        "Parameters": [
            {"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"},
        ],
        "denied_services": ["sns"],
    },
    "template_invalid_cfn_schema": {},
    "template_invalid_yaml_syntax": {},
    "missing_required_parameter": {},
    "combi_template_parameters_ssm_parameters": {
        "Parameters": [
            {"ParameterKey": "Bar", "ParameterValue": "missing-ssm-parameter"},
        ],
    },
    "invalid_parameter_type": {
        "Parameters": [
            {"ParameterKey": "Foo", "ParameterValue": "hello"},
        ],
    },
    "invalid_parameter_type_and_missing_ssm": {
        "Parameters": [
            {"ParameterKey": "Foo", "ParameterValue": "hello"},
            {"ParameterKey": "Bar", "ParameterValue": "missing-ssm-parameter"},
        ],
    },
    "missing_mappings_template_parameters": {
        "Parameters": [],
    },
    "missing_ref_missing_mappings": {},
    "dynamic_reference_missing_parameter": {},
    "create_resource_permission_denied_missing_field": {
        "denied_services": ["ssm"],
    },
}

scenarios = list(create_args.keys())


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
    template_body = load_file(os.path.join(THIS_DIR, f"./templates/{scenario}.yaml"))

    cfn_client: CloudFormationClient = aws_client.cloudformation
    stack_name = f"cfnv2-test-stack-{short_uid()}"
    change_set_name = f"cfnv2-test-changeset-{short_uid()}"

    denied_services = create_args[scenario].pop("denied_services", None)
    if denied_services:
        role_arn = setup_role(denied_services)
        create_args[scenario]["RoleARN"] = role_arn
        time.sleep(15)

    try:
        change_set_result = cfn_client.create_change_set(
            TemplateBody=template_body,
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
    describe_changeset_byarnalone = cfn_client.describe_change_set(ChangeSetName=change_set_arn)
    snapshot.match("describe_changeset_byarnalone", describe_changeset_byarnalone)
    try:
        cfn_client.get_waiter("change_set_create_complete").wait(ChangeSetName=change_set_arn)
    except Exception as e:
        snapshot.match("wait_for_create_change_set_exc", str(e))

    describe_changeset_bynames_postwait = cfn_client.describe_change_set(
        ChangeSetName=change_set_name, StackName=stack_name
    )
    snapshot.match("describe_changeset_bynames_postwait", describe_changeset_bynames_postwait)

    # execute changeset
    try:
        cfn_client.execute_change_set(ChangeSetName=change_set_arn)
    except ClientError as e:
        snapshot.match("execute_change_set_exc", e.response)
    except Exception as e:
        snapshot.match("postcreate_processed_template_exc", str(e))

    try:
        cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_arn)
    except WaiterError:
        pass

        # capture post-state
    describe_stack_postexecute = cfn_client.describe_stacks(StackName=stack_arn)
    snapshot.match("describe_stack_postexecute", describe_stack_postexecute)

    postcreate_original_template = cfn_client.get_template(
        StackName=stack_name, TemplateStage="Original"
    )
    snapshot.match("postcreate_original_template", postcreate_original_template)
    try:
        postcreate_processed_template = cfn_client.get_template(
            StackName=stack_name, TemplateStage="Processed"
        )
        snapshot.match("postcreate_processed_template", postcreate_processed_template)
    except ClientError as e:
        snapshot.match("postcreate_processed_template_exc", e.response)
    except Exception as e:
        snapshot.match("postcreate_processed_template_exc", str(e))

    stack_events = (
        cfn_client.get_paginator("describe_stack_events")
        .paginate(StackName=stack_arn)
        .build_full_result()
    )
    snapshot.match("stack_events", stack_events)


@pytest.mark.parametrize("scenario", scenarios)
def test_skeleton_stack(aws_client, snapshot, cleanups, scenario, setup_role):
    cfn_client = aws_client.cloudformation
    stack_name = f"cfnv2-test-stack-{short_uid()}"

    denied_services = create_args[scenario].pop("denied_services", None)
    if denied_services:
        role_arn = setup_role(denied_services)
        create_args[scenario]["RoleARN"] = role_arn
        # TODO: only AWS cloud
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
    except ClientError as e:
        snapshot.match("postcreate_processed_template_exc", e.response)
    except Exception as e:
        snapshot.match("postcreate_processed_template_exc", str(e))


@pytest.fixture
def capture_cloudtrail_events(aws_client, snapshot, create_iam_role_with_policy):
    start_time = datetime.now(tz=timezone.utc)
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
        ],
    }
    role_arn = create_iam_role_with_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        RoleDefinition=role_definition,
        PolicyDefinition=policy_document,
    )
    time.sleep(15)

    yield role_arn

    end_time = datetime.now(tz=timezone.utc)

    events = []
    paginator: "LookupEventsPaginator" = aws_client.cloudtrail.get_paginator("lookup_events")
    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
    ):
        for event in page["Events"]:
            raw_cloudtrail_event = event.get("CloudTrailEvent")
            if not raw_cloudtrail_event:
                continue
            cloudtrail_event = json.loads(raw_cloudtrail_event)
            deploy_role = (
                cloudtrail_event.get("userIdentity", {})
                .get("sessionContext", {})
                .get("sessionIssuer", {})
                .get("arn")
            )
            if deploy_role == role_arn:
                events.append(cloudtrail_event)

    events.sort(key=lambda e: parse_datetime(e["eventTime"]))

    snapshot.match("cloudtrail-events", events)
