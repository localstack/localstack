import json
import os
import urllib.parse

import pytest

from localstack.constants import PATH_USER_REQUEST
from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))


def test_statemachine_definitionsubstitution(
    cfn_client,
    lambda_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
    stepfunctions_client,
    s3_client,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw("stepfunctions_statemachine_substitutions.yaml"),
        ChangeSetType="CREATE",
        Capabilities=["CAPABILITY_IAM"],
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)

        wait_until(is_stack_created(stack_id))

        stack_result = cfn_client.describe_stacks(StackName=stack_id)
        assert stack_result["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE"

        outputs = stack_result["Stacks"][0]["Outputs"]
        assert len(outputs) == 1
        statemachine_arn = outputs[0]["OutputValue"]

        # execute statemachine
        ex_result = stepfunctions_client.start_execution(stateMachineArn=statemachine_arn)

        def _is_executed():
            return (
                stepfunctions_client.describe_execution(executionArn=ex_result["executionArn"])[
                    "status"
                ]
                != "RUNNING"
            )

        wait_until(_is_executed)
        execution_desc = stepfunctions_client.describe_execution(
            executionArn=ex_result["executionArn"]
        )
        assert execution_desc["status"] == "SUCCEEDED"
        # sync execution is currently not supported since botocore adds a "sync-" prefix
        # ex_result = stepfunctions_client.start_sync_execution(stateMachineArn=statemachine_arn)

        assert "hello from statemachine" in execution_desc["output"]

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


def test_nested_statemachine_with_sync2(
    cfn_client,
    lambda_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
    stepfunctions_client,
    s3_client,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw("sfn_nested_sync2.json"),
        ChangeSetType="CREATE",
        Capabilities=["CAPABILITY_IAM"],
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)

        wait_until(is_stack_created(stack_id))

        stack_result = cfn_client.describe_stacks(StackName=stack_id)
        assert stack_result["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE"

        parent_arn = [
            o["OutputValue"]
            for o in stack_result["Stacks"][0]["Outputs"]
            if o["OutputKey"] == "ParentStateMachineArnOutput"
        ][0]

        ex_result = stepfunctions_client.start_execution(
            stateMachineArn=parent_arn, input='{"Value": 1}'
        )

        def _is_executed():
            return (
                stepfunctions_client.describe_execution(executionArn=ex_result["executionArn"])[
                    "status"
                ]
                != "RUNNING"
            )

        wait_until(_is_executed)
        execution_desc = stepfunctions_client.describe_execution(
            executionArn=ex_result["executionArn"]
        )
        assert execution_desc["status"] == "SUCCEEDED"
        output = json.loads(execution_desc["output"])
        assert output["Value"] == 3

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


@pytest.mark.skip(reason="Challenger: Uses custom resource for API Gateway?")
def test_apigateway_invoke(cfn_client, deploy_cfn_template, stepfunctions_client):
    deploy_result = deploy_cfn_template(template_file_name="sfn_apigateway.yaml")
    state_machine_arn = deploy_result.outputs["statemachineOutput"]

    execution_arn = stepfunctions_client.start_execution(stateMachineArn=state_machine_arn)[
        "executionArn"
    ]

    def _sfn_finished_running():
        return (
            stepfunctions_client.describe_execution(executionArn=execution_arn)["status"]
            != "RUNNING"
        )

    wait_until(_sfn_finished_running)

    execution_result = stepfunctions_client.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"
    assert "hello from stepfunctions" in execution_result["output"]


@pytest.mark.skip(reason="Challenger: Uses custom resource for API Gateway?")
def test_apigateway_invoke_with_path(cfn_client, deploy_cfn_template, stepfunctions_client):
    deploy_result = deploy_cfn_template(template_file_name="sfn_apigateway_two_integrations.yaml")
    state_machine_arn = deploy_result.outputs["statemachineOutput"]

    execution_arn = stepfunctions_client.start_execution(stateMachineArn=state_machine_arn)[
        "executionArn"
    ]

    def _sfn_finished_running():
        return (
            stepfunctions_client.describe_execution(executionArn=execution_arn)["status"]
            != "RUNNING"
        )

    wait_until(_sfn_finished_running)

    execution_result = stepfunctions_client.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"
    assert "hello_with_path from stepfunctions" in execution_result["output"]


def test_apigateway_invoke_localhost(cfn_client, deploy_cfn_template, stepfunctions_client):
    """tests the same as above but with the "generic" localhost version of invoking the apigateway"""
    deploy_result = deploy_cfn_template(template_file_name="sfn_apigateway.yaml")
    state_machine_arn = deploy_result.outputs["statemachineOutput"]
    api_url = deploy_result.outputs["LsApiEndpointA06D37E8"]

    # instead of changing the template, we're just mapping the endpoint here to the more generic path-based version
    state_def = stepfunctions_client.describe_state_machine(stateMachineArn=state_machine_arn)[
        "definition"
    ]
    parsed = urllib.parse.urlparse(api_url)
    api_id = parsed.hostname.split(".")[0]
    state = json.loads(state_def)
    stage = state["States"]["LsCallApi"]["Parameters"]["Stage"]
    state["States"]["LsCallApi"]["Parameters"]["ApiEndpoint"] = "localhost:4566"
    state["States"]["LsCallApi"]["Parameters"][
        "Stage"
    ] = f"restapis/{api_id}/{stage}/{PATH_USER_REQUEST}"
    state["States"]["LsCallApi"]["Parameters"]["Path"] = "/"

    stepfunctions_client.update_state_machine(
        stateMachineArn=state_machine_arn, definition=json.dumps(state)
    )

    execution_arn = stepfunctions_client.start_execution(stateMachineArn=state_machine_arn)[
        "executionArn"
    ]

    def _sfn_finished_running():
        return (
            stepfunctions_client.describe_execution(executionArn=execution_arn)["status"]
            != "RUNNING"
        )

    wait_until(_sfn_finished_running)

    execution_result = stepfunctions_client.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"
    assert "hello from stepfunctions" in execution_result["output"]


def test_apigateway_invoke_localhost_with_path(
    cfn_client, deploy_cfn_template, stepfunctions_client
):
    """tests the same as above but with the "generic" localhost version of invoking the apigateway"""
    deploy_result = deploy_cfn_template(template_file_name="sfn_apigateway_two_integrations.yaml")
    state_machine_arn = deploy_result.outputs["statemachineOutput"]
    api_url = deploy_result.outputs["LsApiEndpointA06D37E8"]

    # instead of changing the template, we're just mapping the endpoint here to the more generic path-based version
    state_def = stepfunctions_client.describe_state_machine(stateMachineArn=state_machine_arn)[
        "definition"
    ]
    parsed = urllib.parse.urlparse(api_url)
    api_id = parsed.hostname.split(".")[0]
    state = json.loads(state_def)
    stage = state["States"]["LsCallApi"]["Parameters"]["Stage"]
    state["States"]["LsCallApi"]["Parameters"]["ApiEndpoint"] = "localhost:4566"
    state["States"]["LsCallApi"]["Parameters"][
        "Stage"
    ] = f"restapis/{api_id}/{stage}/{PATH_USER_REQUEST}"

    stepfunctions_client.update_state_machine(
        stateMachineArn=state_machine_arn, definition=json.dumps(state)
    )

    execution_arn = stepfunctions_client.start_execution(stateMachineArn=state_machine_arn)[
        "executionArn"
    ]

    def _sfn_finished_running():
        return (
            stepfunctions_client.describe_execution(executionArn=execution_arn)["status"]
            != "RUNNING"
        )

    wait_until(_sfn_finished_running)

    execution_result = stepfunctions_client.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"
    assert "hello_with_path from stepfunctions" in execution_result["output"]
