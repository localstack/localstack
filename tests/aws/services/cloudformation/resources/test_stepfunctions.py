import json
import os
import urllib.parse

import pytest

from localstack.constants import PATH_USER_REQUEST
from localstack.testing.pytest import markers
from localstack.utils.sync import wait_until
from tests.aws.services.stepfunctions.utils import await_execution_terminated


@markers.aws.validated
def test_statemachine_definitionsubstitution(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../../templates/stepfunctions_statemachine_substitutions.yaml",
        )
    )

    assert len(stack.outputs) == 1
    statemachine_arn = stack.outputs["StateMachineArnOutput"]

    # execute statemachine
    ex_result = aws_client.stepfunctions.start_execution(stateMachineArn=statemachine_arn)

    def _is_executed():
        return (
            aws_client.stepfunctions.describe_execution(executionArn=ex_result["executionArn"])[
                "status"
            ]
            != "RUNNING"
        )

    wait_until(_is_executed)
    execution_desc = aws_client.stepfunctions.describe_execution(
        executionArn=ex_result["executionArn"]
    )
    assert execution_desc["status"] == "SUCCEEDED"
    # sync execution is currently not supported since botocore adds a "sync-" prefix
    # ex_result = stepfunctions_client.start_sync_execution(stateMachineArn=statemachine_arn)

    assert "hello from statemachine" in execution_desc["output"]


@markers.aws.validated
def test_nested_statemachine_with_sync2(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sfn_nested_sync2.json"
        )
    )

    parent_arn = stack.outputs["ParentStateMachineArnOutput"]
    assert parent_arn

    ex_result = aws_client.stepfunctions.start_execution(
        stateMachineArn=parent_arn, input='{"Value": 1}'
    )

    def _is_executed():
        return (
            aws_client.stepfunctions.describe_execution(executionArn=ex_result["executionArn"])[
                "status"
            ]
            != "RUNNING"
        )

    wait_until(_is_executed)
    execution_desc = aws_client.stepfunctions.describe_execution(
        executionArn=ex_result["executionArn"]
    )
    assert execution_desc["status"] == "SUCCEEDED"
    output = json.loads(execution_desc["output"])
    assert output["Value"] == 3


@markers.aws.needs_fixing
def test_apigateway_invoke(deploy_cfn_template, aws_client):
    deploy_result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sfn_apigateway.yaml"
        )
    )
    state_machine_arn = deploy_result.outputs["statemachineOutput"]

    execution_arn = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)[
        "executionArn"
    ]

    def _sfn_finished_running():
        return (
            aws_client.stepfunctions.describe_execution(executionArn=execution_arn)["status"]
            != "RUNNING"
        )

    wait_until(_sfn_finished_running)

    execution_result = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"
    assert "hello from stepfunctions" in execution_result["output"]


@markers.aws.validated
def test_apigateway_invoke_with_path(deploy_cfn_template, aws_client):
    deploy_result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sfn_apigateway_two_integrations.yaml"
        )
    )
    state_machine_arn = deploy_result.outputs["statemachineOutput"]

    execution_arn = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)[
        "executionArn"
    ]

    def _sfn_finished_running():
        return (
            aws_client.stepfunctions.describe_execution(executionArn=execution_arn)["status"]
            != "RUNNING"
        )

    wait_until(_sfn_finished_running)

    execution_result = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"
    assert "hello_with_path from stepfunctions" in execution_result["output"]


@markers.aws.only_localstack
def test_apigateway_invoke_localhost(deploy_cfn_template, aws_client):
    """tests the same as above but with the "generic" localhost version of invoking the apigateway"""
    deploy_result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sfn_apigateway.yaml"
        )
    )
    state_machine_arn = deploy_result.outputs["statemachineOutput"]
    api_url = deploy_result.outputs["LsApiEndpointA06D37E8"]

    # instead of changing the template, we're just mapping the endpoint here to the more generic path-based version
    state_def = aws_client.stepfunctions.describe_state_machine(stateMachineArn=state_machine_arn)[
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

    aws_client.stepfunctions.update_state_machine(
        stateMachineArn=state_machine_arn, definition=json.dumps(state)
    )

    execution_arn = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)[
        "executionArn"
    ]

    def _sfn_finished_running():
        return (
            aws_client.stepfunctions.describe_execution(executionArn=execution_arn)["status"]
            != "RUNNING"
        )

    wait_until(_sfn_finished_running)

    execution_result = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"
    assert "hello from stepfunctions" in execution_result["output"]


@markers.aws.only_localstack
def test_apigateway_invoke_localhost_with_path(deploy_cfn_template, aws_client):
    """tests the same as above but with the "generic" localhost version of invoking the apigateway"""
    deploy_result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sfn_apigateway_two_integrations.yaml"
        )
    )
    state_machine_arn = deploy_result.outputs["statemachineOutput"]
    api_url = deploy_result.outputs["LsApiEndpointA06D37E8"]

    # instead of changing the template, we're just mapping the endpoint here to the more generic path-based version
    state_def = aws_client.stepfunctions.describe_state_machine(stateMachineArn=state_machine_arn)[
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

    aws_client.stepfunctions.update_state_machine(
        stateMachineArn=state_machine_arn, definition=json.dumps(state)
    )

    execution_arn = aws_client.stepfunctions.start_execution(stateMachineArn=state_machine_arn)[
        "executionArn"
    ]

    def _sfn_finished_running():
        return (
            aws_client.stepfunctions.describe_execution(executionArn=execution_arn)["status"]
            != "RUNNING"
        )

    wait_until(_sfn_finished_running)

    execution_result = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"
    assert "hello_with_path from stepfunctions" in execution_result["output"]


@pytest.mark.skip("Terminates with FAILED on cloud; convert to SFN v2 snapshot lambda test.")
@markers.aws.needs_fixing
def test_retry_and_catch(deploy_cfn_template, aws_client):
    """
    Scenario:

    Lambda invoke (incl. 3 retries)
        => catch (Send SQS message with body "Fail")
        => next (Send SQS message with body "Success")

    The Lambda function simply raises an Exception, so it will always fail.
    It should fail all 4 attempts (1x invoke + 3x retries) which should then trigger the catch path
    and send a "Fail" message to the queue.
    """

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sfn_retry_catch.yaml"
        )
    )
    queue_url = stack.outputs["queueUrlOutput"]
    statemachine_arn = stack.outputs["smArnOutput"]
    assert statemachine_arn

    execution = aws_client.stepfunctions.start_execution(stateMachineArn=statemachine_arn)
    execution_arn = execution["executionArn"]

    await_execution_terminated(aws_client.stepfunctions, execution_arn)

    execution_result = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
    assert execution_result["status"] == "SUCCEEDED"

    receive_result = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=5)
    assert receive_result["Messages"][0]["Body"] == "Fail"


@markers.aws.validated
def test_cfn_statemachine_with_dependencies(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/statemachine_test.json"
        ),
        max_wait=150,
    )

    rs = aws_client.stepfunctions.list_state_machines()
    sm_name = "SFSM22S5Y"
    statemachines = [sm for sm in rs["stateMachines"] if sm_name in sm["name"]]
    assert len(statemachines) == 1

    stack.destroy()

    rs = aws_client.stepfunctions.list_state_machines()
    statemachines = [sm for sm in rs["stateMachines"] if sm_name in sm["name"]]

    assert not statemachines
