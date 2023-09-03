import aws_cdk as cdk
import aws_cdk.aws_events as events
import aws_cdk.aws_events_targets as targets
import aws_cdk.aws_stepfunctions as sfn
import aws_cdk.aws_stepfunctions_tasks as tasks
import pytest

from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner
from tests.aws.services.stepfunctions.utils import await_execution_terminated

FN_CODE = """
import boto3
import os
import json

def _get_sfn_client():
    if "LOCALSTACK_HOSTNAME" in os.environ:
        endpoint_url = f"http://{os.environ['LOCALSTACK_HOSTNAME']}:{os.environ['EDGE_PORT']}"
        return boto3.client("stepfunctions", endpoint_url=endpoint_url)
    else:
        return boto3.client("stepfunctions")

def _get_task_token(event):
    return event["detail"]["token"]

def handler(event, ctx):
    print(event)
    print("Getting client")
    sfn_client = _get_sfn_client()
    print("Getting token")
    task_token = _get_task_token(event)
    sfn_client.send_task_success(taskToken=task_token, output=json.dumps({"hello": "world"}))
"""


class TestTaskServiceEvents:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        """

        Task => EventBridge (async) => lambda (sends success or failure) => end

        """
        app = cdk.App()
        stack = cdk.Stack(app, "TestSfnEventsStack")

        # auxilliary resources
        event_bus = events.EventBus(stack, "bus")
        fn = cdk.aws_lambda.Function(
            stack,
            "fn",
            runtime=cdk.aws_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(FN_CODE),
        )
        # rule that forwards the message to the lambda function, so it can send a success signal back to sfn
        events.Rule(
            stack,
            "rule",
            event_bus=event_bus,
            targets=[targets.LambdaFunction(fn)],
            event_pattern=events.EventPattern(detail_type=["test_sfn_events"]),
        )

        # state machine setup
        run_task = tasks.EventBridgePutEvents(
            stack,
            "ecstask",
            integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            entries=[
                tasks.EventBridgePutEventsEntry(
                    detail_type="test_sfn_events",
                    detail=sfn.TaskInput.from_object({"token": sfn.JsonPath.task_token}),
                    event_bus=event_bus,
                    source="me",
                )
            ],
        )
        statemachine = sfn.StateMachine(stack, "statemachine", definition=run_task)
        statemachine.grant_task_response(fn)

        # stack outputs
        cdk.CfnOutput(stack, "StateMachineArn", value=statemachine.state_machine_arn)
        cdk.CfnOutput(stack, "EventBusName", value=event_bus.event_bus_name)
        cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)

        # provisioning
        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        with provisioner.provisioner(skip_teardown=True) as prov:
            yield prov

    # TODO: snapshot
    @markers.aws.validated
    def test_run_machine(self, aws_client, infrastructure):
        sm_arn = infrastructure.get_stack_outputs(stack_name="TestSfnEventsStack")[
            "StateMachineArn"
        ]
        execution_arn = aws_client.stepfunctions.start_execution(stateMachineArn=sm_arn)[
            "executionArn"
        ]
        await_execution_terminated(aws_client.stepfunctions, execution_arn)
        assert (
            aws_client.stepfunctions.describe_execution(executionArn=execution_arn)["status"]
            == "SUCCEEDED"
        )
