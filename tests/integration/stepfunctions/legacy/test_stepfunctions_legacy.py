import json
import logging
import os

import pytest

from localstack.services.events.provider import TEST_EVENTS_CACHE
from localstack.services.stepfunctions.stepfunctions_utils import await_sfn_execution_result
from localstack.utils import testutil
from localstack.utils.aws import arns, aws_stack
from localstack.utils.files import load_file
from localstack.utils.json import clone
from localstack.utils.strings import short_uid
from localstack.utils.sync import ShortCircuitWaitException, retry, wait_until
from localstack.utils.threads import parallelize
from tests.integration.awslambda.functions import lambda_environment
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_ENV, TEST_LAMBDA_PYTHON_ECHO
from tests.integration.stepfunctions.utils import is_new_provider

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_NAME_1 = "lambda_sfn_1"
TEST_LAMBDA_NAME_2 = "lambda_sfn_2"
TEST_RESULT_VALUE = "testresult1"
TEST_RESULT_VALUE_2 = "testresult2"
TEST_RESULT_VALUE_4 = "testresult4"
STATE_MACHINE_BASIC = {
    "Comment": "Hello World example",
    "StartAt": "step1",
    "States": {
        "step1": {"Type": "Task", "Resource": "__tbd__", "Next": "step2"},
        "step2": {
            "Type": "Task",
            "Resource": "__tbd__",
            "ResultPath": "$.result_value",
            "End": True,
        },
    },
}
TEST_LAMBDA_NAME_3 = "lambda_map_sfn_3"
STATE_MACHINE_MAP = {
    "Comment": "Hello Map State",
    "StartAt": "ExampleMapState",
    "States": {
        "ExampleMapState": {
            "Type": "Map",
            "Iterator": {
                "StartAt": "CallLambda",
                "States": {"CallLambda": {"Type": "Task", "Resource": "__tbd__", "End": True}},
            },
            "End": True,
        }
    },
}
TEST_LAMBDA_NAME_4 = "lambda_choice_sfn_4"
STATE_MACHINE_CHOICE = {
    "StartAt": "CheckValues",
    "States": {
        "CheckValues": {
            "Type": "Choice",
            "Choices": [
                {
                    "And": [
                        {"Variable": "$.x", "IsPresent": True},
                        {"Variable": "$.y", "IsPresent": True},
                    ],
                    "Next": "Add",
                }
            ],
            "Default": "MissingValue",
        },
        "MissingValue": {"Type": "Fail", "Cause": "test"},
        "Add": {
            "Type": "Task",
            "Resource": "__tbd__",
            "ResultPath": "$.added",
            "TimeoutSeconds": 10,
            "End": True,
        },
    },
}
STATE_MACHINE_CATCH = {
    "StartAt": "Start",
    "States": {
        "Start": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {
                "FunctionName": "__tbd__",
                "Payload": {lambda_environment.MSG_BODY_RAISE_ERROR_FLAG: 1},
            },
            "Catch": [
                {
                    "ErrorEquals": [
                        "Exception",
                        "Lambda.Unknown",
                        "ValueError",
                    ],
                    "ResultPath": "$.error",
                    "Next": "ErrorHandler",
                }
            ],
            "Next": "Final",
        },
        "ErrorHandler": {
            "Type": "Task",
            "Resource": "__tbd__",
            "ResultPath": "$.handled",
            "Next": "Final",
        },
        "Final": {
            "Type": "Task",
            "Resource": "__tbd__",
            "ResultPath": "$.final",
            "End": True,
        },
    },
}
TEST_LAMBDA_NAME_5 = "lambda_intrinsic_sfn_5"
STATE_MACHINE_INTRINSIC_FUNCS = {
    "StartAt": "state0",
    "States": {
        "state0": {"Type": "Pass", "Result": {"v1": 1, "v2": "v2"}, "Next": "state1"},
        "state1": {
            "Type": "Pass",
            "Parameters": {
                "lambda_params": {
                    "FunctionName": "__tbd__",
                    "Payload": {"values.$": "States.Array($.v1, $.v2)"},
                }
            },
            "Next": "state2",
        },
        "state2": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {
                "FunctionName.$": "$.lambda_params.FunctionName",
                "Payload.$": "States.StringToJson(States.JsonToString($.lambda_params.Payload))",
            },
            "Next": "state3",
        },
        "state3": {
            "Type": "Task",
            "Resource": "__tbd__",
            "ResultSelector": {"payload.$": "$"},
            "ResultPath": "$.result_value",
            "End": True,
        },
    },
}
STATE_MACHINE_EVENTS = {
    "StartAt": "step1",
    "States": {
        "step1": {
            "Type": "Task",
            "Resource": "arn:aws:states:::events:putEvents",
            "Parameters": {
                "Entries": [
                    {
                        "DetailType": "TestMessage",
                        "Source": "TestSource",
                        "EventBusName": "__tbd__",
                        "Detail": {"Message": "Hello from Step Functions!"},
                    }
                ]
            },
            "End": True,
        },
    },
}

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def setup_and_tear_down():
    lambda_client = aws_stack.create_external_boto_client("lambda")

    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_ENV), get_content=True)
    zip_file2 = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
    testutil.create_lambda_function(
        func_name=TEST_LAMBDA_NAME_1,
        zip_file=zip_file,
        envvars={"Hello": TEST_RESULT_VALUE},
    )
    testutil.create_lambda_function(
        func_name=TEST_LAMBDA_NAME_2,
        zip_file=zip_file,
        envvars={"Hello": TEST_RESULT_VALUE_2},
    )
    testutil.create_lambda_function(
        func_name=TEST_LAMBDA_NAME_3,
        zip_file=zip_file,
        envvars={"Hello": "Replace Value"},
    )
    testutil.create_lambda_function(
        func_name=TEST_LAMBDA_NAME_4,
        zip_file=zip_file,
        envvars={"Hello": TEST_RESULT_VALUE_4},
    )
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_5, zip_file=zip_file2)

    active_waiter = lambda_client.get_waiter("function_active_v2")
    active_waiter.wait(FunctionName=TEST_LAMBDA_NAME_1)
    active_waiter.wait(FunctionName=TEST_LAMBDA_NAME_2)
    active_waiter.wait(FunctionName=TEST_LAMBDA_NAME_3)
    active_waiter.wait(FunctionName=TEST_LAMBDA_NAME_4)
    active_waiter.wait(FunctionName=TEST_LAMBDA_NAME_5)

    yield

    testutil.delete_lambda_function(name=TEST_LAMBDA_NAME_1)
    testutil.delete_lambda_function(name=TEST_LAMBDA_NAME_2)
    testutil.delete_lambda_function(name=TEST_LAMBDA_NAME_3)
    testutil.delete_lambda_function(name=TEST_LAMBDA_NAME_4)
    testutil.delete_lambda_function(name=TEST_LAMBDA_NAME_5)


@pytest.fixture
def sfn_execution_role(iam_client):
    role_name = f"role-{short_uid()}"
    result = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": {"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}}}',
    )
    return result["Role"]


def _assert_machine_instances(expected_instances, sfn_client):
    def check():
        state_machines_after = sfn_client.list_state_machines()["stateMachines"]
        assert expected_instances == len(state_machines_after)
        return state_machines_after

    return retry(check, sleep=1, retries=4)


def _get_execution_results(sm_arn, sfn_client):
    response = sfn_client.list_executions(stateMachineArn=sm_arn)
    executions = sorted(response["executions"], key=lambda x: x["startDate"])
    execution = executions[-1]
    result = sfn_client.get_execution_history(executionArn=execution["executionArn"])
    events = sorted(result["events"], key=lambda event: event["timestamp"])
    result = json.loads(events[-1]["executionSucceededEventDetails"]["output"])
    return result


def assert_machine_deleted(state_machines_before, sfn_client):
    return _assert_machine_instances(len(state_machines_before), sfn_client)


def assert_machine_created(state_machines_before, sfn_client):
    return _assert_machine_instances(len(state_machines_before) + 1, sfn_client=sfn_client)


def cleanup(sm_arn, state_machines_before, sfn_client):
    sfn_client.delete_state_machine(stateMachineArn=sm_arn)
    assert_machine_deleted(state_machines_before, sfn_client=sfn_client)


def get_machine_arn(sm_name, sfn_client):
    state_machines = sfn_client.list_state_machines()["stateMachines"]
    return [m["stateMachineArn"] for m in state_machines if m["name"] == sm_name][0]


pytestmark = pytest.mark.skipif(
    condition=is_new_provider(), reason="Test suite only for legacy provider."
)


@pytest.mark.usefixtures("setup_and_tear_down")
class TestStateMachine:
    def test_create_choice_state_machine(self, stepfunctions_client):
        state_machines_before = stepfunctions_client.list_state_machines()["stateMachines"]
        role_arn = arns.role_arn("sfn_role")

        definition = clone(STATE_MACHINE_CHOICE)
        lambda_arn_4 = arns.lambda_function_arn(TEST_LAMBDA_NAME_4)
        definition["States"]["Add"]["Resource"] = lambda_arn_4
        definition = json.dumps(definition)
        sm_name = f"choice-{short_uid()}"
        stepfunctions_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # assert that the SM has been created
        assert_machine_created(state_machines_before, stepfunctions_client)

        # run state machine
        sm_arn = get_machine_arn(sm_name, stepfunctions_client)
        input = {"x": "1", "y": "2"}
        result = stepfunctions_client.start_execution(
            stateMachineArn=sm_arn, input=json.dumps(input)
        )
        assert result.get("executionArn")

        # define expected output
        test_output = {**input, "added": {"Hello": TEST_RESULT_VALUE_4}}

        def check_result():
            result = _get_execution_results(sm_arn, stepfunctions_client)
            assert test_output == result

        # assert that the result is correct
        retry(check_result, sleep=2, retries=10)

        # clean up
        cleanup(sm_arn, state_machines_before, sfn_client=stepfunctions_client)

    def test_create_run_map_state_machine(self, stepfunctions_client):
        names = ["Bob", "Meg", "Joe"]
        test_input = [{"map": name} for name in names]
        test_output = [{"Hello": name} for name in names]
        state_machines_before = stepfunctions_client.list_state_machines()["stateMachines"]

        role_arn = arns.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_MAP)
        lambda_arn_3 = arns.lambda_function_arn(TEST_LAMBDA_NAME_3)
        definition["States"]["ExampleMapState"]["Iterator"]["States"]["CallLambda"][
            "Resource"
        ] = lambda_arn_3
        definition = json.dumps(definition)
        sm_name = f"map-{short_uid()}"
        stepfunctions_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # assert that the SM has been created
        assert_machine_created(state_machines_before, stepfunctions_client)

        # run state machine
        sm_arn = get_machine_arn(sm_name, stepfunctions_client)
        result = stepfunctions_client.start_execution(
            stateMachineArn=sm_arn, input=json.dumps(test_input)
        )
        assert result.get("executionArn")

        def check_invocations():
            # assert that the result is correct
            result = _get_execution_results(sm_arn, stepfunctions_client)
            assert test_output == result

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        cleanup(sm_arn, state_machines_before, stepfunctions_client)

    def test_create_run_state_machine(self, stepfunctions_client):
        state_machines_before = stepfunctions_client.list_state_machines()["stateMachines"]

        # create state machine
        role_arn = arns.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_BASIC)
        lambda_arn_1 = arns.lambda_function_arn(TEST_LAMBDA_NAME_1)
        lambda_arn_2 = arns.lambda_function_arn(TEST_LAMBDA_NAME_2)
        definition["States"]["step1"]["Resource"] = lambda_arn_1
        definition["States"]["step2"]["Resource"] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = f"basic-{short_uid()}"
        stepfunctions_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # assert that the SM has been created
        assert_machine_created(state_machines_before, stepfunctions_client)

        # run state machine
        sm_arn = get_machine_arn(sm_name, stepfunctions_client)
        result = stepfunctions_client.start_execution(stateMachineArn=sm_arn)
        assert result.get("executionArn")

        def check_invocations():
            # assert that the result is correct
            result = _get_execution_results(sm_arn, stepfunctions_client)
            assert {"Hello": TEST_RESULT_VALUE_2} == result["result_value"]

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=0.7, retries=25)

        # clean up
        cleanup(sm_arn, state_machines_before, stepfunctions_client)

    def test_try_catch_state_machine(self, stepfunctions_client):
        if os.environ.get("AWS_DEFAULT_REGION") != "us-east-1":
            pytest.skip("skipping non us-east-1 temporarily")

        state_machines_before = stepfunctions_client.list_state_machines()["stateMachines"]

        # create state machine
        role_arn = arns.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_CATCH)
        lambda_arn_1 = arns.lambda_function_arn(TEST_LAMBDA_NAME_1)
        lambda_arn_2 = arns.lambda_function_arn(TEST_LAMBDA_NAME_2)
        definition["States"]["Start"]["Parameters"]["FunctionName"] = lambda_arn_1
        definition["States"]["ErrorHandler"]["Resource"] = lambda_arn_2
        definition["States"]["Final"]["Resource"] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = f"catch-{short_uid()}"
        stepfunctions_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # run state machine
        sm_arn = get_machine_arn(sm_name, stepfunctions_client)
        result = stepfunctions_client.start_execution(stateMachineArn=sm_arn)
        assert result.get("executionArn")

        def check_invocations():
            # assert that the result is correct
            result = _get_execution_results(sm_arn, stepfunctions_client)
            assert {"Hello": TEST_RESULT_VALUE_2} == result.get("handled")

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        cleanup(sm_arn, state_machines_before, stepfunctions_client)

    def test_intrinsic_functions(self, stepfunctions_client):
        if os.environ.get("AWS_DEFAULT_REGION") != "us-east-1":
            pytest.skip("skipping non us-east-1 temporarily")

        state_machines_before = stepfunctions_client.list_state_machines()["stateMachines"]

        # create state machine
        role_arn = arns.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_INTRINSIC_FUNCS)
        lambda_arn_1 = arns.lambda_function_arn(TEST_LAMBDA_NAME_5)
        lambda_arn_2 = arns.lambda_function_arn(TEST_LAMBDA_NAME_5)
        if isinstance(definition["States"]["state1"].get("Parameters"), dict):
            definition["States"]["state1"]["Parameters"]["lambda_params"][
                "FunctionName"
            ] = lambda_arn_1
            definition["States"]["state3"]["Resource"] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = f"intrinsic-{short_uid()}"
        stepfunctions_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # run state machine
        sm_arn = get_machine_arn(sm_name, stepfunctions_client)
        input = {}
        result = stepfunctions_client.start_execution(
            stateMachineArn=sm_arn, input=json.dumps(input)
        )
        assert result.get("executionArn")

        def check_invocations():
            # assert that the result is correct
            result = _get_execution_results(sm_arn, stepfunctions_client)
            assert {"payload": {"values": [1, "v2"]}} == result.get("result_value")

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        cleanup(sm_arn, state_machines_before, stepfunctions_client)

    def test_events_state_machine(self, stepfunctions_client):
        events = aws_stack.create_external_boto_client("events")
        state_machines_before = stepfunctions_client.list_state_machines()["stateMachines"]

        # create event bus
        bus_name = f"bus-{short_uid()}"
        events.create_event_bus(Name=bus_name)

        # create state machine
        definition = clone(STATE_MACHINE_EVENTS)
        definition["States"]["step1"]["Parameters"]["Entries"][0]["EventBusName"] = bus_name
        definition = json.dumps(definition)
        sm_name = f"events-{short_uid()}"
        role_arn = arns.role_arn("sfn_role")
        stepfunctions_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # run state machine
        events_before = len(TEST_EVENTS_CACHE)
        sm_arn = get_machine_arn(sm_name, stepfunctions_client)
        result = stepfunctions_client.start_execution(stateMachineArn=sm_arn)
        assert result.get("executionArn")

        def check_invocations():
            # assert that the event is received
            assert events_before + 1 == len(TEST_EVENTS_CACHE)
            last_event = TEST_EVENTS_CACHE[-1]
            assert bus_name == last_event["EventBusName"]
            assert "TestSource" == last_event["Source"]
            assert "TestMessage" == last_event["DetailType"]
            assert {"Message": "Hello from Step Functions!"} == json.loads(last_event["Detail"])

        # assert that the event bus has received an event from the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        cleanup(sm_arn, state_machines_before, stepfunctions_client)
        events.delete_event_bus(Name=bus_name)

    def test_create_state_machines_in_parallel(self, stepfunctions_client, cleanups):
        """
        Perform a test that creates a series of state machines in parallel. Without concurrency control, using
        StepFunctions-Local, the following error is pretty consistently reproducible:

        botocore.errorfactory.InvalidDefinition: An error occurred (InvalidDefinition) when calling the
        CreateStateMachine operation: Invalid State Machine Definition: ''DUPLICATE_STATE_NAME: Duplicate State name:
        MissingValue at /States/MissingValue', 'DUPLICATE_STATE_NAME: Duplicate State name: Add at /States/Add''
        """
        role_arn = arns.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_CHOICE)
        lambda_arn_4 = arns.lambda_function_arn(TEST_LAMBDA_NAME_4)
        definition["States"]["Add"]["Resource"] = lambda_arn_4
        definition = json.dumps(definition)
        results = []

        def _create_sm(*_):
            sm_name = f"sm-{short_uid()}"
            result = stepfunctions_client.create_state_machine(
                name=sm_name, definition=definition, roleArn=role_arn
            )
            assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
            cleanups.append(
                lambda: stepfunctions_client.delete_state_machine(
                    stateMachineArn=result["stateMachineArn"]
                )
            )
            results.append(result)
            stepfunctions_client.describe_state_machine(stateMachineArn=result["stateMachineArn"])
            stepfunctions_client.list_tags_for_resource(resourceArn=result["stateMachineArn"])

        num_machines = 30
        parallelize(_create_sm, list(range(num_machines)), size=2)
        assert len(results) == num_machines


TEST_STATE_MACHINE = {
    "StartAt": "s0",
    "States": {"s0": {"Type": "Pass", "Result": {}, "End": True}},
}

TEST_STATE_MACHINE_2 = {
    "StartAt": "s1",
    "States": {
        "s1": {
            "Type": "Task",
            "Resource": "arn:aws:states:::states:startExecution.sync",
            "Parameters": {
                "Input": {"Comment": "Hello world!"},
                "StateMachineArn": "__machine_arn__",
                "Name": "ExecutionName",
            },
            "End": True,
        }
    },
}

TEST_STATE_MACHINE_3 = {
    "StartAt": "s1",
    "States": {
        "s1": {
            "Type": "Task",
            "Resource": "arn:aws:states:::states:startExecution.sync",
            "Parameters": {
                "Input": {"Comment": "Hello world!"},
                "StateMachineArn": "__machine_arn__",
                "Name": "ExecutionName",
            },
            "End": True,
        }
    },
}

STS_ROLE_POLICY_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": ["states.amazonaws.com"]},
            "Action": "sts:AssumeRole",
        }
    ],
}


@pytest.mark.parametrize("region_name", ("us-east-1", "us-east-2", "eu-west-1", "eu-central-1"))
@pytest.mark.parametrize("statemachine_definition", (TEST_STATE_MACHINE_3,))  # TODO: add sync2 test
def test_multiregion_nested(region_name, statemachine_definition):
    client1 = aws_stack.create_external_boto_client("stepfunctions", region_name=region_name)
    # create state machine
    child_machine_name = f"sf-child-{short_uid()}"
    role = arns.role_arn("sfn_role")
    child_machine_result = client1.create_state_machine(
        name=child_machine_name, definition=json.dumps(TEST_STATE_MACHINE), roleArn=role
    )
    child_machine_arn = child_machine_result["stateMachineArn"]

    # create parent state machine
    name = f"sf-parent-{short_uid()}"
    role = arns.role_arn("sfn_role")
    result = client1.create_state_machine(
        name=name,
        definition=json.dumps(statemachine_definition).replace(
            "__machine_arn__", child_machine_arn
        ),
        roleArn=role,
    )
    machine_arn = result["stateMachineArn"]
    try:
        # list state machine
        result = client1.list_state_machines()["stateMachines"]
        assert len(result) > 0
        assert len([sm for sm in result if sm["name"] == name]) == 1
        assert len([sm for sm in result if sm["name"] == child_machine_name]) == 1

        # start state machine execution
        result = client1.start_execution(stateMachineArn=machine_arn)

        execution = client1.describe_execution(executionArn=result["executionArn"])
        assert execution["stateMachineArn"] == machine_arn
        assert execution["status"] in ["RUNNING", "SUCCEEDED"]

        def assert_success():
            return (
                client1.describe_execution(executionArn=result["executionArn"])["status"]
                == "SUCCEEDED"
            )

        wait_until(assert_success)

        result = client1.describe_state_machine_for_execution(executionArn=result["executionArn"])
        assert result["stateMachineArn"] == machine_arn

    finally:
        client1.delete_state_machine(stateMachineArn=machine_arn)
        client1.delete_state_machine(stateMachineArn=child_machine_arn)


@pytest.mark.aws_validated
def test_default_logging_configuration(iam_client, create_state_machine, stepfunctions_client):
    role_name = f"role_name-{short_uid()}"
    try:
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(STS_ROLE_POLICY_DOC),
        )["Role"]["Arn"]

        definition = clone(TEST_STATE_MACHINE)
        definition = json.dumps(definition)

        sm_name = f"sts-logging-{short_uid()}"
        result = create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)

        assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
        result = stepfunctions_client.describe_state_machine(
            stateMachineArn=result["stateMachineArn"]
        )
        assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert result["loggingConfiguration"] == {"level": "OFF", "includeExecutionData": False}
    finally:
        iam_client.delete_role(RoleName=role_name)


def test_aws_sdk_task(sfn_execution_role, stepfunctions_client, iam_client, sns_client):
    statemachine_definition = {
        "StartAt": "CreateTopicTask",
        "States": {
            "CreateTopicTask": {
                "End": True,
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sns:createTopic",
                "Parameters": {"Name.$": "$.Name"},
            }
        },
    }

    # create parent state machine
    name = f"statemachine-{short_uid()}"
    policy_name = f"policy-{short_uid()}"
    topic_name = f"topic-{short_uid()}"

    policy = iam_client.create_policy(
        PolicyDocument='{"Version": "2012-10-17", "Statement": {"Action": "sns:createTopic", "Effect": "Allow", "Resource": "*"}}',
        PolicyName=policy_name,
    )
    iam_client.attach_role_policy(
        RoleName=sfn_execution_role["RoleName"], PolicyArn=policy["Policy"]["Arn"]
    )

    result = stepfunctions_client.create_state_machine(
        name=name,
        definition=json.dumps(statemachine_definition),
        roleArn=sfn_execution_role["Arn"],
    )
    machine_arn = result["stateMachineArn"]

    try:
        result = stepfunctions_client.list_state_machines()["stateMachines"]
        assert len(result) > 0
        assert len([sm for sm in result if sm["name"] == name]) == 1

        def assert_execution_success(executionArn: str):
            def _assert_execution_success():
                status = stepfunctions_client.describe_execution(executionArn=executionArn)[
                    "status"
                ]
                if status == "FAILED":
                    raise ShortCircuitWaitException("Statemachine execution failed")
                else:
                    return status == "SUCCEEDED"

            return _assert_execution_success

        def _retry_execution():
            # start state machine execution
            # AWS initially straight up fails until the permissions seem to take effect
            # so we wait until the statemachine is at least running
            result = stepfunctions_client.start_execution(
                stateMachineArn=machine_arn, input='{"Name": "' f"{topic_name}" '"}'
            )
            assert wait_until(assert_execution_success(result["executionArn"]))
            describe_result = stepfunctions_client.describe_execution(
                executionArn=result["executionArn"]
            )
            output = describe_result["output"]
            assert topic_name in output
            result = stepfunctions_client.describe_state_machine_for_execution(
                executionArn=result["executionArn"]
            )
            assert result["stateMachineArn"] == machine_arn
            topic_arn = json.loads(describe_result["output"])["TopicArn"]
            topics = sns_client.list_topics()
            assert topic_arn in [t["TopicArn"] for t in topics["Topics"]]
            sns_client.delete_topic(TopicArn=topic_arn)
            return True

        assert wait_until(_retry_execution, max_retries=3, strategy="linear", wait=3.0)

    finally:
        iam_client.delete_policy(PolicyArn=policy["Policy"]["Arn"])
        stepfunctions_client.delete_state_machine(stateMachineArn=machine_arn)


def test_aws_sdk_task_delete_s3_object(
    stepfunctions_client, s3_bucket, iam_client, sns_client, s3_client, sfn_execution_role
):
    s3_key = "test-key"
    statemachine_definition = {
        "StartAt": "CreateTopicTask",
        "States": {
            "CreateTopicTask": {
                "Type": "Task",
                "Parameters": {"Bucket": s3_bucket, "Key": s3_key},
                "Resource": "arn:aws:states:::aws-sdk:s3:deleteObject",
                "End": True,
            }
        },
    }

    # create state machine
    s3_client.put_object(Bucket=s3_bucket, Key=s3_key, Body=b"")
    name = f"statemachine-{short_uid()}"

    result = stepfunctions_client.create_state_machine(
        name=name,
        definition=json.dumps(statemachine_definition),
        roleArn=sfn_execution_role["Arn"],
    )
    machine_arn = result["stateMachineArn"]

    result = stepfunctions_client.start_execution(stateMachineArn=machine_arn, input="{}")
    execution_arn = result["executionArn"]

    await_sfn_execution_result(execution_arn)

    with pytest.raises(Exception) as exc:
        s3_client.head_object(Bucket=s3_bucket, Key=s3_key)
    assert "Not Found" in str(exc)
