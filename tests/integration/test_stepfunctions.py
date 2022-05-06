import json
import os
import unittest

import pytest

from localstack.services.awslambda import lambda_api
from localstack.services.events.provider import TEST_EVENTS_CACHE
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import clone, load_file, retry, short_uid
from localstack.utils.generic.wait_utils import ShortCircuitWaitException, wait_until

from .awslambda.functions import lambda_environment
from .awslambda.test_lambda import TEST_LAMBDA_ENV, TEST_LAMBDA_PYTHON_ECHO

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_NAME_1 = "lambda_sfn_1"
TEST_LAMBDA_NAME_2 = "lambda_sfn_2"
TEST_RESULT_VALUE = "testresult1"
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


class TestStateMachine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lambda_client = aws_stack.create_external_boto_client("lambda")
        cls.s3_client = aws_stack.create_external_boto_client("s3")
        cls.sfn_client = aws_stack.create_external_boto_client("stepfunctions")

        zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_ENV), get_content=True)
        zip_file2 = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_1,
            zip_file=zip_file,
            envvars={"Hello": TEST_RESULT_VALUE},
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_2,
            zip_file=zip_file,
            envvars={"Hello": TEST_RESULT_VALUE},
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_3,
            zip_file=zip_file,
            envvars={"Hello": "Replace Value"},
        )
        testutil.create_lambda_function(
            func_name=TEST_LAMBDA_NAME_4,
            zip_file=zip_file,
            envvars={"Hello": TEST_RESULT_VALUE},
        )
        testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_5, zip_file=zip_file2)

    @classmethod
    def tearDownClass(cls):
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_1)
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_2)
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_3)
        cls.lambda_client.delete_function(FunctionName=TEST_LAMBDA_NAME_4)

    def test_create_choice_state_machine(self):
        state_machines_before = self.sfn_client.list_state_machines()["stateMachines"]
        role_arn = aws_stack.role_arn("sfn_role")

        definition = clone(STATE_MACHINE_CHOICE)
        lambda_arn_4 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_4)
        definition["States"]["Add"]["Resource"] = lambda_arn_4
        definition = json.dumps(definition)
        sm_name = "choice-%s" % short_uid()
        result = self.sfn_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # assert that the SM has been created
        self.assert_machine_created(state_machines_before)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        input = {"x": "1", "y": "2"}
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn, input=json.dumps(input))
        self.assertTrue(result.get("executionArn"))

        # define expected output
        test_output = {**input, "added": {"Hello": TEST_RESULT_VALUE}}

        def check_result():
            result = self._get_execution_results(sm_arn)
            self.assertEqual(test_output, result)

        # assert that the result is correct
        retry(check_result, sleep=2, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_create_run_map_state_machine(self):
        names = ["Bob", "Meg", "Joe"]
        test_input = [{"map": name} for name in names]
        test_output = [{"Hello": name} for name in names]
        state_machines_before = self.sfn_client.list_state_machines()["stateMachines"]

        role_arn = aws_stack.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_MAP)
        lambda_arn_3 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_3)
        definition["States"]["ExampleMapState"]["Iterator"]["States"]["CallLambda"][
            "Resource"
        ] = lambda_arn_3
        definition = json.dumps(definition)
        sm_name = "map-%s" % short_uid()
        _ = self.sfn_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # assert that the SM has been created
        self.assert_machine_created(state_machines_before)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        lambda_api.LAMBDA_EXECUTOR.function_invoke_times.clear()
        result = self.sfn_client.start_execution(
            stateMachineArn=sm_arn, input=json.dumps(test_input)
        )
        self.assertTrue(result.get("executionArn"))

        def check_invocations():
            self.assertIn(lambda_arn_3, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            # assert that the result is correct
            result = self._get_execution_results(sm_arn)
            self.assertEqual(test_output, result)

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_create_run_state_machine(self):
        state_machines_before = self.sfn_client.list_state_machines()["stateMachines"]

        # create state machine
        role_arn = aws_stack.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_BASIC)
        lambda_arn_1 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_1)
        lambda_arn_2 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_2)
        definition["States"]["step1"]["Resource"] = lambda_arn_1
        definition["States"]["step2"]["Resource"] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = "basic-%s" % short_uid()
        result = self.sfn_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # assert that the SM has been created
        self.assert_machine_created(state_machines_before)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        lambda_api.LAMBDA_EXECUTOR.function_invoke_times.clear()
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn)
        self.assertTrue(result.get("executionArn"))

        def check_invocations():
            self.assertIn(lambda_arn_1, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            self.assertIn(lambda_arn_2, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            # assert that the result is correct
            result = self._get_execution_results(sm_arn)
            self.assertEqual({"Hello": TEST_RESULT_VALUE}, result["result_value"])

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=0.7, retries=25)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_try_catch_state_machine(self):
        if os.environ.get("AWS_DEFAULT_REGION") != "us-east-1":
            pytest.skip("skipping non us-east-1 temporarily")

        state_machines_before = self.sfn_client.list_state_machines()["stateMachines"]

        # create state machine
        role_arn = aws_stack.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_CATCH)
        lambda_arn_1 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_1)
        lambda_arn_2 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_2)
        definition["States"]["Start"]["Parameters"]["FunctionName"] = lambda_arn_1
        definition["States"]["ErrorHandler"]["Resource"] = lambda_arn_2
        definition["States"]["Final"]["Resource"] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = "catch-%s" % short_uid()
        result = self.sfn_client.create_state_machine(
            name=sm_name, definition=definition, roleArn=role_arn
        )

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        lambda_api.LAMBDA_EXECUTOR.function_invoke_times.clear()
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn)
        self.assertTrue(result.get("executionArn"))

        def check_invocations():
            self.assertIn(lambda_arn_1, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            self.assertIn(lambda_arn_2, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            # assert that the result is correct
            result = self._get_execution_results(sm_arn)
            self.assertEqual({"Hello": TEST_RESULT_VALUE}, result.get("handled"))

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_intrinsic_functions(self):
        if os.environ.get("AWS_DEFAULT_REGION") != "us-east-1":
            pytest.skip("skipping non us-east-1 temporarily")

        state_machines_before = self.sfn_client.list_state_machines()["stateMachines"]

        # create state machine
        role_arn = aws_stack.role_arn("sfn_role")
        definition = clone(STATE_MACHINE_INTRINSIC_FUNCS)
        lambda_arn_1 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_5)
        lambda_arn_2 = aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_5)
        if isinstance(definition["States"]["state1"].get("Parameters"), dict):
            definition["States"]["state1"]["Parameters"]["lambda_params"][
                "FunctionName"
            ] = lambda_arn_1
            definition["States"]["state3"]["Resource"] = lambda_arn_2
        definition = json.dumps(definition)
        sm_name = "intrinsic-%s" % short_uid()
        self.sfn_client.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)

        # run state machine
        sm_arn = self.get_machine_arn(sm_name)
        lambda_api.LAMBDA_EXECUTOR.function_invoke_times.clear()
        input = {}
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn, input=json.dumps(input))
        self.assertTrue(result.get("executionArn"))

        def check_invocations():
            self.assertIn(lambda_arn_1, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            self.assertIn(lambda_arn_2, lambda_api.LAMBDA_EXECUTOR.function_invoke_times)
            # assert that the result is correct
            result = self._get_execution_results(sm_arn)
            self.assertEqual({"payload": {"values": [1, "v2"]}}, result.get("result_value"))

        # assert that the lambda has been invoked by the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)

    def test_events_state_machine(self):
        events = aws_stack.create_external_boto_client("events")
        state_machines_before = self.sfn_client.list_state_machines()["stateMachines"]

        # create event bus
        bus_name = f"bus-{short_uid()}"
        events.create_event_bus(Name=bus_name)

        # create state machine
        definition = clone(STATE_MACHINE_EVENTS)
        definition["States"]["step1"]["Parameters"]["Entries"][0]["EventBusName"] = bus_name
        definition = json.dumps(definition)
        sm_name = "events-%s" % short_uid()
        role_arn = aws_stack.role_arn("sfn_role")
        self.sfn_client.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)

        # run state machine
        events_before = len(TEST_EVENTS_CACHE)
        sm_arn = self.get_machine_arn(sm_name)
        result = self.sfn_client.start_execution(stateMachineArn=sm_arn)
        self.assertTrue(result.get("executionArn"))

        def check_invocations():
            # assert that the event is received
            self.assertEqual(events_before + 1, len(TEST_EVENTS_CACHE))
            last_event = TEST_EVENTS_CACHE[-1]
            self.assertEqual(bus_name, last_event["EventBusName"])
            self.assertEqual("TestSource", last_event["Source"])
            self.assertEqual("TestMessage", last_event["DetailType"])
            self.assertEqual(
                {"Message": "Hello from Step Functions!"}, json.loads(last_event["Detail"])
            )

        # assert that the event bus has received an event from the SM execution
        retry(check_invocations, sleep=1, retries=10)

        # clean up
        self.cleanup(sm_arn, state_machines_before)
        events.delete_event_bus(Name=bus_name)

    # -----------------
    # HELPER FUNCTIONS
    # -----------------

    def get_machine_arn(self, sm_name):
        state_machines = self.sfn_client.list_state_machines()["stateMachines"]
        return [m["stateMachineArn"] for m in state_machines if m["name"] == sm_name][0]

    def assert_machine_created(self, state_machines_before):
        return self._assert_machine_instances(len(state_machines_before) + 1)

    def assert_machine_deleted(self, state_machines_before):
        return self._assert_machine_instances(len(state_machines_before))

    def cleanup(self, sm_arn, state_machines_before):
        self.sfn_client.delete_state_machine(stateMachineArn=sm_arn)
        self.assert_machine_deleted(state_machines_before)

    def _assert_machine_instances(self, expected_instances):
        def check():
            state_machines_after = self.sfn_client.list_state_machines()["stateMachines"]
            self.assertEqual(expected_instances, len(state_machines_after))
            return state_machines_after

        return retry(check, sleep=1, retries=4)

    def _get_execution_results(self, sm_arn):
        response = self.sfn_client.list_executions(stateMachineArn=sm_arn)
        executions = sorted(response["executions"], key=lambda x: x["startDate"])
        execution = executions[-1]
        result = self.sfn_client.get_execution_history(executionArn=execution["executionArn"])
        events = sorted(result["events"], key=lambda event: event["timestamp"])
        result = json.loads(events[-1]["executionSucceededEventDetails"]["output"])
        return result


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


@pytest.mark.parametrize("region_name", ("us-east-1", "us-east-2", "eu-west-1", "eu-central-1"))
@pytest.mark.parametrize("statemachine_definition", (TEST_STATE_MACHINE_3,))  # TODO: add sync2 test
def test_multiregion_nested(region_name, statemachine_definition):
    client1 = aws_stack.create_external_boto_client("stepfunctions", region_name=region_name)
    # create state machine
    child_machine_name = f"sf-child-{short_uid()}"
    role = aws_stack.role_arn("sfn_role")
    child_machine_result = client1.create_state_machine(
        name=child_machine_name, definition=json.dumps(TEST_STATE_MACHINE), roleArn=role
    )
    child_machine_arn = child_machine_result["stateMachineArn"]

    # create parent state machine
    name = f"sf-parent-{short_uid()}"
    role = aws_stack.role_arn("sfn_role")
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


def test_aws_sdk_task(stepfunctions_client, iam_client, sns_client):
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
    role_name = f"role-{short_uid()}"
    topic_name = f"topic-{short_uid()}"

    role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": {"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}}}',
    )
    policy = iam_client.create_policy(
        PolicyDocument='{"Version": "2012-10-17", "Statement": {"Action": "sns:createTopic", "Effect": "Allow", "Resource": "*"}}',
        PolicyName=policy_name,
    )
    iam_client.attach_role_policy(
        RoleName=role["Role"]["RoleName"], PolicyArn=policy["Policy"]["Arn"]
    )

    result = stepfunctions_client.create_state_machine(
        name=name,
        definition=json.dumps(statemachine_definition),
        roleArn=role["Role"]["Arn"],
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
        iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy["Policy"]["Arn"])
        iam_client.delete_role(RoleName=role_name)
        iam_client.delete_policy(PolicyArn=policy["Policy"]["Arn"])
        stepfunctions_client.delete_state_machine(stateMachineArn=machine_arn)
