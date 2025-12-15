import json
from datetime import datetime
from typing import Final

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.context_object.context_object_templates import (
    ContextObjectTemplates,
)
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)

TEST_STATE_NAME: Final[str] = "TestState"

_CONTEXT_OBJECT_FULL: Final[dict] = {
    "Execution": {
        "Id": "arn:aws:states:::execution:MyStateMachine:execution-name-12345",
        "Input": {
            "input-value": 0,
            "message": "test data",
            "values": ["charizard", "pikachu", "bulbasaur"],
        },
        "Name": "execution-name-12345",
        "RoleArn": "arn:aws:iam:::role/StepFunctionsRole",
        "StartTime": "2025-01-15T10:30:00.000Z",
    },
    "State": {
        "EnteredTime": "2025-01-15T10:30:01.500Z",
        "Name": "MyTaskState",
        "RetryCount": 0,
    },
    "StateMachine": {
        "Id": "arn:aws:states:::stateMachine:MyStateMachine",
        "Name": "MyStateMachine",
    },
    # Context object contains 'Task' when state is not a Task state with a '.sync' or '.waitForTaskToken' service integration pattern
    # "Task": {
    #     "Token": "AAAAKgAAAAIAAAAAAAAAAZGexGPEB9DwXS+Bz/bGmUq4hN8v7X3LKnKj0p1qJ7qL4d5kF2gH3iJ4jK5lM6nN7oO8pP9qQ0rR1sS2tT3uU4vV5wW6xX7yY8zZ9aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9kK0lL1mM2nN3oO4pP5qQ6rR7sS8tT9uU0vV1wW2xX3yY4zZ5"
    # },
    # Invalid Context object provided: 'Map' field is not supported when mocking a Context object
    # "Map": {
    #     "Item": {"Index": 2, "Value": {"id": "item-3", "name": "Third Item", "quantity": 15}}
    # },
}

CONTEXT_OBJECT_FULL: Final[str] = json.dumps(_CONTEXT_OBJECT_FULL)

TASK_CONTEXT_OBJECT_FULL: Final[str] = json.dumps(
    _CONTEXT_OBJECT_FULL | {"Task": {"Token": "abcd123"}}
)

BASE_CONTEXT_OBJECT_BINDINGS: list[str] = ["$$", "$$.Execution.Input", "$$.Execution.Input.values"]

IDS_BASE_CONTEXT_OBJECT_BINDINGS: list[str] = ["ALL", "EXECUTION_INPUT", "EXECUTION_INPUT_VALUES"]


class TestStateContextObject:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "context_object_literal", BASE_CONTEXT_OBJECT_BINDINGS, ids=IDS_BASE_CONTEXT_OBJECT_BINDINGS
    )
    def test_state_task_context_object(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        context_object_literal,
    ):
        state_machine_template = ContextObjectTemplates.load_sfn_template(
            ContextObjectTemplates.CONTEXT_OBJECT_RESULT_PATH
        )

        state_template = state_machine_template["States"][TEST_STATE_NAME]

        definition = json.dumps(state_template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER, context_object_literal
        )

        exec_input = json.dumps(
            {"FunctionName": "lambda_function_name", "Payload": {"input-value": 0}}
        )
        mocked_result = json.dumps({"pokemon": ["charizard", "pikachu", "bulbasaur"]})

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
            context=CONTEXT_OBJECT_FULL,
            mock={"result": mocked_result},
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    def test_state_wait_task_context_object(
        self,
        aws_client_no_sync_prefix,
        account_id,
        region_name,
        sfn_snapshot,
    ):
        state_template = TST.load_sfn_template(
            TST.IO_SQS_SERVICE_TASK_WAIT,
        )

        sqs_queue_url = f"https://sqs.{region_name}.amazonaws.com/{account_id}/test-queue"
        state_template["Parameters"]["QueueUrl"] = sqs_queue_url

        definition = json.dumps(state_template)
        mocked_result = json.dumps({"pokemon": ["charizard", "pikachu", "bulbasaur"]})

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            inspectionLevel=InspectionLevel.TRACE,
            context=TASK_CONTEXT_OBJECT_FULL,
            mock={"result": mocked_result},
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "context_object_literal",
        BASE_CONTEXT_OBJECT_BINDINGS,
        ids=IDS_BASE_CONTEXT_OBJECT_BINDINGS,
    )
    @pytest.mark.skipif(not is_aws_cloud(), reason="Error messages are different")
    def test_state_map_context_object(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        context_object_literal,
    ):
        state_machine_template = ContextObjectTemplates.load_sfn_template(
            ContextObjectTemplates.CONTEXT_OBJECT_ITEMS_PATH
        )

        state_template = state_machine_template["States"][TEST_STATE_NAME]

        definition = json.dumps(state_template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER, context_object_literal
        )

        exec_input = json.dumps(["fire", "electricity", "grass"])
        mocked_result = json.dumps(["CHARIZARD", "PIKACHU", "BULBASAUR"])

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
            context=CONTEXT_OBJECT_FULL,
            mock={"result": mocked_result},
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "state_template,context_template",
        [
            (ContextObjectTemplates.CONTEXT_OBJECT_RESULT_PATH, TASK_CONTEXT_OBJECT_FULL),
            (ContextObjectTemplates.CONTEXT_OBJECT_INPUT_PATH, CONTEXT_OBJECT_FULL),
        ],
        ids=["TOKEN_TASK_NOT_SYNC", "INVALID_STATE_PASS"],
    )
    @pytest.mark.skipif(condition=not is_aws_cloud(), reason="Failure cases not yet handled.")
    def test_state_context_object_invalid_states(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        state_template,
        context_template,
    ):
        state_machine_template = ContextObjectTemplates.load_sfn_template(state_template)

        state_template = state_machine_template["States"][TEST_STATE_NAME]

        definition = json.dumps(state_template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER, "$$"
        )

        exec_input = json.dumps(["fire", "electricity", "grass"])
        mocked_result = json.dumps({"pokemon": ["CHARIZARD", "PIKACHU", "BULBASAUR"]})

        with pytest.raises(ClientError) as exc:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.TRACE,
                context=context_template,
                mock={"result": mocked_result},
            )
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "context_template",
        [
            {"Execution": {"Id": 1}},
            {"Map": {}},
            {"Execution": {"pokemon": "squirtle"}},
            {"Pokedex": {}},
        ],
        ids=[
            "INVALID_EXECUTION_ID_TYPE",
            "INVALID_MAP",
            "INVALID_EXECUTION_FIELD",
            "INVALID_FIELD",
        ],
    )
    def test_state_context_object_validation_failures(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        context_template,
    ):
        context_object = json.dumps(context_template)

        state_template = TST.load_sfn_template(
            TST.BASE_SFN_START_EXECUTION_TASK_STATE,
        )
        definition = json.dumps(state_template)

        exec_input = json.dumps(
            {"stateMachineArn": "arn", "targetInput": None, "name": "exec_name"}
        )

        result = {"ExecutionArn": "exec_arn", "StartDate": datetime.now().isoformat()}
        mocked_result = json.dumps(result)

        with pytest.raises(ClientError) as exc:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.TRACE,
                context=context_object,
                mock={"result": mocked_result},
            )

        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "context_template",
        [
            {"Execution": {}, "State": {}, "StateMachine": {}},
            pytest.param(
                {},
                marks=pytest.mark.skipif(
                    not is_aws_cloud(), reason="Empty context case is not properly accounted for."
                ),
            ),
        ],
        ids=[
            "EMPTY_OBJECTS",
            "EMPTY",
        ],
    )
    def test_state_context_object_edge_cases(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        context_template,
    ):
        context_object = json.dumps(context_template)

        state_machine_template = ContextObjectTemplates.load_sfn_template(
            ContextObjectTemplates.CONTEXT_OBJECT_RESULT_PATH
        )

        state_template = state_machine_template["States"][TEST_STATE_NAME]

        definition = json.dumps(state_template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER, "$$"
        )

        exec_input = json.dumps(
            {"FunctionName": "lambda_function_name", "Payload": {"input-value": 0}}
        )

        mocked_result = json.dumps({"pokemon": "pikachu"})

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
            context=context_object,
            mock={"result": mocked_result},
        )
        sfn_snapshot.match("test_case_response", test_case_response)
