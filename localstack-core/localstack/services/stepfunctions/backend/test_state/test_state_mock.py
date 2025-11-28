import copy
import json
from typing import Final

from pydantic import (
    ValidationError,
)

from localstack.aws.api.stepfunctions import (
    HistoryEventType,
    MockInput,
    TaskFailedEventDetails,
    TestStateConfiguration,
)
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.state.state_type import StateType
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.states import (
    ContextObjectData,
)
from localstack.services.stepfunctions.test_state.mock_config import (
    TestStateContextObjectValidator,
    TestStateMockedResponse,
    TestStateResponseReturn,
    TestStateResponseThrow,
)


def eval_mocked_response_throw(env: Environment, mocked_response: TestStateResponseThrow) -> None:
    task_failed_event_details = TaskFailedEventDetails(
        error=mocked_response.error, cause=mocked_response.cause
    )
    error_name = ErrorName(mocked_response.error)
    failure_event = FailureEvent(
        env=env,
        error_name=error_name,
        event_type=HistoryEventType.TaskFailed,  # TODO(gregfurman): Should this be state specific?
        event_details=EventDetails(taskFailedEventDetails=task_failed_event_details),
    )
    raise FailureEventException(failure_event=failure_event)


class TestStateMock:
    _mock_input: MockInput | None
    _state_configuration: TestStateConfiguration | None
    _result_stack: Final[list[TestStateMockedResponse]]
    _context: Final[ContextObjectData | None]

    def __init__(
        self,
        mock_input: MockInput | None,
        state_configuration: TestStateConfiguration | None,
        context: str | None,
    ):
        self._mock_input = mock_input
        self._state_configuration = state_configuration
        self._result_stack = []
        self._context = None

        if not mock_input:
            return

        self._context = None if context is None else self.parse_context(context)

        if mock_result_raw := mock_input.get("result"):
            mock = json.loads(mock_result_raw)
            self._result_stack.append(TestStateResponseReturn(mock))
            return

        if mock_error_output := mock_input.get("errorOutput"):
            mock = copy.deepcopy(mock_error_output)
            self._result_stack.append(TestStateResponseThrow(**mock))
            return

    def is_mocked(self):
        if self._mock_input or self._state_configuration:
            return True

        return False

    def add_result(self, result: TestStateMockedResponse):
        mock = copy.deepcopy(result)
        self._result_stack.append(mock)

    def get_next_result(self) -> TestStateMockedResponse:
        if not self._result_stack:
            return None
        return self._result_stack.pop()

    def get_context(self) -> ContextObjectData | None:
        if self._context is not None:
            return copy.deepcopy(self._context)
        return None

    @staticmethod
    def parse_context(context: str, state_type: StateType = None) -> ContextObjectData:
        """Parse and validate context JSON string."""
        try:
            validation_result = TestStateContextObjectValidator.model_validate_json(context)
            return validation_result.model_dump(exclude_unset=True, exclude_none=True)
        except ValidationError as e:
            error = e.errors()[0]
            path_str = ".".join(str(x) for x in error["loc"])

            match error:
                case {"type": "extra_forbidden", "loc": ("Map",)}:
                    raise ValueError("'Map' field is not supported when mocking a Context object")

                case {"type": "extra_forbidden", "loc": (*_, forbidden_key)}:
                    raise ValueError(f"Field '{forbidden_key}' is not allowed")

                case {"type": t} if t in ("string_type", "int_type", "dict_type", "model_type"):
                    expected_map = {
                        "string_type": "string",
                        "int_type": "integer",
                        "dict_type": "object",
                        "model_type": "object",
                    }
                    expected = expected_map.get(t, "valid type")
                    raise ValueError(f"{path_str} must be a {expected}")
                case _:
                    raise ValueError(f"{error['msg']}")
