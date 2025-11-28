from __future__ import annotations

from typing import Self

from localstack.aws.api.stepfunctions import Arn, InspectionData, StateMachineType
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.evaluation_details import AWSExecutionDetails
from localstack.services.stepfunctions.asl.eval.event.event_manager import (
    EventHistoryContext,
)
from localstack.services.stepfunctions.asl.eval.event.logging import (
    CloudWatchLoggingSession,
)
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramRunning,
)
from localstack.services.stepfunctions.asl.eval.states import ContextObjectData
from localstack.services.stepfunctions.asl.eval.test_state.program_state import (
    ProgramCaughtError,
    ProgramChoiceSelected,
    ProgramRetriable,
)
from localstack.services.stepfunctions.asl.eval.variable_store import VariableStore
from localstack.services.stepfunctions.backend.activity import Activity
from localstack.services.stepfunctions.backend.test_state.test_state_mock import TestStateMock


class TestStateEnvironment(Environment):
    inspection_data: InspectionData
    mock: TestStateMock

    def __init__(
        self,
        aws_execution_details: AWSExecutionDetails,
        execution_type: StateMachineType,
        context: ContextObjectData,
        event_history_context: EventHistoryContext,
        activity_store: dict[Arn, Activity],
        cloud_watch_logging_session: CloudWatchLoggingSession | None = None,
        variable_store: VariableStore | None = None,
        mock: TestStateMock | None = None,
    ):
        super().__init__(
            aws_execution_details=aws_execution_details,
            execution_type=execution_type,
            context=context,
            event_history_context=event_history_context,
            cloud_watch_logging_session=cloud_watch_logging_session,
            activity_store=activity_store,
            variable_store=variable_store,
        )
        self.inspection_data = InspectionData()
        self.mock = mock

    def is_test_state_mocked_mode(self) -> bool:
        return self.mock.is_mocked()

    @classmethod
    def as_frame_of(
        cls,
        env: Self,
        event_history_frame_cache: EventHistoryContext | None = None,
    ) -> Self:
        if (mocked_context := env.mock.get_context()) is not None:
            env.states.context_object.context_object_data = mocked_context

        return cls.as_inner_frame_of(
            env=env,
            variable_store=env.variable_store,
            event_history_frame_cache=event_history_frame_cache,
        )

    @classmethod
    def as_inner_frame_of(
        cls,
        env: Self,
        variable_store: VariableStore,
        event_history_frame_cache: EventHistoryContext | None = None,
    ) -> Self:
        frame = super().as_inner_frame_of(
            env=env,
            event_history_frame_cache=event_history_frame_cache,
            variable_store=variable_store,
        )
        frame.inspection_data = env.inspection_data
        frame.mock = env.mock
        return frame

    def set_choice_selected(self, next_state_name: str) -> None:
        with self._state_mutex:
            if isinstance(self._program_state, ProgramRunning):
                self._program_state = ProgramChoiceSelected(next_state_name=next_state_name)
                self.program_state_event.set()
                self.program_state_event.clear()

    def set_caught_error(self, next_state_name: str, error: str, cause: str) -> None:
        with self._state_mutex:
            if isinstance(self._program_state, ProgramRunning):
                self._program_state = ProgramCaughtError(
                    next_state_name=next_state_name,
                    error=error,
                    cause=cause,
                )
                self.program_state_event.set()
                self.program_state_event.clear()

    def set_retriable_error(self, error: str, cause: str) -> None:
        with self._state_mutex:
            if isinstance(self._program_state, ProgramRunning):
                self._program_state = ProgramRetriable(
                    error=error,
                    cause=cause,
                )
                self.program_state_event.set()
                self.program_state_event.clear()
