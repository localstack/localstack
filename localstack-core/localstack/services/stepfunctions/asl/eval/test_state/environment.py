from __future__ import annotations

from typing import Final, Optional

from localstack.aws.api.stepfunctions import Arn, InspectionData, StateMachineType
from localstack.services.stepfunctions.asl.eval.aws_execution_details import AWSExecutionDetails
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObjectInitData,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_manager import (
    EventHistoryContext,
)
from localstack.services.stepfunctions.asl.eval.event.logging import (
    CloudWatchLoggingSession,
)
from localstack.services.stepfunctions.asl.eval.program_state import ProgramRunning
from localstack.services.stepfunctions.asl.eval.test_state.program_state import (
    ProgramChoiceSelected,
)
from localstack.services.stepfunctions.backend.activity import Activity


class TestStateEnvironment(Environment):
    inspection_data: Final[InspectionData]

    def __init__(
        self,
        aws_execution_details: AWSExecutionDetails,
        execution_type: StateMachineType,
        context_object_init: ContextObjectInitData,
        event_history_context: EventHistoryContext,
        activity_store: dict[Arn, Activity],
        cloud_watch_logging_session: Optional[CloudWatchLoggingSession] = None,
    ):
        super().__init__(
            aws_execution_details=aws_execution_details,
            execution_type=execution_type,
            context_object_init=context_object_init,
            event_history_context=event_history_context,
            cloud_watch_logging_session=cloud_watch_logging_session,
            activity_store=activity_store,
        )
        self.inspection_data = InspectionData()

    @classmethod
    def as_frame_of(
        cls, env: TestStateEnvironment, event_history_frame_cache: EventHistoryContext
    ) -> TestStateEnvironment:
        frame = super().as_frame_of(env=env, event_history_frame_cache=event_history_frame_cache)
        frame.inspection_data = env.inspection_data
        return frame

    def set_choice_selected(self, next_state_name: str) -> None:
        with self._state_mutex:
            if isinstance(self._program_state, ProgramRunning):
                self._program_state = ProgramChoiceSelected(next_state_name=next_state_name)
                self.program_state_event.set()
                self.program_state_event.clear()
            else:
                raise RuntimeError("Cannot set choice selected for non running ProgramState.")
