from __future__ import annotations

import copy
import logging
import threading
from typing import Any, Final, Optional

from localstack.aws.api.stepfunctions import ExecutionFailedEventDetails, Timestamp
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.map_run_record import (
    MapRunRecordPoolManager,
)
from localstack.services.stepfunctions.asl.eval.aws_execution_details import AWSExecutionDetails
from localstack.services.stepfunctions.asl.eval.callback.callback import CallbackPoolManager
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObject,
    ContextObjectInitData,
    ContextObjectManager,
)
from localstack.services.stepfunctions.asl.eval.event.event_history import (
    EventHistory,
    EventHistoryContext,
)
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramEnded,
    ProgramError,
    ProgramRunning,
    ProgramState,
    ProgramStopped,
    ProgramTimedOut,
)

LOG = logging.getLogger(__name__)


class Environment:
    _state_mutex: Final[threading.RLock()]
    _program_state: Optional[ProgramState]
    program_state_event: Final[threading.Event()]

    event_history: EventHistory
    event_history_context: Final[EventHistoryContext]
    aws_execution_details: Final[AWSExecutionDetails]
    callback_pool_manager: CallbackPoolManager
    map_run_record_pool_manager: MapRunRecordPoolManager
    context_object_manager: Final[ContextObjectManager]

    _frames: Final[list[Environment]]
    _is_frame: bool = False

    heap: dict[str, Any] = dict()
    stack: list[Any] = list()
    inp: Optional[Any] = None

    def __init__(
        self,
        aws_execution_details: AWSExecutionDetails,
        context_object_init: ContextObjectInitData,
        event_history_context: EventHistoryContext,
    ):
        super(Environment, self).__init__()
        self._state_mutex = threading.RLock()
        self._program_state = None
        self.program_state_event = threading.Event()

        self.event_history = EventHistory()
        self.event_history_context = event_history_context
        self.aws_execution_details = aws_execution_details
        self.callback_pool_manager = CallbackPoolManager()
        self.map_run_record_pool_manager = MapRunRecordPoolManager()
        self.context_object_manager = ContextObjectManager(
            context_object=ContextObject(
                Execution=context_object_init["Execution"],
                StateMachine=context_object_init["StateMachine"],
            )
        )

        self._frames = list()
        self._is_frame = False

        self.heap = dict()
        self.stack = list()
        self.inp = None

    @classmethod
    def as_frame_of(cls, env: Environment, event_history_frame_cache: EventHistoryContext):
        context_object_init = ContextObjectInitData(
            Execution=env.context_object_manager.context_object["Execution"],
            StateMachine=env.context_object_manager.context_object["StateMachine"],
        )
        frame = cls(
            aws_execution_details=env.aws_execution_details,
            context_object_init=context_object_init,
            event_history_context=event_history_frame_cache,
        )
        frame._is_frame = True
        frame.event_history = env.event_history
        frame.callback_pool_manager = env.callback_pool_manager
        frame.map_run_record_pool_manager = env.map_run_record_pool_manager
        frame.heap = env.heap
        frame._program_state = copy.deepcopy(env._program_state)
        return frame

    @property
    def next_state_name(self) -> Optional[str]:
        next_state_name: Optional[str] = None
        if isinstance(self._program_state, ProgramRunning):
            next_state_name = self._program_state.next_state_name
        return next_state_name

    @next_state_name.setter
    def next_state_name(self, next_state_name: str) -> None:
        if self._program_state is None:
            self._program_state = ProgramRunning()

        if isinstance(self._program_state, ProgramRunning):
            self._program_state.next_state_name = next_state_name
        else:
            raise RuntimeError(
                f"Could not set NextState value when in state '{type(self._program_state)}'."
            )

    def program_state(self) -> ProgramState:
        return copy.deepcopy(self._program_state)

    def is_running(self) -> bool:
        return isinstance(self._program_state, ProgramRunning)

    def set_ended(self) -> None:
        with self._state_mutex:
            if isinstance(self._program_state, ProgramRunning):
                self._program_state = ProgramEnded()
                for frame in self._frames:
                    frame.set_ended()
            self.program_state_event.set()
            self.program_state_event.clear()

    def set_error(self, error: ExecutionFailedEventDetails) -> None:
        with self._state_mutex:
            self._program_state = ProgramError(error=error)
            for frame in self._frames:
                frame.set_error(error=error)
            self.program_state_event.set()
            self.program_state_event.clear()

    def set_timed_out(self) -> None:
        with self._state_mutex:
            self._program_state = ProgramTimedOut()
            for frame in self._frames:
                frame.set_timed_out()
            self.program_state_event.set()
            self.program_state_event.clear()

    def set_stop(self, stop_date: Timestamp, cause: Optional[str], error: Optional[str]) -> None:
        with self._state_mutex:
            if isinstance(self._program_state, ProgramRunning):
                self._program_state = ProgramStopped(stop_date=stop_date, cause=cause, error=error)
                for frame in self._frames:
                    frame.set_stop(stop_date=stop_date, cause=cause, error=error)
                self.program_state_event.set()
                self.program_state_event.clear()
            else:
                raise RuntimeError("Cannot stop non running ProgramState.")

    def open_frame(
        self, event_history_context: Optional[EventHistoryContext] = None
    ) -> Environment:
        with self._state_mutex:
            # The default logic provisions for child frame to extend the source frame event id.
            if event_history_context is None:
                event_history_context = EventHistoryContext(
                    previous_event_id=self.event_history_context.source_event_id
                )

            frame = Environment.as_frame_of(self, event_history_context)
            self._frames.append(frame)
            return frame

    def close_frame(self, frame: Environment) -> None:
        with self._state_mutex:
            if frame in self._frames:
                self._frames.remove(frame)
                self.event_history_context.integrate(frame.event_history_context)

    def delete_frame(self, frame: Environment) -> None:
        with self._state_mutex:
            if frame in self._frames:
                self._frames.remove(frame)

    def is_frame(self) -> bool:
        return self._is_frame
