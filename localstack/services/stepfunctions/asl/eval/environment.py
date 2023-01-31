from __future__ import annotations

import copy
import logging
import threading
from typing import Any, Optional

from localstack.aws.api.stepfunctions import Timestamp
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObject,
    ContextObjectInitData,
)
from localstack.services.stepfunctions.asl.eval.event.event_history import EventHistory
from localstack.services.stepfunctions.asl.eval.programstate.program_ended import ProgramEnded
from localstack.services.stepfunctions.asl.eval.programstate.program_error import ProgramError
from localstack.services.stepfunctions.asl.eval.programstate.program_running import ProgramRunning
from localstack.services.stepfunctions.asl.eval.programstate.program_state import ProgramState
from localstack.services.stepfunctions.asl.eval.programstate.program_stopped import ProgramStopped

LOG = logging.getLogger(__name__)


class Environment:
    def __init__(self, context_object_init: ContextObjectInitData):
        super(Environment, self).__init__()
        self._state_mutex = threading.RLock()
        self._program_state: Optional[ProgramState] = None
        self.program_state_event = threading.Event()
        self._frames: list[Environment] = list()

        self.event_history: EventHistory = EventHistory()

        self.heap: dict[str, Any] = dict()
        self.stack: list[Any] = list()
        self.inp: Optional[Any] = None

        self.context_object: ContextObject = ContextObject(
            Execution=context_object_init["Execution"],
            StateMachine=context_object_init["StateMachine"],
            State=None,
            Task=None,
            Map=None,
        )

    @classmethod
    def as_frame_of(cls, env: Environment):
        context_object_init = ContextObjectInitData(
            Execution=env.context_object["Execution"],
            StateMachine=env.context_object["StateMachine"],
        )
        frame = cls(context_object_init=context_object_init)
        frame.heap = env.heap
        frame.event_history = env.event_history
        frame.context_object = env.context_object
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

    def set_error(self, error: Any) -> None:
        with self._state_mutex:
            self._program_state = ProgramError(error=error)
            for frame in self._frames:
                frame.set_error(error=error)
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

    def open_frame(self) -> Environment:
        with self._state_mutex:
            frame = Environment.as_frame_of(self)
            self._frames.append(frame)
            return frame

    def close_frame(self, frame: Environment) -> None:
        with self._state_mutex:
            self._frames.remove(frame)
