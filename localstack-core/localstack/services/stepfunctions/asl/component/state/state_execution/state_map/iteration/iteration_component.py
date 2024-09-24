from __future__ import annotations

import abc
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.states import States


class IterationComponent(EvalComponent, abc.ABC):
    _start_at: Final[StartAt]
    _states: Final[States]
    _comment: Final[Optional[Comment]]

    def __init__(
        self,
        start_at: StartAt,
        states: States,
        comment: Optional[Comment],
    ):
        self._start_at = start_at
        self._states = states
        self._comment = comment
