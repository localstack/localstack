from __future__ import annotations

import abc
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguage
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.program.states import States


class IterationComponent(EvalComponent, abc.ABC):
    # Ensure no member variables are used to keep track of the state of
    # iteration components: the evaluation must be stateless as for all
    # EvalComponents to ensure they can be reused or used concurrently.
    _query_language: Final[QueryLanguage]
    _start_at: Final[StartAt]
    _states: Final[States]
    _comment: Final[Optional[Comment]]

    def __init__(
        self,
        query_language: QueryLanguage,
        start_at: StartAt,
        states: States,
        comment: Optional[Comment],
    ):
        self._query_language = query_language
        self._start_at = start_at
        self._states = states
        self._comment = comment

    def _get_iteration_program(self) -> Program:
        return Program(
            query_language=self._query_language,
            start_at=self._start_at,
            states=self._states,
            timeout_seconds=None,
            comment=self._comment,
        )
