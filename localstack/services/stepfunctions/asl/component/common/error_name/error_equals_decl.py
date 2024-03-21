from typing import Final

from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ErrorEqualsDecl(EvalComponent):
    """
    ErrorEquals value MUST be a non-empty array of Strings, which match Error Names.
    Each Retrier MUST contain a field named "ErrorEquals" whose value MUST be a non-empty array of Strings,
    which match Error Names.
    """

    _STATE_ALL_ERROR: Final[StatesErrorName] = StatesErrorName(typ=StatesErrorNameType.StatesALL)
    _STATE_TASK_ERROR: Final[StatesErrorName] = StatesErrorName(
        typ=StatesErrorNameType.StatesTaskFailed
    )

    def __init__(self, error_names: list[ErrorName]):
        # The reserved name "States.ALL" in a Retrier’s "ErrorEquals" field is a wildcard
        # and matches any Error Name. Such a value MUST appear alone in the "ErrorEquals"
        # array and MUST appear in the last Retrier in the "Retry" array.
        if ErrorEqualsDecl._STATE_ALL_ERROR in error_names and len(error_names) > 1:
            raise ValueError(
                f"States.ALL must appear alone in the ErrorEquals array, got '{error_names}'."
            )

        # TODO: how to handle duplicate ErrorName?
        self.error_names: list[ErrorName] = error_names

    def _eval_body(self, env: Environment) -> None:
        """
        When a state reports an error, the interpreter scans through the Retriers and,
        when the Error Name appears in the value of a Retrier’s "ErrorEquals" field, implements the retry policy
        described in that Retrier.
        This pops the error from the stack, and appends the bool of this check.
        """

        # Try to reduce error response to ErrorName or pass exception upstream.
        error_name: ErrorName = env.stack.pop()

        if ErrorEqualsDecl._STATE_ALL_ERROR in self.error_names:
            res = True
        elif (
            ErrorEqualsDecl._STATE_TASK_ERROR in self.error_names
            and not isinstance(error_name, StatesErrorName)
        ):  # TODO: consider binding a 'context' variable to error_names to more formally detect their evaluation type.
            res = True
        else:
            res = error_name in self.error_names

        env.stack.append(res)
