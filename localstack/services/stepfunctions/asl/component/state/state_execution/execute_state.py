import abc
from typing import Optional

from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.common.catch.catch_decl import CatchDecl
from localstack.services.stepfunctions.asl.component.common.catch.catch_outcome import (
    CatchOutcome,
    CatchOutcomeCaught,
    CatchOutcomeNotCaught,
)
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.common.retry.retry_decl import RetryDecl
from localstack.services.stepfunctions.asl.component.common.retry.retry_outcome import RetryOutcome
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ExecutionState(CommonStateField, abc.ABC):
    def __init__(
        self,
        state_entered_event_type: HistoryEventType,
        state_exited_event_type: Optional[HistoryEventType],
    ):
        super().__init__(
            state_entered_event_type=state_entered_event_type,
            state_exited_event_type=state_exited_event_type,
        )
        # ResultPath (Optional)
        # Specifies where (in the input) to place the results of executing the state_task that's specified in Resource.
        # The input is then filtered as specified by the OutputPath field (if present) before being used as the
        # state's output.
        self.result_path: Optional[ResultPath] = None

        # ResultSelector (Optional)
        # Pass a collection of key value pairs, where the values are static or selected from the result.
        self.result_selector: Optional[ResultSelector] = None

        # Retry (Optional)
        # An array of objects, called Retriers, that define a retry policy if the state encounters runtime errors.
        self.retry: Optional[RetryDecl] = None

        # Catch (Optional)
        # An array of objects, called Catchers, that define a fallback state. This state is executed if the state
        # encounters runtime errors and its retry policy is exhausted or isn't defined.
        self.catch: Optional[CatchDecl] = None

    def from_state_props(self, state_props: StateProps) -> None:
        super().from_state_props(state_props=state_props)
        self.result_path = state_props.get(ResultPath)
        self.result_selector = state_props.get(ResultSelector)
        self.retry = state_props.get(RetryDecl)
        self.catch = state_props.get(CatchDecl)

    def _to_error_name(self, ex: Exception) -> ErrorName:  # noqa
        error_name: ErrorName = StatesErrorName(StatesErrorNameType.StatesTaskFailed)
        return error_name

    @abc.abstractmethod
    def _eval_execution(self, env: Environment) -> None:
        ...

    def _handle_retry(self, ex: Exception, env: Environment) -> None:
        error_name: ErrorName = self._to_error_name(ex)
        env.stack.append(error_name)

        self.retry.eval(env)
        res: RetryOutcome = env.stack.pop()

        match res:
            case RetryOutcome.CanRetry:
                self._eval_state(env)
            case RetryOutcome.CannotRetry:
                # TODO: error type.
                raise RuntimeError("Reached maximum Retry attempts.")
            case RetryOutcome.NoRetrier:
                raise RuntimeError(f"No Retriers when dealing with exception '{ex}'.")

    def _handle_catch(self, ex: Exception, env: Environment) -> None:
        error_name: ErrorName = self._to_error_name(ex)
        env.stack.append(error_name)

        self.catch.eval(env)
        res: CatchOutcome = env.stack.pop()

        if isinstance(res, CatchOutcomeCaught):
            pass
        elif isinstance(res, CatchOutcomeNotCaught):
            raise RuntimeError(f"No Catcher when dealing with exception '{ex}'.")

    def _eval_state(self, env: Environment) -> None:
        try:
            self._eval_execution(env)

            if self.result_selector:
                self.result_selector.eval(env=env)

            if self.result_path:
                self.result_path.eval(env)
            else:
                res = env.stack.pop()
                env.inp = res
        except Exception as ex:
            if self.retry:
                self._handle_retry(ex, env)
            elif self.catch:
                self._handle_catch(ex, env)
            else:
                raise ex
