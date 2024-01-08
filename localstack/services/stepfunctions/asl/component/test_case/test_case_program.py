import logging
from typing import Final

from localstack.aws.api.stepfunctions import (
    ExecutionFailedEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class TestCaseProgram(EvalComponent):
    test_state: Final[CommonStateField]

    def __init__(
        self,
        test_state: CommonStateField,
    ):
        self.test_state = test_state

    def _eval_body(self, env: Environment) -> None:
        try:
            self.test_state.eval(env=env)
        except FailureEventException as ex:
            env.set_error(error=ex.get_execution_failed_event_details())
        except Exception as ex:
            cause = f"{type(ex).__name__}({str(ex)})"
            LOG.error(f"Stepfunctions computation ended with exception '{cause}'.")
            env.set_error(
                ExecutionFailedEventDetails(
                    error=StatesErrorName(typ=StatesErrorNameType.StatesRuntime).error_name,
                    cause=cause,
                )
            )

        # program_state: ProgramState = env.program_state()
        # if isinstance(program_state, ProgramError):
        #     exec_failed_event_details = select_from_typed_dict(
        #         typed_dict=ExecutionFailedEventDetails, obj=program_state.error or dict()
        #     )
        #     env.event_history.add_event(
        #         context=env.event_history_context,
        #         hist_type_event=HistoryEventType.ExecutionFailed,
        #         event_detail=EventDetails(executionFailedEventDetails=exec_failed_event_details),
        #     )
        # elif isinstance(program_state, ProgramStopped):
        #     env.event_history_context.source_event_id = 0
        #     env.event_history.add_event(
        #         context=env.event_history_context,
        #         hist_type_event=HistoryEventType.ExecutionAborted,
        #         event_detail=EventDetails(
        #             executionAbortedEventDetails=ExecutionAbortedEventDetails(
        #                 error=program_state.error, cause=program_state.cause
        #             )
        #         ),
        #     )
        # elif isinstance(program_state, ProgramTimedOut):
        #     env.event_history.add_event(
        #         context=env.event_history_context,
        #         hist_type_event=HistoryEventType.ExecutionTimedOut,
        #         event_detail=EventDetails(
        #             executionTimedOutEventDetails=ExecutionTimedOutEventDetails()
        #         ),
        #     )
        # elif isinstance(program_state, ProgramEnded):
        #     env.event_history.add_event(
        #         context=env.event_history_context,
        #         hist_type_event=HistoryEventType.ExecutionSucceeded,
        #         event_detail=EventDetails(
        #             executionSucceededEventDetails=ExecutionSucceededEventDetails(
        #                 output=to_json_str(env.inp, separators=(",", ":")),
        #                 outputDetails=HistoryEventExecutionDataDetails(
        #                     truncated=False  # Always False for api calls.
        #                 ),
        #             )
        #         ),
        #     )
