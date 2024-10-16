import copy
import datetime
from threading import Thread
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    Definition,
    ExecutionStartedEventDetails,
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    StateMachineType,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.aws_execution_details import AWSExecutionDetails
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObjectInitData,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.event.event_manager import (
    EventHistoryContext,
)
from localstack.services.stepfunctions.asl.eval.event.logging import (
    CloudWatchLoggingSession,
)
from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.backend.activity import Activity
from localstack.services.stepfunctions.backend.execution_worker_comm import (
    ExecutionWorkerCommunication,
)
from localstack.utils.common import TMP_THREADS


class ExecutionWorker:
    env: Optional[Environment]
    _execution_type: Final[StateMachineType]
    _definition: Definition
    _input_data: Optional[dict]
    _exec_comm: Final[ExecutionWorkerCommunication]
    _context_object_init: Final[ContextObjectInitData]
    _aws_execution_details: Final[AWSExecutionDetails]
    _cloud_watch_logging_session: Final[Optional[CloudWatchLoggingSession]]
    _activity_store: dict[Arn, Activity]

    def __init__(
        self,
        execution_type: StateMachineType,
        definition: Definition,
        input_data: Optional[dict],
        context_object_init: ContextObjectInitData,
        aws_execution_details: AWSExecutionDetails,
        exec_comm: ExecutionWorkerCommunication,
        cloud_watch_logging_session: Optional[CloudWatchLoggingSession],
        activity_store: dict[Arn, Activity],
    ):
        self._execution_type = execution_type
        self._definition = definition
        self._input_data = input_data
        self._exec_comm = exec_comm
        self._context_object_init = context_object_init
        self._aws_execution_details = aws_execution_details
        self._cloud_watch_logging_session = cloud_watch_logging_session
        self._activity_store = activity_store
        self.env = None

    def _get_evaluation_entrypoint(self) -> EvalComponent:
        return AmazonStateLanguageParser.parse(self._definition)[0]

    def _get_evaluation_environment(self) -> Environment:
        return Environment(
            aws_execution_details=self._aws_execution_details,
            execution_type=self._execution_type,
            context_object_init=self._context_object_init,
            event_history_context=EventHistoryContext.of_program_start(),
            cloud_watch_logging_session=self._cloud_watch_logging_session,
            activity_store=self._activity_store,
        )

    def _execution_logic(self):
        program = self._get_evaluation_entrypoint()
        self.env = self._get_evaluation_environment()
        self.env.inp = copy.deepcopy(
            self._input_data
        )  # The program will mutate the input_data, which is otherwise constant in regard to the execution value.

        self.env.event_manager.add_event(
            context=self.env.event_history_context,
            event_type=HistoryEventType.ExecutionStarted,
            event_details=EventDetails(
                executionStartedEventDetails=ExecutionStartedEventDetails(
                    input=to_json_str(self.env.inp),
                    inputDetails=HistoryEventExecutionDataDetails(
                        truncated=False
                    ),  # Always False for api calls.
                    roleArn=self._aws_execution_details.role_arn,
                )
            ),
            update_source_event_id=False,
        )

        program.eval(self.env)

        self._exec_comm.terminated()

    def start(self):
        execution_logic_thread = Thread(target=self._execution_logic, daemon=True)
        TMP_THREADS.append(execution_logic_thread)
        execution_logic_thread.start()

    def stop(self, stop_date: datetime.datetime, error: Optional[str], cause: Optional[str]):
        self.env.set_stop(stop_date=stop_date, cause=cause, error=error)


class SyncExecutionWorker(ExecutionWorker):
    def start(self):
        # bypass the native async execution of ASL programs.
        self._execution_logic()
