import copy
import datetime
from threading import Thread
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    Definition,
    ExecutionStartedEventDetails,
    HistoryEventExecutionDataDetails,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.eval.aws_execution_details import AWSExecutionDetails
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObjectInitData,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.event.event_history import EventHistoryContext
from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.backend.execution_worker_comm import ExecutionWorkerComm


class ExecutionWorker:
    env: Optional[Environment]
    _definition: Definition
    _input_data: Optional[dict]
    _exec_comm: Final[ExecutionWorkerComm]
    _context_object_init: Final[ContextObjectInitData]
    _aws_execution_details: Final[AWSExecutionDetails]

    def __init__(
        self,
        definition: Definition,
        input_data: Optional[dict],
        context_object_init: ContextObjectInitData,
        aws_execution_details: AWSExecutionDetails,
        exec_comm: ExecutionWorkerComm,
    ):
        self._definition = definition
        self._input_data = input_data
        self._exec_comm = exec_comm
        self._context_object_init = context_object_init
        self._aws_execution_details = aws_execution_details
        self.env = None

    def _execution_logic(self):
        program: Program = AmazonStateLanguageParser.parse(self._definition)
        self.env = Environment(
            aws_execution_details=self._aws_execution_details,
            context_object_init=self._context_object_init,
            event_history_context=EventHistoryContext.of_program_start(),
        )
        self.env.inp = copy.deepcopy(
            self._input_data
        )  # The program will mutate the input_data, which is otherwise constant in regard to the execution value.

        self.env.event_history.add_event(
            context=self.env.event_history_context,
            hist_type_event=HistoryEventType.ExecutionStarted,
            event_detail=EventDetails(
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
        Thread(target=self._execution_logic).start()

    def stop(self, stop_date: datetime.datetime, error: Optional[str], cause: Optional[str]):
        self.env.set_stop(stop_date=stop_date, cause=cause, error=error)
