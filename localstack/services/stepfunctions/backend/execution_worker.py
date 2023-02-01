import datetime
import json
from threading import Thread
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    Definition,
    ExecutionStartedEventDetails,
    HistoryEventExecutionDataDetails,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObjectInitData,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser
from localstack.services.stepfunctions.backend.execution_worker_comm import ExecutionWorkerComm


class ExecutionWorker:
    def __init__(
        self,
        role_arn: Arn,
        definition: Definition,
        input_data: Optional[dict],
        context_object_init: ContextObjectInitData,
        exec_comm: ExecutionWorkerComm,
    ):
        self.role_arn: Final[Arn] = role_arn
        self.definition: Definition = definition
        self.input_data: Optional[dict] = input_data
        self._worker_thread: Optional[Thread] = None
        self.env: Optional[Environment] = None
        self._context_object_init = context_object_init
        self.exec_comm: Final[ExecutionWorkerComm] = exec_comm

    def _execution_logic(self):
        program: Program = AmazonStateLanguageParser.parse(self.definition)
        self.env = Environment(context_object_init=self._context_object_init)
        self.env.inp = self.input_data or {}

        self.env.event_history.add_event(
            hist_type_event=HistoryEventType.ExecutionStarted,
            event_detail=EventDetails(
                executionStartedEventDetails=ExecutionStartedEventDetails(
                    input=json.dumps(self.env.inp),
                    inputDetails=HistoryEventExecutionDataDetails(
                        truncated=False
                    ),  # Always False for api calls.
                    roleArn=self.role_arn,
                )
            ),
        )

        program.eval(self.env)

        self.exec_comm.terminated()

    def start(self):
        self._worker_thread = Thread(target=self._execution_logic)
        self._worker_thread.start()

    def stop(self, stop_date: datetime.datetime, error: Optional[str], cause: Optional[str]):
        self.env.set_stop(stop_date=stop_date, cause=cause, error=error)
