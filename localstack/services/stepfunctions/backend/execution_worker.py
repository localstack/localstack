import datetime
import json
from threading import Thread
from typing import Optional

from localstack.aws.api.stepfunctions import Definition, SensitiveData
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import (
    ContextObjectInitData,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser
from localstack.services.stepfunctions.backend.execution_worker_comm import ExecutionWorkerComm


# TODO: add stop flag checks during interpreter work.
class ExecutionWorker:
    def __init__(
        self,
        definition: Definition,
        input_data: Optional[SensitiveData],
        exec_comm: ExecutionWorkerComm,
        context_object_init: ContextObjectInitData,
    ):
        self.definition: Definition = definition
        self.input_data: Optional[SensitiveData] = input_data
        self.exec_comm: ExecutionWorkerComm = exec_comm
        self._worker_thread: Optional[Thread] = None
        self.env: Optional[Environment] = None
        self._context_object_init = context_object_init

    def _execution_logic(self):
        # TODO.
        program: Program = AmazonStateLanguageParser.parse(self.definition)
        self.env = Environment(context_object_init=self._context_object_init)
        if self.input_data:
            self.env.inp = json.loads(self.input_data)
        program.eval(self.env)

        result = self.env.inp
        self.exec_comm.succeed(result_data=json.dumps(result))  # TODO: output types?

    def start(self):
        self._worker_thread = Thread(target=self._execution_logic)
        self._worker_thread.start()

    def stop(self, stop_date: datetime.datetime, error: Optional[str], cause: Optional[str]):
        self.env.set_stop(stop_date=stop_date, cause=cause, error=error)
