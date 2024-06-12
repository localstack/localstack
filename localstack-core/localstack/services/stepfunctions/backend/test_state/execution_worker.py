from typing import Optional

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_manager import (
    EventHistoryContext,
)
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.parse.test_state.asl_parser import (
    TestStateAmazonStateLanguageParser,
)
from localstack.services.stepfunctions.backend.execution_worker import ExecutionWorker


class TestStateExecutionWorker(ExecutionWorker):
    env: Optional[TestStateEnvironment]

    def _get_evaluation_entrypoint(self) -> EvalComponent:
        return TestStateAmazonStateLanguageParser.parse(self._definition)[0]

    def _get_evaluation_environment(self) -> Environment:
        return TestStateEnvironment(
            aws_execution_details=self._aws_execution_details,
            context_object_init=self._context_object_init,
            event_history_context=EventHistoryContext.of_program_start(),
            activity_store=self._activity_store,
        )

    def start(self):
        # bypass the native async execution of ASL programs.
        self._execution_logic()
