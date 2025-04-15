import datetime
from threading import Thread
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    ExecutionStartedEventDetails,
    HistoryEventExecutionDataDetails,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.evaluation_details import EvaluationDetails
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.event.event_manager import (
    EventHistoryContext,
)
from localstack.services.stepfunctions.asl.eval.event.logging import (
    CloudWatchLoggingSession,
)
from localstack.services.stepfunctions.asl.eval.states import (
    ContextObjectData,
    ExecutionData,
    StateMachineData,
)
from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.backend.activity import Activity
from localstack.services.stepfunctions.backend.execution_worker_comm import (
    ExecutionWorkerCommunication,
)
from localstack.services.stepfunctions.mocking.mock_config import MockTestCase
from localstack.utils.common import TMP_THREADS


class ExecutionWorker:
    _evaluation_details: Final[EvaluationDetails]
    _execution_communication: Final[ExecutionWorkerCommunication]
    _cloud_watch_logging_session: Final[Optional[CloudWatchLoggingSession]]
    _mock_test_case: Final[Optional[MockTestCase]]
    _activity_store: dict[Arn, Activity]

    env: Optional[Environment]

    def __init__(
        self,
        evaluation_details: EvaluationDetails,
        exec_comm: ExecutionWorkerCommunication,
        cloud_watch_logging_session: Optional[CloudWatchLoggingSession],
        activity_store: dict[Arn, Activity],
        mock_test_case: Optional[MockTestCase] = None,
    ):
        self._evaluation_details = evaluation_details
        self._execution_communication = exec_comm
        self._cloud_watch_logging_session = cloud_watch_logging_session
        self._mock_test_case = mock_test_case
        self._activity_store = activity_store
        self.env = None

    def _get_evaluation_entrypoint(self) -> EvalComponent:
        return AmazonStateLanguageParser.parse(
            self._evaluation_details.state_machine_details.definition
        )[0]

    def _get_evaluation_environment(self) -> Environment:
        return Environment(
            aws_execution_details=self._evaluation_details.aws_execution_details,
            execution_type=self._evaluation_details.state_machine_details.typ,
            context=ContextObjectData(
                Execution=ExecutionData(
                    Id=self._evaluation_details.execution_details.arn,
                    Input=self._evaluation_details.execution_details.inpt,
                    Name=self._evaluation_details.execution_details.name,
                    RoleArn=self._evaluation_details.execution_details.role_arn,
                    StartTime=self._evaluation_details.execution_details.start_time,
                ),
                StateMachine=StateMachineData(
                    Id=self._evaluation_details.state_machine_details.arn,
                    Name=self._evaluation_details.state_machine_details.name,
                ),
            ),
            event_history_context=EventHistoryContext.of_program_start(),
            cloud_watch_logging_session=self._cloud_watch_logging_session,
            activity_store=self._activity_store,
            mock_test_case=self._mock_test_case,
        )

    def _execution_logic(self):
        program = self._get_evaluation_entrypoint()
        self.env = self._get_evaluation_environment()

        self.env.event_manager.add_event(
            context=self.env.event_history_context,
            event_type=HistoryEventType.ExecutionStarted,
            event_details=EventDetails(
                executionStartedEventDetails=ExecutionStartedEventDetails(
                    input=to_json_str(self._evaluation_details.execution_details.inpt),
                    inputDetails=HistoryEventExecutionDataDetails(
                        truncated=False
                    ),  # Always False for api calls.
                    roleArn=self._evaluation_details.aws_execution_details.role_arn,
                )
            ),
            update_source_event_id=False,
        )

        program.eval(self.env)

        self._execution_communication.terminated()

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
