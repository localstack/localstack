from localstack.aws.api.stepfunctions import Arn, StateName
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.evaluation_details import EvaluationDetails
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
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.parse.test_state.asl_parser import (
    TestStateAmazonStateLanguageParser,
)
from localstack.services.stepfunctions.backend.activity import Activity
from localstack.services.stepfunctions.backend.execution_worker import SyncExecutionWorker
from localstack.services.stepfunctions.backend.execution_worker_comm import (
    ExecutionWorkerCommunication,
)
from localstack.services.stepfunctions.backend.test_state.test_state_mock import TestStateMock


class TestStateExecutionWorker(SyncExecutionWorker):
    env: TestStateEnvironment | None
    state_name: str | None = None
    mock: TestStateMock | None

    def __init__(
        self,
        evaluation_details: EvaluationDetails,
        exec_comm: ExecutionWorkerCommunication,
        cloud_watch_logging_session: CloudWatchLoggingSession | None,
        activity_store: dict[Arn, Activity],
        state_name: StateName | None = None,
        mock: TestStateMock | None = None,
    ):
        super().__init__(
            evaluation_details,
            exec_comm,
            cloud_watch_logging_session,
            activity_store,
            local_mock_test_case=None,  # local mock is only applicable to SFN Local, but not for TestState
        )
        self.state_name = state_name
        self.mock = mock

    def _get_evaluation_entrypoint(self) -> EvalComponent:
        return TestStateAmazonStateLanguageParser.parse(
            self._evaluation_details.state_machine_details.definition, self.state_name
        )[0]

    def _get_evaluation_environment(self) -> Environment:
        return TestStateEnvironment(
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
            mock=self.mock,
        )
