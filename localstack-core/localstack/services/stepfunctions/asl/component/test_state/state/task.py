from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.component.test_state.state.base_mock import (
    MockedBaseState,
)
from localstack.services.stepfunctions.asl.component.test_state.state.execution import (
    MockedStateExecution,
)
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class MockedStateTask(MockedBaseState[StateTask]):
    def add_inspection_data(self, env: TestStateEnvironment):
        if self._wrapped.query_language.query_language_mode == QueryLanguageMode.JSONPath:
            if "afterParameters" not in env.inspection_data:
                env.inspection_data["afterParameters"] = to_json_str(env.states.get_input())

    def _apply_patches(self):
        self._wrapped = MockedStateExecution.wrap(self._wrapped)

        if self._wrapped.query_language.query_language_mode == QueryLanguageMode.JSONPath:
            self._eval_with_inspect(self._wrapped.parargs, "afterParameters")

        if isinstance(self._wrapped, StateTaskService):
            self._wrapped._eval_service_task = self.wrap_with_mock(self._wrapped._eval_service_task)

        original_eval_execution = self._wrapped._eval_execution

        def mock_eval_execution(env: TestStateEnvironment, *args, **kwargs):
            original_eval_execution(env, *args, **kwargs)
            result = to_json_str(env.stack[-1])
            env.inspection_data["result"] = result

        self._wrapped._eval_execution = self.wrap_with_post_return(
            mock_eval_execution, self.add_inspection_data
        )
