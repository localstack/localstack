import copy

from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.component.state.state_continue_with import (
    ContinueWithEnd,
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
        state = self._wrapped
        if state.query_language.query_language_mode == QueryLanguageMode.JSONata:
            return

        original_stack = copy.deepcopy(env.stack)
        env.stack.clear()

        if state.input_path:
            state._eval_state_input(env)
            env.inspection_data["afterInputPath"] = to_json_str(env.stack.pop())

        env.inspection_data["afterParameters"] = to_json_str(env.states.get_input())
        if state.parargs:
            state.parargs._eval_body(env)
            env.inspection_data["afterParameters"] = to_json_str(env.stack.pop())

        env.inspection_data["afterResultSelector"] = to_json_str(original_stack[-1])
        if state.result_selector:
            state.result_selector._eval_body(env)
            env.inspection_data["afterResultSelector"] = to_json_str(env.stack.pop())

        env.inspection_data["afterResultPath"] = to_json_str(original_stack[-1])

        env.stack = original_stack

    def _apply_patches(self):
        self._wrapped = MockedStateExecution.wrap(self._wrapped)

        if isinstance(self._wrapped, StateTaskService):
            self._wrapped._eval_service_task = self.wrap_with_mock(self._wrapped._eval_service_task)

        original_eval_execution = self._wrapped._eval_execution

        def mock_eval_execution(env: TestStateEnvironment, *args, **kwargs):
            original_eval_execution(env, *args, **kwargs)
            result = to_json_str(env.stack[-1])
            env.inspection_data["result"] = result

        if isinstance(self._wrapped.continue_with, ContinueWithEnd):
            mock_eval_execution = self.wrap_with_inspection_data(
                method=mock_eval_execution,
                add_inspection_data=self.add_inspection_data,
            )

        self._wrapped._eval_execution = mock_eval_execution
