from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.state_parallel import (
    StateParallel,
)
from localstack.services.stepfunctions.asl.component.test_state.state.base_mock import (
    MockedBaseState,
)
from localstack.services.stepfunctions.asl.component.test_state.state.execution import (
    MockedStateExecution,
)
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class MockedStateParallel(MockedBaseState[StateParallel]):
    def add_inspection_data(self, env: TestStateEnvironment):
        if self._wrapped.query_language.query_language_mode == QueryLanguageMode.JSONPath:
            # Parallel states do not report afterInputPath in AWS inspection data.
            env.inspection_data.pop("afterInputPath", None)

            # MockedStateExecution.add_inspection_data skips list values for afterResultSelector,
            # but Parallel state always produces a list result. Handle it here.
            if "afterResultSelector" not in env.inspection_data:
                env.inspection_data["afterResultSelector"] = to_json_str(env.stack[-1])

    def _apply_patches(self):
        self._wrapped = MockedStateExecution.wrap(self._wrapped)
        original_branches_eval_body = self._wrapped.branches._eval_body
        original_eval_execution = self._wrapped._eval_execution

        self._wrapped._eval_execution = self.wrap_with_post_return(
            method=original_eval_execution,
            post_return_fn=self.add_inspection_data,
        )

        self._wrapped.branches._eval_body = self.wrap_with_mock(original_branches_eval_body)
