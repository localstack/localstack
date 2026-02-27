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


class MockedStateParallel(MockedBaseState[StateParallel]):
    def _apply_patches(self):
        self._wrapped = MockedStateExecution.wrap(self._wrapped)

        original_branches_eval_body = self._wrapped.branches._eval_body
        original_eval_execution = self._wrapped._eval_execution

        self._wrapped._eval_execution = self.wrap_with_post_return(
            method=original_eval_execution,
            post_return_fn=self.add_inspection_data,
        )

        self._wrapped.branches._eval_body = self.wrap_with_mock(original_branches_eval_body)

    def add_inspection_data(self, env: TestStateEnvironment):
        if self._wrapped.is_jsonpath_query_language():
            # AWS does not include afterInputPath in inspection data for Parallel states.
            env.inspection_data.pop("afterInputPath", None)
        else:
            # AWS does not include afterArguments in inspection data for Parallel states.
            env.inspection_data.pop("afterArguments", None)
