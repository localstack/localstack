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
        if self._wrapped._is_language_query_jsonpath():
            # AWS does not include afterInputPath in inspection data for Parallel states.
            env.inspection_data.pop("afterInputPath", None)
            # For the base case (no explicit ResultPath), afterResultPath equals the
            # branches result. For I/O cases with explicit ResultPath, the preprocessor's
            # result_path decoration will overwrite this with the merged value later.
            if "afterResultPath" not in env.inspection_data:
                env.inspection_data["afterResultPath"] = to_json_str(env.stack[-1])
        else:
            # For JSONata Parallel states, AWS does not include afterArguments in inspection data.
            env.inspection_data.pop("afterArguments", None)
