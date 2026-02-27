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

        cls = type(self)

        def mocked_branches_eval_body(env: TestStateEnvironment) -> None:
            if not env.mock.is_mocked():
                original_branches_eval_body(env)
                return
            # Pop the input value just like the original BranchesDecl._eval_body does.
            env.stack.pop()
            cls.do_mock(env)

        self._wrapped.branches._eval_body = mocked_branches_eval_body

    def add_inspection_data(self, env: TestStateEnvironment):
        if self._wrapped._is_language_query_jsonpath():
            # AWS does not include afterInputPath in inspection data for Parallel states.
            env.inspection_data.pop("afterInputPath", None)
            # MockedStateExecution.add_inspection_data skips afterResultSelector for list
            # results (its isinstance check excludes lists). Parallel state results are
            # lists, so we handle it here. This runs before result_path, so stack[-1] is
            # the raw branches result (list), which is the correct value.
            if "afterResultSelector" not in env.inspection_data:
                env.inspection_data["afterResultSelector"] = to_json_str(env.stack[-1])
            # For the base case (no explicit ResultPath), afterResultPath equals the
            # branches result. For I/O cases with explicit ResultPath, the preprocessor's
            # result_path decoration will overwrite this with the merged value later.
            if "afterResultPath" not in env.inspection_data:
                env.inspection_data["afterResultPath"] = to_json_str(env.stack[-1])
        else:
            # For JSONata Parallel states, AWS does not include afterArguments,
            # afterResultSelector, or afterResultPath in inspection data.
            env.inspection_data.pop("afterArguments", None)
