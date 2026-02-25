from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.state_parallel import (
    StateParallel,
)
from localstack.services.stepfunctions.asl.component.test_state.state.base_mock import (
    MockedBaseState,
)
from localstack.services.stepfunctions.asl.component.test_state.state.execution import (
    MockedStateExecution,
)


class MockedStateParallel(MockedBaseState[StateParallel]):
    def _apply_patches(self):
        self._wrapped = MockedStateExecution.wrap(self._wrapped)

        original_eval_execution = self._wrapped._eval_execution
        self._wrapped._eval_execution = self.wrap_with_post_return(
            method=original_eval_execution,
            post_return_fn=lambda env: None,
        )

        for program in self._wrapped.branches.programs:
            original_program_eval_body = program._eval_body
            program._eval_body = self.wrap_with_mock(original_program_eval_body)
