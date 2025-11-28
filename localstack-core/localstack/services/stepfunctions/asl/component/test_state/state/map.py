from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.state_map import (
    StateMap,
)
from localstack.services.stepfunctions.asl.component.test_state.state.base_mock import (
    MockedBaseState,
)
from localstack.services.stepfunctions.asl.component.test_state.state.execution import (
    MockedStateExecution,
)
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.backend.test_state.test_state_mock import (
    TestStateResponseThrow,
)


class MockedStateMap(MockedBaseState[StateMap]):
    def add_inspection_data(self, env: TestStateEnvironment):
        if tolerated_failure_percentage := env.inspection_data.get("toleratedFailurePercentage"):
            env.inspection_data["toleratedFailurePercentage"] = float(tolerated_failure_percentage)

        if tolerated_failure_count := env.inspection_data.get("toleratedFailureCount"):
            env.inspection_data["toleratedFailureCount"] = int(tolerated_failure_count)

    @classmethod
    def before_mock(cls, env: TestStateEnvironment):
        if not env.mock or not env.mock._state_configuration:
            return

        if not cls._wrapped.catch and not cls._wrapped.retry:
            return

        if failure_count := env.mock._state_configuration.get("mapIterationFailureCount"):
            max_failure_count = (
                cls._wrapped.tolerated_failure_count_decl._eval_tolerated_failure_count(env)
            )
            if failure_count > max_failure_count:
                error_response = TestStateResponseThrow(
                    error=StatesErrorNameType.StatesExceedToleratedFailureThreshold.to_name(),
                    cause="The specified tolerated failure threshold was exceeded",
                )
                env.mock.add_result(error_response)
                return

    def _apply_patches(self):
        self._wrapped = MockedStateExecution.wrap(self._wrapped)

        if self._wrapped.query_language.query_language_mode == QueryLanguageMode.JSONPath:
            self._eval_with_inspect(self._wrapped.items_path, "afterInputPath")
            self._eval_with_inspect(self._wrapped.item_selector, "afterItemsSelector")

        original_eval_max_concurrency = self._wrapped.max_concurrency_decl._eval_max_concurrency
        original_iteration_component_eval_body = self._wrapped.iteration_component._eval_body
        original_eval_execution = self._wrapped._eval_execution

        # HACK(gregfurman): Ideally we should be using the "$$.Map.Item.Index" to access each item of the
        # mocked result list. This is turning out to be quite complicated, so instead just patch the
        # StateMap's max concurrency decleration to always eval to '1' -- making the map run in serial.
        def mock_max_concurrency(env: TestStateEnvironment) -> int:
            # always set concurrency to 1 but inspection data is accurate to original
            env.inspection_data["maxConcurrency"] = original_eval_max_concurrency(env)
            return 1

        self._wrapped._eval_execution = self.wrap_with_post_return(
            method=original_eval_execution,
            post_return_fn=self.add_inspection_data,
        )

        self._wrapped.max_concurrency_decl._eval_max_concurrency = mock_max_concurrency
        self._wrapped.iteration_component._eval_body = self.wrap_with_mock(
            original_iteration_component_eval_body
        )
