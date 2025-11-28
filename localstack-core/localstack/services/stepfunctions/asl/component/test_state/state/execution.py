from collections.abc import Callable
from functools import partial

from localstack.services.stepfunctions.asl.component.common.catch.catcher_outcome import (
    CatcherOutcomeCaught,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.component.common.retry.retrier_decl import RetrierDecl
from localstack.services.stepfunctions.asl.component.common.retry.retrier_outcome import (
    RetrierOutcome,
)
from localstack.services.stepfunctions.asl.component.common.retry.retry_outcome import RetryOutcome
from localstack.services.stepfunctions.asl.component.state.state_execution.execute_state import (
    ExecutionState,
)
from localstack.services.stepfunctions.asl.component.test_state.state.base_mock import (
    MockedBaseState,
)
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class MockedStateExecution(MockedBaseState[ExecutionState]):
    def add_inspection_data(self, env: TestStateEnvironment):
        if self._wrapped.query_language.query_language_mode == QueryLanguageMode.JSONPath:
            if "afterResultSelector" not in env.inspection_data:
                # HACK: A DistributedItemProcessorEvalInput is added to the stack and never popped off
                # during an error case. So we need to check the inspected value is correct before
                # adding it to our inspectionData.
                if isinstance(env.stack[-1], (dict, str, int, float)):
                    env.inspection_data["afterResultSelector"] = to_json_str(env.stack[-1])

        if catch := self._wrapped.catch:
            for ind, catcher in enumerate(catch.catchers):
                original_fn = catcher._eval_body
                catcher._eval_body = self.with_catch_state_id(original_fn, ind)

        if retry := self._wrapped.retry:
            for ind, retrier in enumerate(retry.retriers):
                original_fn = retrier._eval_body
                retrier._eval_body = self.with_retry_state_id(retrier, ind)

    def _apply_patches(self):
        if not isinstance(self._wrapped, ExecutionState):
            raise ValueError("Can only apply MockedStateExecution patches to an ExecutionState")
        state = self._wrapped

        if state.query_language.query_language_mode == QueryLanguageMode.JSONPath:
            self._eval_with_inspect(self._wrapped.input_path, "afterInputPath")
            self._eval_with_inspect(self._wrapped.result_path, "afterResultPath")

        self._eval_with_inspect(self._wrapped.result_selector, "afterResultSelector")
        original_eval_execution = self._wrapped._eval_execution

        if self._wrapped.catch:
            original_fn = self._wrapped._handle_catch
            self._wrapped._handle_catch = partial(self._handle_catch, original_fn)

        if self._wrapped.retry:
            original_fn = self._wrapped._handle_retry
            self._wrapped._handle_retry = partial(self._handle_retry, original_fn)

        self._wrapped._eval_execution = self.wrap_with_post_return(
            method=original_eval_execution,
            post_return_fn=self.add_inspection_data,
        )

    @staticmethod
    def with_catch_state_id(
        original_eval_body: Callable[[TestStateEnvironment], None], state_id: int
    ) -> Callable[[TestStateEnvironment], None]:
        def _wrapped(env: TestStateEnvironment):
            original_eval_body(env)

            if isinstance(env.stack[-1], CatcherOutcomeCaught):
                if not (error_details := env.inspection_data.get("errorDetails")):
                    error_details = env.inspection_data["errorDetails"] = {}

                error_details["catchIndex"] = state_id

        return _wrapped

    @staticmethod
    def with_retry_state_id(
        retrier: RetrierDecl, state_id: int
    ) -> Callable[[TestStateEnvironment], None]:
        original_retrier_eval_body = retrier._eval_body

        def _wrapped(env: TestStateEnvironment):
            if (retry_count := env.mock._state_configuration.get("retrierRetryCount", 0)) > 0:
                retrier.max_attempts._store_attempt_number(env, retry_count - 1)

            original_retrier_eval_body(env)

            if not (error_details := env.inspection_data.get("errorDetails")):
                error_details = env.inspection_data["errorDetails"] = {}

            error_details["retryIndex"] = state_id
            if env.stack[-1] == RetrierOutcome.Executed:
                # TODO(gregfurman): Ideally, retryBackoffIntervalSeconds should be written to inspectionData
                # within the retrier.backoff_rate decleration (perhaps at _access_next_multiplier).
                rate = retrier.backoff_rate.rate
                interval = retrier.interval_seconds.seconds
                error_details["retryBackoffIntervalSeconds"] = int(interval * (rate**retry_count))

        return _wrapped

    @staticmethod
    def _handle_catch(
        original_handle_catch: Callable[[TestStateEnvironment, FailureEvent], None],
        env: TestStateEnvironment,
        failure_event: FailureEvent,
    ) -> None:
        original_handle_catch(env, failure_event)

        spec: dict[str, str] = ExecutionState._construct_error_output_value(failure_event)
        error, cause = spec.get("Error"), spec.get("Cause")

        env.set_caught_error(env.next_state_name, error, cause)

    @staticmethod
    def _handle_retry(
        original_handle_retry: Callable[[TestStateEnvironment, FailureEvent], RetryOutcome],
        env: TestStateEnvironment,
        failure_event: FailureEvent,
    ) -> RetryOutcome:
        res = original_handle_retry(env, failure_event)

        spec: dict[str, str] = ExecutionState._construct_error_output_value(failure_event)
        error, cause = spec.get("Error"), spec.get("Cause")

        if res == RetryOutcome.CanRetry:
            env.set_retriable_error(error, cause)
        return res
