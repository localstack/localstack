import abc
import copy
from typing import Generic, TypeVar

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_continue_with import (
    ContinueWithNext,
)
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.backend.test_state.test_state_mock import (
    TestStateResponseReturn,
    TestStateResponseThrow,
    eval_mocked_response_throw,
)

T = TypeVar("T", bound=CommonStateField)


class MockedBaseState(Generic[T], abc.ABC):
    is_single_state: bool
    _wrapped: T

    def __init__(self, wrapped: T):
        super().__init__()
        self._wrapped = wrapped
        self.apply_patches()

    def apply_patches(self):
        self._apply_patches()

        original_eval_body = self._wrapped._eval_body
        self._wrapped._eval_body = self.wrap_with_post_return(
            original_eval_body, self.stop_execution
        )

    @abc.abstractmethod
    def _apply_patches(self): ...

    @classmethod
    def wrap(cls, state: T, is_single_state: bool = False) -> T:
        cls.is_single_state = is_single_state
        cls._wrapped = state
        return cls(state)._wrapped

    def __getattr__(self, attr: str):
        return getattr(self._wrapped, attr)

    @classmethod
    def before_mock(self, env: TestStateEnvironment):
        return

    @classmethod
    def do_mock(self, env: TestStateEnvironment):
        mocked_response = env.mock.get_next_result()
        if not mocked_response:
            return

        if isinstance(mocked_response, TestStateResponseThrow):
            eval_mocked_response_throw(env, mocked_response)
            return

        if isinstance(mocked_response, TestStateResponseReturn):
            result_copy = copy.deepcopy(mocked_response.payload)
            env.stack.append(result_copy)

    @classmethod
    def after_mock(self, env: TestStateEnvironment):
        return

    @classmethod
    def wrap_with_mock(cls, original_method):
        def wrapper(env: TestStateEnvironment, *args, **kwargs):
            if not env.mock.is_mocked():
                original_method(env, *args, **kwargs)
                return

            cls.before_mock(env)
            try:
                cls.do_mock(env)
            finally:
                cls.after_mock(env)

        return wrapper

    @staticmethod
    def wrap_with_post_return(method, post_return_fn):
        def wrapper(env: TestStateEnvironment, *args, **kwargs):
            try:
                method(env, *args, **kwargs)
            finally:
                post_return_fn(env)

        return wrapper

    @staticmethod
    def _eval_with_inspect(component: EvalComponent, key: str):
        if not component:
            return

        eval_body_fn = component._eval_body

        def _update(env: TestStateEnvironment, *args, **kwargs):
            # if inspectionData already populated, don't execute again
            if key in env.inspection_data:
                return

            eval_body_fn(env, *args, **kwargs)
            result = env.stack[-1]
            env.inspection_data[key] = to_json_str(result)

        component._eval_body = MockedBaseState.wrap_with_post_return(eval_body_fn, _update)

    def stop_execution(self, env: TestStateEnvironment):
        if isinstance(self._wrapped.continue_with, ContinueWithNext):
            if next_state := self._wrapped.continue_with.next_state:
                env.set_choice_selected(next_state.name)
