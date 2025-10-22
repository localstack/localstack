import abc
import copy
from typing import Generic, TypeVar

from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
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
    def wrap_with_inspection_data(method, add_inspection_data):
        def wrapper(env: TestStateEnvironment, *args, **kwargs):
            try:
                method(env, *args, **kwargs)
            finally:
                add_inspection_data(env)

        return wrapper
