import threading

import pytest

from localstack.utils.sync import Once, SynchronizedDefaultDict, once_func


def test_synchronized_defaultdict():
    d = SynchronizedDefaultDict(int)

    d["a"] = 1
    d["b"] = 2

    assert d["a"] == 1
    assert d["b"] == 2
    assert d["c"] == 0

    d = SynchronizedDefaultDict(threading.RLock)

    with d["a"]:
        assert isinstance(d["a"], type(threading.RLock()))


class TestOnce:
    def test_executes_only_once(self):
        once = Once()

        res = []

        def fn():
            res.append(1)

        assert once.do(fn) is None
        assert once.do(fn) is None
        assert len(res) == 1

    def test_exception_propagates(self):
        once = Once()

        res = []

        def error_fn():
            res.append(1)
            raise ValueError("oops")

        # Only the first call raises an exception
        with pytest.raises(ValueError, match="oops"):
            once.do(error_fn)

        once.do(error_fn)  # No exception raised

        assert len(res) == 1

    def test_different_functions(self):
        once = Once()

        res = []
        fn_1 = lambda: res.append(1)  # noqa
        fn_2 = lambda: res.append(2)  # noqa

        # Only the first call to Once is run
        once.do(fn_1)
        once.do(fn_2)

        assert len(res) == 1
        assert res[0] == 1


class TestOnceDecorator:
    def test_executes_only_once(self):
        counter = []

        @once_func
        def increment():
            counter.append(1)
            return sum(counter)

        result1 = increment()
        result2 = increment()
        result3 = increment()

        assert len(counter) == 1
        assert result1 == 1
        assert result2 == 1
        assert result3 == 1

    def test_with_arguments(self):
        calls = []

        @once_func
        def add(a, b):
            calls.append((a, b))
            return a + b

        result1 = add(2, 3)
        result2 = add(5, 7)
        result3 = add(1, 1)

        assert len(calls) == 1
        assert calls[0] == (2, 3)
        assert result1 == 5
        assert result2 == 5
        assert result3 == 5

    def test_exception_reraises(self):
        call_count = []

        @once_func
        def failing_function():
            call_count.append(1)
            raise ValueError("Something went wrong")

        with pytest.raises(ValueError, match="Something went wrong"):
            failing_function()

        with pytest.raises(ValueError, match="Something went wrong"):
            failing_function()

        with pytest.raises(ValueError, match="Something went wrong"):
            failing_function()

        assert len(call_count) == 1

    def test_none_return_value(self):
        calls = []

        @once_func
        def returns_none():
            calls.append(1)
            return None

        result1 = returns_none()
        result2 = returns_none()

        assert len(calls) == 1
        assert result1 is None
        assert result2 is None

    def test_preserves_function_metadata(self):
        @once_func
        def documented_function():
            """This is a docstring."""
            return 42

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This is a docstring."

    def test_multiple_decorated_functions(self):
        counter1 = []
        counter2 = []

        @once_func
        def function1():
            counter1.append(1)
            return "func1"

        @once_func
        def function2():
            counter2.append(1)
            return "func2"

        assert function1() == "func1"
        assert function1() == "func1"
        assert function2() == "func2"
        assert function2() == "func2"

        assert len(counter1) == 1
        assert len(counter2) == 1

    def test_with_kwargs(self):
        calls = []

        @once_func
        def with_kwargs(a, b=10, **kwargs):
            calls.append((a, b, kwargs))
            return "result"

        result1 = with_kwargs(1, b=20, extra="data")
        result2 = with_kwargs(5)

        assert len(calls) == 1
        assert calls[0] == (1, 20, {"extra": "data"})
        assert result1 == "result"
        assert result2 == "result"
