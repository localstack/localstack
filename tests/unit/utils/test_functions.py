import pytest

from localstack.utils.functions import Result, call_safe_with_result


def test_call_safe_ok():
    def _my_fun():
        return 2 + 2

    result = call_safe_with_result(_my_fun)
    assert not result.has_error
    assert result.value == 4


def test_call_safe_none():
    def _my_fun():
        return None

    result = call_safe_with_result(_my_fun)
    assert not result.has_error
    assert result.value is None


def test_call_safe_error():
    def _my_fun():
        d = {"foo": "bar"}
        return d["baz"]

    result = call_safe_with_result(_my_fun)
    assert result.has_error
    assert isinstance(result.error, KeyError)


def test_result_init():
    with pytest.raises(TypeError):
        Result()  # type: ignore

    result_ok = Result(value=1, error=None)
    assert not result_ok.has_error
    assert result_ok.value == 1

    result_error = Result(value=1, error=Exception())
    assert result_error.has_error
    assert isinstance(result_error.error, Exception)
