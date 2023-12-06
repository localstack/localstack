from unittest.mock import MagicMock

import pytest

from localstack.utils.objects import SubtypesInstanceManager, singleton_factory


def test_subtypes_instance_manager():
    class BaseClass(SubtypesInstanceManager):
        def foo(self):
            pass

    class C1(BaseClass):
        @staticmethod
        def impl_name() -> str:
            return "c1"

        def foo(self):
            return "bar"

    instance1 = BaseClass.get("c1")
    assert instance1
    assert BaseClass.get("c1") == instance1
    assert instance1.foo() == "bar"
    with pytest.raises(Exception):
        assert BaseClass.get("c2")

    class C2(BaseClass):
        @staticmethod
        def impl_name() -> str:
            return "c2"

        def foo(self):
            return "baz"

    instance2 = BaseClass.get("c2")
    assert BaseClass.get("c2") == instance2
    assert instance2.foo() == "baz"


class TestSingletonFactory:
    def test_call_and_clear(self):
        mock = MagicMock()
        mock.return_value = "foobar"

        @singleton_factory
        def my_singleton():
            return mock()

        assert my_singleton() == mock.return_value
        mock.assert_called_once()

        assert my_singleton() == mock.return_value
        mock.assert_called_once()

        my_singleton.clear()

        assert my_singleton() == mock.return_value
        mock.assert_has_calls([(), ()])

        assert my_singleton() == mock.return_value
        mock.assert_has_calls([(), ()])

    def test_exception_does_not_set_a_value(self):
        mock = MagicMock()

        @singleton_factory
        def my_singleton():
            mock()
            raise ValueError("oh noes")

        with pytest.raises(ValueError):
            my_singleton()

        mock.assert_has_calls([()])

        with pytest.raises(ValueError):
            my_singleton()

        mock.assert_has_calls([(), ()])

    def test_set_none_value_does_not_set_singleton(self):
        mock = MagicMock()
        mock.return_value = None

        @singleton_factory
        def my_singleton():
            return mock()

        assert my_singleton() is None
        mock.assert_has_calls([()])

        assert my_singleton() is None
        mock.assert_has_calls([(), ()])

    def test_set_falsy_value_sets_singleton(self):
        mock = MagicMock()
        mock.return_value = False

        @singleton_factory
        def my_singleton():
            return mock()

        assert my_singleton() is False
        mock.assert_called_once()

        assert my_singleton() is False
        mock.assert_called_once()
