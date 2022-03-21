import pytest

from localstack.utils.objects import SubtypesInstanceManager


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
