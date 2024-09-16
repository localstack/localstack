import pytest

from localstack.utils.patch import Patch, get_defining_object, patch


def echo(arg):
    return f"echo: {arg}"


class MyEchoer:
    def do_echo(self, arg):
        return f"do_echo: {arg}"

    @classmethod
    def do_class_echo(cls, arg):
        return f"do_class_echo: {arg}"

    @staticmethod
    def do_static_echo(arg):
        return f"do_static_echo: {arg}"


def test_patch_context_manager():
    assert echo("foo") == "echo: foo"

    def monkey(arg):
        return f"monkey: {arg}"

    with Patch(get_defining_object(echo), "echo", monkey):
        assert echo("foo") == "monkey: foo"

    assert echo("foo") == "echo: foo"


def test_patch_with_pass_target_context_manager():
    assert echo("foo") == "echo: foo"

    def uppercase(target, arg):
        return target(arg).upper()

    with Patch(get_defining_object(echo), "echo", uppercase):
        assert echo("foo") == "ECHO: FOO"

    assert echo("foo") == "echo: foo"


def test_patch_decorator():
    @patch(target=echo, pass_target=False)
    def monkey(arg):
        return f"monkey: {arg}"

    assert echo("foo") == "monkey: foo"
    monkey.patch.undo()
    assert echo("foo") == "echo: foo"


def test_patch_decorator_with_pass_target():
    @patch(target=echo)
    def uppercase(target, arg):
        return target(arg).upper()

    assert echo("foo") == "ECHO: FOO"
    uppercase.patch.undo()
    assert echo("foo") == "echo: foo"


def test_patch_decorator_on_method():
    @patch(target=MyEchoer.do_echo)
    def uppercase(target, self, arg):
        return target(self, arg).upper()

    obj = MyEchoer()

    assert obj.do_echo("foo") == "DO_ECHO: FOO"
    uppercase.patch.undo()
    assert obj.do_echo("foo") == "do_echo: foo"
    assert MyEchoer().do_echo("foo") == "do_echo: foo"


def test_patch_decorator_on_bound_method_with_pass_target():
    obj = MyEchoer()

    @patch(target=obj.do_echo)
    def uppercase(self, target, arg):
        return target(arg).upper()

    assert obj.do_echo("foo") == "DO_ECHO: FOO"
    assert MyEchoer().do_echo("foo") == "do_echo: foo"
    uppercase.patch.undo()

    assert obj.do_echo("foo") == "do_echo: foo"
    assert MyEchoer().do_echo("foo") == "do_echo: foo"


def test_patch_decorator_on_bound_method():
    obj = MyEchoer()

    @patch(target=obj.do_echo, pass_target=False)
    def monkey(self, arg):
        return f"monkey: {arg}"

    assert obj.do_echo("foo") == "monkey: foo"
    assert MyEchoer().do_echo("foo") == "do_echo: foo"
    monkey.patch.undo()

    assert obj.do_echo("foo") == "do_echo: foo"
    assert MyEchoer().do_echo("foo") == "do_echo: foo"


def test_patch_decorator_twice_on_method():
    @patch(target=MyEchoer.do_echo)
    def monkey1(self, *args):
        return f"monkey: {args[-1]}"

    @patch(target=MyEchoer.do_echo)
    def monkey2(fn, self, *args):
        return f"monkey 2: {fn(*args)}"

    obj = MyEchoer()

    try:
        assert obj.do_echo("foo") == "monkey 2: monkey: foo"
        assert MyEchoer().do_echo("foo") == "monkey 2: monkey: foo"
    finally:
        monkey2.patch.undo()
        monkey1.patch.undo()

    assert obj.do_echo("foo") == "do_echo: foo"
    assert MyEchoer().do_echo("foo") == "do_echo: foo"


@pytest.mark.parametrize("pass_target", [True, False])
def test_patch_decorator_twice_on_bound_method(pass_target):
    obj = MyEchoer()

    @patch(target=obj.do_echo, pass_target=pass_target)
    def monkey1(self, *args):
        return f"monkey: {args[-1]}"

    @patch(target=obj.do_echo, pass_target=True)
    def monkey2(self, fn, *args):
        return f"monkey 2: {fn(*args)}"

    assert obj.do_echo("foo") == "monkey 2: monkey: foo"
    assert MyEchoer().do_echo("foo") == "do_echo: foo"
    monkey2.patch.undo()
    monkey1.patch.undo()

    assert obj.do_echo("foo") == "do_echo: foo"
    assert MyEchoer().do_echo("foo") == "do_echo: foo"


def test_patch_decorator_on_class_method():
    @patch(target=MyEchoer.do_class_echo)
    def uppercase(target, *args):
        if len(args) > 1:
            # this happens when the method is called on an object, the first arg will be the object
            arg = args[1]
        else:
            arg = args[0]

        return target(arg).upper()

    assert MyEchoer.do_class_echo("foo") == "DO_CLASS_ECHO: FOO"
    assert MyEchoer().do_class_echo("foo") == "DO_CLASS_ECHO: FOO"
    uppercase.patch.undo()
    assert MyEchoer.do_class_echo("foo") == "do_class_echo: foo"
    assert MyEchoer().do_class_echo("foo") == "do_class_echo: foo"


def test_get_defining_object():
    from localstack.utils import strings
    from localstack.utils.strings import short_uid

    # module
    assert get_defining_object(short_uid) == strings

    # unbound method (=function defined by a class)
    assert get_defining_object(MyEchoer.do_echo) == MyEchoer

    obj = MyEchoer()
    # bound method
    assert get_defining_object(obj.do_echo) == obj

    # class method referenced by an object
    assert get_defining_object(obj.do_class_echo) == MyEchoer

    # class method referenced by the class
    assert get_defining_object(MyEchoer.do_class_echo) == MyEchoer

    # static method (= function defined by a class)
    assert get_defining_object(MyEchoer.do_static_echo) == MyEchoer


def test_to_string():
    @patch(MyEchoer.do_echo)
    def monkey(self, *args):
        return f"monkey: {args[-1]}"

    applied = [str(p) for p in Patch.applied_patches]

    value = "Patch(function(tests.unit.utils.test_patch:MyEchoer.do_echo) -> function(tests.unit.utils.test_patch:test_to_string.<locals>.monkey), applied=True)"
    assert value in applied
    assert str(monkey.patch) == value
