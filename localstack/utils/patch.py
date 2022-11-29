import functools
import inspect
import types
from typing import Any, Callable, List


def get_defining_object(method):
    """Returns either the class or the module that defines the given function/method."""
    # adapted from https://stackoverflow.com/a/25959545/804840
    if inspect.ismethod(method):
        return method.__self__

    if inspect.isfunction(method):
        class_name = method.__qualname__.split(".<locals>", 1)[0].rsplit(".", 1)[0]
        try:
            # method is not bound but referenced by a class, like MyClass.mymethod
            cls = getattr(inspect.getmodule(method), class_name)
        except AttributeError:
            cls = method.__globals__.get(class_name)

        if isinstance(cls, type):
            return cls

    # method is a module-level function
    return inspect.getmodule(method)


def create_patch_proxy(target: Callable, new: Callable):
    """
    Creates a proxy that calls `new` but passes as first argument the target.
    """

    @functools.wraps(target)
    def proxy(*args, **kwargs):
        if _is_bound_method:
            # bound object "self" is passed as first argument if this is a bound method
            args = args[1:]
        return new(target, *args, **kwargs)

    _is_bound_method = inspect.ismethod(target)
    if _is_bound_method:
        proxy = types.MethodType(proxy, target.__self__)

    return proxy


class Patch:
    obj: Any
    name: str
    new: Any

    def __init__(self, obj: Any, name: str, new: Any) -> None:
        super().__init__()
        self.obj = obj
        self.name = name
        self.old = getattr(self.obj, name)
        self.new = new
        self.is_applied = False

    def apply(self):
        setattr(self.obj, self.name, self.new)
        self.is_applied = True

    def undo(self):
        setattr(self.obj, self.name, self.old)
        self.is_applied = False

    def __enter__(self):
        self.apply()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.undo()
        return self

    @staticmethod
    def function(target: Callable, fn: Callable, pass_target: bool = True):
        obj = get_defining_object(target)
        name = target.__name__

        is_class_instance = not inspect.isclass(obj) and not inspect.ismodule(obj)
        if is_class_instance:
            # special case: If the defining object is not a class, but a class instance,
            # then we need to bind the patch function to the target object. Also, we need
            # to ensure that the final patched method has the same name as the original
            # method on the defining object (required for restoring objects with patched
            # methods from persistence, to avoid AttributeError).
            fn.__name__ = name
            fn = types.MethodType(fn, obj)

        if pass_target:
            new = create_patch_proxy(target, fn)
        else:
            new = fn

        return Patch(obj, name, new)


class Patches:
    patches: List[Patch]

    def __init__(self, patches: List[Patch] = None) -> None:
        super().__init__()

        self.patches = []
        if patches:
            self.patches.extend(patches)

    def apply(self):
        for p in self.patches:
            p.apply()

    def undo(self):
        for p in self.patches:
            p.undo()

    def __enter__(self):
        self.apply()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.undo()

    def add(self, patch: Patch):
        self.patches.append(patch)

    def function(self, target: Callable, fn: Callable, pass_target: bool = True):
        self.add(Patch.function(target, fn, pass_target))


def patch(target, pass_target=True):
    """
    Function decorator to create a patch via Patch.function and immediately apply it.

    Example::

        def echo(string):
            return "echo " + string

        @patch(target=echo)
        def echo_uppercase(target, string):
            return target(string).upper()

        echo("foo")
        # will print "ECHO FOO"

        echo_uppercase.patch.undo()
        echo("foo")
        # will print "echo foo"

    When you are patching classes, with ``pass_target=True``, the unbound function will be passed as the first
    argument before ``self``.

    For example::

        @patch(target=MyEchoer.do_echo, pass_target=True)
        def my_patch(fn, self, *args):
            return fn(self, *args)

        @patch(target=MyEchoer.do_echo, pass_target=False)
        def my_patch(self, *args):
            ...

    :param target: the function or method to patch
    :param pass_target: whether to pass the target to the patching function as first parameter
    :returns: the same function, but with a patch created
    """

    def wrapper(fn):
        fn.patch = Patch.function(target, fn, pass_target=pass_target)
        fn.patch.apply()
        return fn

    return wrapper
