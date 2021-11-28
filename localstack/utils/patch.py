import functools
import inspect
from typing import Any, Callable


def get_defining_object(method):
    """Returns either the class or the module that defines the given function/method."""
    # adapted from https://stackoverflow.com/a/25959545/804840
    if inspect.ismethod(method):
        for cls in inspect.getmro(method.__self__.__class__):
            if cls.__dict__.get(method.__name__) is method:
                return cls
        method = method.__func__  # fallback to __qualname__ parsing

    if inspect.isfunction(method):
        class_name = method.__qualname__.split(".<locals>", 1)[0].rsplit(".", 1)[0]
        try:
            cls = getattr(inspect.getmodule(method), class_name)
        except AttributeError:
            cls = method.__globals__.get(class_name)

        if isinstance(cls, type):
            return cls

    return inspect.getmodule(method)


def create_patch_proxy(target: Callable, new: Callable):
    """
    Creates a proxy that calls `new` but passes as first argument the target.
    """

    @functools.wraps(target)
    def proxy(*args, **kwargs):
        return new(target, *args, **kwargs)

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

        if pass_target:
            new = create_patch_proxy(target, fn)
        else:
            new = fn

        return Patch(obj, name, new)


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

    :param target: the function or method to patch
    :param pass_target: whether to pass the target to the patching function as first parameter
    :returns: the same function, but with a patch created
    """

    def wrapper(fn):
        fn.patch = Patch.function(target, fn, pass_target=pass_target)
        fn.patch.apply()
        return fn

    return wrapper
