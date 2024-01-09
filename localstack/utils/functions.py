"""Higher-order functional tools."""
import functools
import inspect
import logging
from typing import Any, Callable, Dict, NamedTuple, Optional, Tuple

LOG = logging.getLogger(__name__)


def run_safe(_python_lambda, *args, _default=None, **kwargs):
    print_error = kwargs.get("print_error", False)
    try:
        return _python_lambda(*args, **kwargs)
    except Exception as e:
        if print_error:
            LOG.warning("Unable to execute function: %s", e)
        return _default


class Result(NamedTuple):
    """Wraps the possible outcomes of a function call, that can either be a value or an exception."""

    error: Optional[Exception]
    value: Optional[Any] = None

    @property
    def has_error(self) -> bool:
        return self.error is not None


def call_safe(
    func: Callable, args: Tuple = None, kwargs: Dict = None, exception_message: str = None
) -> Optional[Any]:
    """
    Call the given function with the given arguments, and if it fails, log the given exception_message.
    If logging.DEBUG is set for the logger, then we also log the traceback.

    :param func: function to call
    :param args: arguments to pass
    :param kwargs: keyword arguments to pass
    :param exception_message: message to log on exception
    :return: whatever the func returns
    """
    result = call_safe_with_result(func, args, kwargs, exception_message)
    if result.has_error:
        return None
    return result.value


def call_safe_with_result(
    func: Callable, args: Tuple = None, kwargs: Dict = None, exception_message: str = None
) -> Result:
    """Similar as call_safe, but returns a Result object that contains the value returned by func or the raised
    exception."""
    if exception_message is None:
        exception_message = "error calling function %s" % func.__name__
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}

    try:
        value = func(*args, **kwargs)
        return Result(value=value, error=None)
    except Exception as e:
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.exception(exception_message)
        else:
            LOG.warning("%s: %s", exception_message, e)
        return Result(error=e)


def prevent_stack_overflow(match_parameters=False):
    """Function decorator to protect a function from stack overflows -
    raises an exception if a (potential) infinite recursion is detected."""

    def _decorator(wrapped):
        @functools.wraps(wrapped)
        def func(*args, **kwargs):
            def _matches(frame):
                if frame.function != wrapped.__name__:
                    return False
                frame = frame.frame

                if not match_parameters:
                    return False

                # construct dict of arguments this stack frame has been called with
                prev_call_args = {
                    frame.f_code.co_varnames[i]: frame.f_locals[frame.f_code.co_varnames[i]]
                    for i in range(frame.f_code.co_argcount)
                }

                # construct dict of arguments the original function has been called with
                sig = inspect.signature(wrapped)
                this_call_args = dict(zip(sig.parameters.keys(), args))
                this_call_args.update(kwargs)

                return prev_call_args == this_call_args

            matching_frames = [frame[2] for frame in inspect.stack(context=1) if _matches(frame)]
            if matching_frames:
                raise RecursionError("(Potential) infinite recursion detected")
            return wrapped(*args, **kwargs)

        return func

    return _decorator


def empty_context_manager():
    import contextlib

    return contextlib.nullcontext()
