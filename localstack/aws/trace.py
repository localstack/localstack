import dataclasses
import inspect
import logging
import time
from typing import Any, Callable

from werkzeug.datastructures import Headers

from localstack.http import Response
from localstack.utils.patch import Patch, Patches

from .api import RequestContext
from .chain import ExceptionHandler, Handler, HandlerChain

LOG = logging.getLogger(__name__)


class Action:
    """
    Encapsulates something that the handler performed on the request context, request, or response objects.
    """

    name: str

    def __init__(self, name: str):
        self.name = name

    def __repr__(self):
        return self.name


class SetAttributeAction(Action):
    """
    The handler set an attribute of the request context or something else.
    """

    key: str
    value: Any | None

    def __init__(self, key: str, value: Any | None = None):
        super().__init__("set")
        self.key = key
        self.value = value

    def __repr__(self):
        if self.value is None:
            return f"set {self.key}"
        return f"set {self.key} = {self.value!r}"


class ModifyHeadersAction(Action):
    """
    The handler modified headers in some way, either adding, updating, or removing headers.
    """

    def __init__(self, name: str, before: Headers, after: Headers):
        super().__init__(name)
        self.before = before
        self.after = after

    @property
    def header_actions(self) -> list[Action]:
        after = self.after
        before = self.before

        actions = []

        headers_set = dict(set(after.items()) - set(before.items()))
        headers_removed = {k: v for k, v in before.items() if k not in after}

        for k, v in headers_set.items():
            actions.append(Action(f"set '{k}: {v}'"))
        for k, v in headers_removed.items():
            actions.append(Action(f"del '{k}: {v}'"))

        return actions


@dataclasses.dataclass
class HandlerTrace:
    handler: Handler
    """The handler"""
    duration_ms: float
    """The runtime duration of the handler in milliseconds"""
    actions: list[Action]
    """The actions the handler chain performed"""

    @property
    def handler_module(self):
        return self.handler.__module__

    @property
    def handler_name(self):
        if inspect.isfunction(self.handler):
            return self.handler.__name__
        else:
            return self.handler.__class__.__name__


def _log_method_call(name: str, actions: list[Action]):
    """Creates a wrapper around the original method `_fn`. It appends an action to the `actions`
    list indicating that the function was called and then returns the original function."""

    def _proxy(self, _fn, *args, **kwargs):
        actions.append(Action(f"call {name}"))
        return _fn(*args, **kwargs)

    return _proxy


class TracingHandlerBase:
    """
    This class is a Handler that records a trace of the execution of another request handler. It has two
    attributes: `trace`, which stores the tracing information, and `delegate`, which is the handler or
    exception handler that will be traced.
    """

    trace: HandlerTrace | None
    delegate: Handler | ExceptionHandler

    def __init__(self, delegate: Handler | ExceptionHandler):
        self.trace = None
        self.delegate = delegate

    def do_trace_call(
        self, fn: Callable, chain: HandlerChain, context: RequestContext, response: Response
    ):
        """
        Wraps the function call with the tracing functionality and records a HandlerTrace.

        The method determines changes made by the request handler to specific aspects of the request.
        Changes made to the request context and the response headers/status by the request handler are then
        examined, and appropriate actions are added to the `actions` list of the trace.

        :param fn: which is the function to be traced, which is the request/response/exception handler
        :param chain: the handler chain
        :param context: the request context
        :param response: the response object
        """
        then = time.perf_counter()

        actions = []

        prev_context = dict(context.__dict__)
        prev_stopped = chain.stopped
        prev_request_identity = id(context.request)
        prev_terminated = chain.terminated
        prev_request_headers = context.request.headers.copy()
        prev_response_headers = response.headers.copy()
        prev_response_status = response.status_code

        # add patches to log invocations or certain functions
        patches = Patches(
            [
                Patch.function(
                    context.request.get_data,
                    _log_method_call("request.get_data", actions),
                ),
                Patch.function(
                    context.request._load_form_data,
                    _log_method_call("request._load_form_data", actions),
                ),
                Patch.function(
                    response.get_data,
                    _log_method_call("response.get_data", actions),
                ),
            ]
        )
        patches.apply()

        try:
            return fn()
        finally:
            now = time.perf_counter()
            # determine some basic things the handler changed in the context
            patches.undo()

            # chain
            if chain.stopped and not prev_stopped:
                actions.append(Action("stop chain"))
            if chain.terminated and not prev_terminated:
                actions.append(Action("terminate chain"))

            # request contex
            if context.region and not prev_context.get("region"):
                actions.append(SetAttributeAction("region", context.region))
            if context.account_id and not prev_context.get("account_id"):
                actions.append(SetAttributeAction("account_id", context.account_id))
            if context.service and not prev_context.get("service"):
                actions.append(SetAttributeAction("service", context.service.service_name))
            if context.operation and not prev_context.get("operation"):
                actions.append(SetAttributeAction("operation", context.operation.name))
            if context.service_request and not prev_context.get("service_request"):
                actions.append(SetAttributeAction("service_request"))
            if context.service_response and not prev_context.get("service_response"):
                actions.append(SetAttributeAction("service_response"))

            # request
            if id(context.request) != prev_request_identity:
                actions.append(Action("replaced request object"))

            # response
            if response.status_code != prev_response_status:
                actions.append(SetAttributeAction("response stats_code", response.status_code))
            if context.request.headers != prev_request_headers:
                actions.append(
                    ModifyHeadersAction(
                        "modify request headers",
                        prev_request_headers,
                        context.request.headers.copy(),
                    )
                )
            if response.headers != prev_response_headers:
                actions.append(
                    ModifyHeadersAction(
                        "modify response headers", prev_response_headers, response.headers.copy()
                    )
                )

            self.trace = HandlerTrace(
                handler=self.delegate, duration_ms=(now - then) * 1000, actions=actions
            )


class TracingHandler(Handler, TracingHandlerBase):
    delegate: Handler

    def __init__(self, delegate: Handler):
        super().__init__(delegate)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        def _call():
            return self.delegate(chain, context, response)

        return self.do_trace_call(_call, chain, context, response)


class TracingExceptionHandler(ExceptionHandler, TracingHandlerBase):
    delegate: ExceptionHandler

    def __init__(self, delegate: ExceptionHandler):
        super().__init__(delegate)

    def __call__(
        self, chain: HandlerChain, exception: Exception, context: RequestContext, response: Response
    ):
        def _call():
            return self.delegate(chain, exception, context, response)

        return self.do_trace_call(_call, chain, context, response)


class TracingHandlerChain(HandlerChain):
    """
    DebuggingHandlerChain - A subclass of HandlerChain for logging and tracing handlers.

    Attributes:
    - duration (float): Total time taken for handling request in milliseconds.
    - request_handler_traces (list[HandlerTrace]): List of request handler traces.
    - response_handler_traces (list[HandlerTrace]): List of response handler traces.
    - exception_handler_traces (list[HandlerTrace]): List of exception handler traces.

    Methods:
    - handle(context: RequestContext, response: Response):
    - _call_response_handlers(response): .
    - _call_exception_handlers(e, response): Overrides HandlerChain's _call_exception_handlers method and adds tracing handler to exception handlers.
    - _log_report(): Logs the trace report in the format specified.
    """

    duration: float
    request_handler_traces: list[HandlerTrace]
    response_handler_traces: list[HandlerTrace]
    exception_handler_traces: list[HandlerTrace]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_handler_traces = []
        self.response_handler_traces = []
        self.exception_handler_traces = []

    def handle(self, context: RequestContext, response: Response):
        """Overrides HandlerChain's handle method and adds tracing handler to request handlers. Logs the trace
        report with request and response details."""
        then = time.perf_counter()
        try:
            self.request_handlers = [TracingHandler(handler) for handler in self.request_handlers]
            return super().handle(context, response)
        finally:
            self.duration = (time.perf_counter() - then) * 1000
            self.request_handler_traces = [handler.trace for handler in self.request_handlers]
            self._log_report()

    def _call_response_handlers(self, response):
        self.response_handlers = [TracingHandler(handler) for handler in self.response_handlers]
        try:
            return super()._call_response_handlers(response)
        finally:
            self.response_handler_traces = [handler.trace for handler in self.response_handlers]

    def _call_exception_handlers(self, e, response):
        self.exception_handlers = [
            TracingExceptionHandler(handler) for handler in self.exception_handlers
        ]
        try:
            return super()._call_exception_handlers(e, response)
        finally:
            self.exception_handler_traces = [handler.trace for handler in self.exception_handlers]

    def _log_report(self):
        report = []
        request = self.context.request
        response = self.response

        def _append_traces(traces: list[HandlerTrace]):
            """Format and appends a list of traces to the report, and recursively append the trace's
            actions (if any)."""

            for trace in traces:
                if trace is None:
                    continue

                report.append(
                    f"{trace.handler_module:43s} {trace.handler_name:30s} {trace.duration_ms:8.2f}ms"
                )
                _append_actions(trace.actions, 46)

        def _append_actions(actions: list[Action], indent: int):
            for action in actions:
                report.append((" " * indent) + f"- {action!r}")

                if isinstance(action, ModifyHeadersAction):
                    _append_actions(action.header_actions, indent + 2)

        report.append(f"request:  {request.method} {request.url}")
        report.append(f"response: {response.status_code}")
        report.append("---- request handlers " + ("-" * 63))
        _append_traces(self.request_handler_traces)
        report.append("---- response handlers " + ("-" * 63))
        _append_traces(self.response_handler_traces)
        report.append("---- exception handlers " + ("-" * 63))
        _append_traces(self.exception_handler_traces)
        # Add a separator and total duration value to the end of the report
        report.append(f"{'=' * 68} total {self.duration:8.2f}ms")

        LOG.info("handler chain trace report:\n%s\n%s", "=" * 85, "\n".join(report))
