from typing import TypedDict

from localstack.aws.api import RequestContext

INTERNAL_CONTEXT_TRACE_CONTEXT = "_trace_context"


class TraceContext(TypedDict):
    trace_id: str | None
    parent_id: str | None


def is_tracing_enabled() -> bool:
    """Check if tracing is enabled, this needs to be patched by an extension that requires tracing."""
    return False


def get_trace_context(context: RequestContext) -> TraceContext | None:
    """Retrieve a data transfer object with only the relevant subset of the context.
    Required for tracing propagation and to keep performance overhead low."""
    if is_tracing_enabled():
        if trace_context := context.get(INTERNAL_CONTEXT_TRACE_CONTEXT) is None:
            trace_context = TraceContext(trace_id=None, parent_id=None)
            setattr(context, INTERNAL_CONTEXT_TRACE_CONTEXT, trace_context)
        return trace_context

    else:
        return None
