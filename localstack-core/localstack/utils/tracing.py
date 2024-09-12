from typing import TypedDict

from localstack.aws.api import RequestContext

INTERNAL_CONTEXT_EVENTSTUDIO_TRACING_PARAMETER = "_eventstudio_tracing_parameter"


class TraceContext(TypedDict):
    trace_id: str | None
    parent_id: str | None


def get_trace_context(context: RequestContext) -> TraceContext | None:
    """Generate a data transfer object with only the relevant subset of the context.
    Required for tracing propagation and to keep performance overhead low."""
    eventstudio_tracing_parameter = context.get(INTERNAL_CONTEXT_EVENTSTUDIO_TRACING_PARAMETER)

    if eventstudio_tracing_parameter is not None:
        trace_id = context.get("trace_id")
        parent_id = context.get("parent_id")

        if trace_id is not None or parent_id is not None:
            return TraceContext(trace_id=trace_id, parent_id=parent_id)

    return None
