from typing import TypedDict

from localstack.aws.api import RequestContext


class TraceContext(TypedDict):
    trace_id: str
    parent_id: str


def get_trace_context(context: RequestContext) -> TraceContext | None:
    """Generate a data transfer object with only the relevant subset of the context.
    Required for tracing propagation and to keep performance overhead low."""
    trace_id = context.get("trace_id")
    parent_id = context.get("parent_id")

    if trace_id is not None or parent_id is not None:
        return TraceContext(trace_id=trace_id, parent_id=parent_id)

    return None
