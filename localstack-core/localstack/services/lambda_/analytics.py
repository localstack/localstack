from enum import StrEnum

from localstack.utils.analytics.metrics import Counter

NAMESPACE = "lambda"

hotreload_counter = Counter(namespace=NAMESPACE, name="hotreload", labels=["operation"])

function_counter = Counter(
    namespace=NAMESPACE,
    name="function",
    labels=[
        "operation",
        "status",
        "runtime",
        "package_type",
        # only for operation "invoke"
        "invocation_type",
    ],
)


class FunctionOperation(StrEnum):
    invoke = "invoke"
    create = "create"


class FunctionStatus(StrEnum):
    success = "success"
    zero_reserved_concurrency_error = "zero_reserved_concurrency_error"
    event_age_exceeded_error = "event_age_exceeded_error"
    throttle_error = "throttle_error"
    system_error = "system_error"
    unhandled_state_error = "unhandled_state_error"
    failed_state_error = "failed_state_error"
    pending_state_error = "pending_state_error"
    invalid_payload_error = "invalid_payload_error"
    invocation_error = "invocation_error"


esm_counter = Counter(namespace=NAMESPACE, name="esm", labels=["source", "status"])


class EsmExecutionStatus(StrEnum):
    success = "success"
    partial_batch_failure_error = "partial_batch_failure_error"
    target_invocation_error = "target_invocation_error"
    unhandled_error = "unhandled_error"
    source_poller_error = "source_poller_error"
    # TODO: Add tracking for filter error. Options:
    #  a) raise filter exception and track it in the esm_worker
    #  b) somehow add tracking in the individual pollers
    filter_error = "filter_error"
