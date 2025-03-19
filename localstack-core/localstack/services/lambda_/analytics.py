from enum import StrEnum

from localstack.utils.analytics.metrics import Counter

NAMESPACE = "lambda"

hotreload_counter = Counter(namespace=NAMESPACE, name="hotreload", labels=["operation"])

function_counter = Counter(
    namespace=NAMESPACE,
    name="function",
    labels=[
        "operation",
        "runtime",
        "status",
        "invocation_type",
    ],
)


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
