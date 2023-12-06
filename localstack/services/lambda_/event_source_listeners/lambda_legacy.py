# TODO: remove this legacy construct when re-working event source mapping.
class LegacyInvocationResult:
    """Data structure for representing the result of a Lambda invocation in the old Lambda provider.
    Could not be removed upon 3.0 because it was still used in the `sqs_event_source_listener.py` and `adapters.py`.
    """

    def __init__(self, result, log_output=""):
        if isinstance(result, LegacyInvocationResult):
            raise Exception("Unexpected invocation result type: %s" % result)
        self.result = result
        self.log_output = log_output or ""
