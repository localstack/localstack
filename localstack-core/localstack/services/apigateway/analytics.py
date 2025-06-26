from localstack.utils.analytics.metrics import LabeledCounter

invocation_counter = LabeledCounter(
    namespace="apigateway", name="rest_api_execute", labels=["invocation_type"]
)
