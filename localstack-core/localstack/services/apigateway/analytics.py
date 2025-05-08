from localstack.utils.analytics.metrics import Counter

invocation_counter = Counter(
    namespace="apigateway", name="rest_api_execute", labels=["invocation_type"]
)
