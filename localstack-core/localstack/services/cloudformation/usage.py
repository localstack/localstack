from localstack.utils.analytics.metrics import Counter

COUNTER_NAMESPACE = "cloudformation"

resources = Counter(
    namespace=COUNTER_NAMESPACE, name="resources", labels=["resource_type", "missing"]
)
