from localstack.utils.analytics.metrics import LabeledCounter

COUNTER_NAMESPACE = "cloudformation"

resources = LabeledCounter(
    namespace=COUNTER_NAMESPACE, name="resources", labels=["resource_type", "missing"]
)
