from localstack.utils.analytics.metrics import Counter

COUNTER_NAMESPACE = "cloudformation"

# XXX the name is resourcetype to maintain backwards compatibility with the previous counters (when using UsageSetCounter)
resource_types = Counter(namespace=COUNTER_NAMESPACE, name="resourcetype", labels=["resource_type"])

# XXX the name is missingresourcetypes to maintain backwards compatibility with the previous counters (when using UsageSetCounter)
missing_resource_types = Counter(
    namespace=COUNTER_NAMESPACE, name="missingresourcetypes", labels=["missing_resource_type"]
)
