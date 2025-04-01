"""
Usage analytics for SNS internal endpoints
"""

from localstack.utils.analytics.metrics import Counter

# number of times SNS internal endpoint per resource types
# (e.g. PlatformMessage invoked 10x times, SMSMessage invoked 3x times, SubscriptionToken...)
internal_api_calls = Counter(namespace="sns", name="internal_api_call", labels=["resource_type"])
