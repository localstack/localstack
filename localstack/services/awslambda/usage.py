"""
Usage reporting for Lambda service
"""
from localstack.utils.analytics.usage import UsageCounter, UsageSetCounter

# usage of lambda hot-reload feature
hotreload = UsageCounter("lambda:hotreload", aggregations=["sum"])

# used unique lambda runtimes (e.g. python3.7)
runtime = UsageSetCounter("lambda:invokedruntime")
