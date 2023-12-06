"""
Usage reporting for Lambda service
"""
from localstack.utils.analytics.usage import UsageCounter, UsageSetCounter

# usage of lambda hot-reload feature
hotreload = UsageCounter("lambda:hotreload", aggregations=["sum"])

# number of function invocations per Lambda runtime (e.g. python3.7 invoked 10x times, nodejs14.x invoked 3x times, ...)
runtime = UsageSetCounter("lambda:invokedruntime")
