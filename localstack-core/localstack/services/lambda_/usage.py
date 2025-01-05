"""
Usage reporting for Lambda service
"""

from localstack.utils.analytics.usage import UsageCounter, UsageSetCounter

# number of Lambda API operations for CreateFunction using hot reloading
hotreload = UsageCounter("lambda:hotreload")

# number of function invocations per Lambda runtime (e.g. python3.7 invoked 10x times, nodejs14.x invoked 3x times, ...)
runtime = UsageSetCounter("lambda:invokedruntime")

# number of event source mapping invocations per source (e.g. aws:sqs, aws:kafka, SelfManagedKafka)
esm_invocation = UsageSetCounter("lambda:esm:invocation")

# number of event source mapping errors per source (e.g. aws:sqs, aws:kafka, SelfManagedKafka)
esm_error = UsageSetCounter("lambda:esm:error")
