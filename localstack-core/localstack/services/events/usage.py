from localstack.utils.analytics.usage import UsageSetCounter

# number of pipe invocations per source (e.g. aws:sqs, aws:kafka, SelfManagedKafka) and target (e.g., aws:lambda)
rule_invocation = UsageSetCounter("events:rule:invocation")

# number of pipe errors per source (e.g. aws:sqs, aws:kafka, SelfManagedKafka) and target (e.g., aws:lambda)
rule_error = UsageSetCounter("events:rule:error")
