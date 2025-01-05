from localstack.utils.analytics.usage import UsageSetCounter

# number of successful EventBridge rule invocations per target (e.g., aws:lambda)
rule_invocation = UsageSetCounter("events:rule:invocation")

# number of EventBridge rule errors per target (e.g., aws:lambda)
rule_error = UsageSetCounter("events:rule:error")
