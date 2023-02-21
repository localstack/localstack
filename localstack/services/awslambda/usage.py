from localstack.utils.analytics.usage import UsageCounter, UsageSetCounter

hotreload = UsageCounter("lambda:hotreload", aggregations=["sum"])
initduration = UsageCounter("lambda:initduration", aggregations=["min", "max", "mean", "median"])
runtime = UsageSetCounter("lambda:invokedruntime")
