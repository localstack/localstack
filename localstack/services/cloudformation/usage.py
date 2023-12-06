from localstack.utils.analytics.usage import UsageSetCounter

resource_type = UsageSetCounter("cloudformation:resourcetype")
missing_resource_types = UsageSetCounter("cloudformation:missingresourcetypes")
