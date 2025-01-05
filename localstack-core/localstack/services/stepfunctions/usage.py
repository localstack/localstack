"""
Usage reporting for StepFunctions service
"""

from localstack.utils.analytics.usage import UsageCounter

# Count of StepFunctions being created with JSONata QueryLanguage
jsonata_create_counter = UsageCounter("stepfunctions:jsonata:create")

# Count of StepFunctions being created with JSONPath QueryLanguage
jsonpath_create_counter = UsageCounter("stepfunctions:jsonpath:create")

# Count of StepFunctions being created that use Variable Sampling or the Assign block
variables_create_counter = UsageCounter("stepfunctions:variables:create")

# Successful invocations (also including expected error cases in line with AWS behaviour)
invocation_counter = UsageCounter("stepfunctions:invocation")

# Unexpected errors that we do not account for
error_counter = UsageCounter("stepfunctions:error")
