"""
Usage reporting for StepFunctions service
"""

from localstack.utils.analytics.metrics import LabeledCounter

# Initialize a counter to record the usage of language features for each state machine.
language_features_counter = LabeledCounter(
    namespace="stepfunctions",
    name="language_features_used",
    labels=["query_language", "uses_variables"],
)
