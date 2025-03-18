"""
Usage reporting for StepFunctions service
"""

from localstack.utils.analytics.metrics import Counter

# Initialize a counter to record the usage of language features for each state machine.
language_features_counter = Counter(
    namespace="stepfunctions",
    name="language_features_used",
    labels=["query_language", "uses_variables"],
)
