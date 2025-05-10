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

# Initialize a counter to record the use of each execution type.
execution_type_counter = Counter(
    namespace="stepfunctions", name="execution_type", labels=["is_mock_test_case"]
)
