"""
During initial rollout of the test selection in PRs this is additionally limited to the opt-in list below.

A test selection will only be effective if all files that would be selected under the testselection also have at least one match in the list below.
"""

OPT_IN = [
    # SFN
    "localstack/services/stepfunctions",
    "tests/aws/services/stepfunctions",
    # CFn
    # probably the riskiest here since CFn tests are not as isolated as the rest
    "localstack/services/cloudformation",
    "tests/aws/services/cloudformation",
    # Lambda
    "localstack/services/lambda_",
    "tests/aws/services/lambda_",
]
