"""
During initial rollout of the test selection in PRs this is additionally limited to the opt-in list below.

A test selection will only be effective if all files that would be selected under the testselection also have at least one match in the list below.
"""

import fnmatch
from typing import Iterable, Optional

OPT_IN = [
    # acm
    "localstack/services/acm/**",
    "tests/aws/services/acm/**",
    # cloudformation
    # probably the riskiest here since CFn tests are not as isolated as the rest
    "localstack/services/cloudformation/**",
    "tests/aws/services/cloudformation/**",
    # elasticsearch
    "localstack/services/es/**",
    "tests/aws/services/es/**",
    # lambda
    "localstack/services/lambda_/**",
    "tests/aws/services/lambda_/**",
    # sns
    "localstack/services/sns/**",
    "tests/aws/services/sns/**",
    # opensearch
    "localstack/services/opensearch/**",
    "tests/aws/services/opensearch/**",
    # stepfunctions
    "localstack/services/stepfunctions/**",
    "tests/aws/services/stepfunctions/**",
    # secretsmanager
    "localstack/services/secretsmanager/**",
    "tests/aws/services/secretsmanager/**",
    # events
    "localstack/services/events/**",
    "tests/aws/services/events/**",
    # SSM
    "localstack/services/ssm/**",
    "tests/aws/services/ssm/**",
]


def complies_with_opt_in(
    changed_files: list[str], opt_in_rules: Optional[Iterable[str]] = None
) -> bool:
    """
     _Every_ changed file needs to be covered via at least one optin glob

    :param changed_files: List of changed file paths
    :param opt_in_rules: Iterable of globs to match the changed files against. Defaults to the rules defined in OPT_IN
    :return: True if every changed file  matches at least one glob, False otherwise
    """
    if opt_in_rules is None:
        opt_in_rules = OPT_IN

    for changed_file in changed_files:
        if not any(fnmatch.fnmatch(changed_file, opt_in_glob) for opt_in_glob in opt_in_rules):
            return False
    return True
