from typing import Iterable, Optional

from localstack.testing.testselection.matching import MATCHING_RULES, MatchingRule


def get_affected_tests_from_changes(
    changed_files: Iterable[str], matching_rules: Optional[list[MatchingRule]] = None
) -> list[str]:
    """
    Generate test selectors based on the changed files and matching rules to apply to.

    :param matching_rules: A list of matching rules which are used to generate test selectors from a given changed file
    :param changed_files: Iterable of file paths where changes were detected
    :return: Sorted list of test selectors
    """
    if matching_rules is None:
        matching_rules = MATCHING_RULES

    result = set()
    for changed_file in changed_files:
        added_test_rules = set()
        for rule in matching_rules:
            added_test_rules.update(rule(changed_file))

        # default case where no rule was matching where we default to execute all tests
        if len(added_test_rules) == 0:
            print(f"Change to file not covered via rules: {changed_file}")
            added_test_rules.add("SENTINEL_ALL_TESTS")
        result.update(added_test_rules)

    return sorted(result)
