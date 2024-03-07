from localstack.testing.testselection.matching import MATCHING_RULES


def get_affected_tests_from_changes(changed_files: [str]) -> "set[str]":
    # TODO: reduce based on inclusion (won't hurt but is a bit weird)
    # e.g. Number of affected test determined: 3
    # {'tests/aws/services/stepfunctions/',
    #  'tests/aws/services/stepfunctions/templates/scenarios/scenarios_templates.py',
    #  'tests/aws/services/stepfunctions/v2/scenarios/test_base_scenarios.py'}
    # should only really have 'tests/aws/services/stepfunctions'

    result = set()

    for changed_file in changed_files:
        added_test_rules = set()
        for rule in MATCHING_RULES:
            added_test_rules.update(rule(changed_file))

        # default case where no rule was matching where we default to execute all tests
        if len(added_test_rules) == 0:
            print(f"Change to file not covered via rules: {changed_file}")
            added_test_rules.add("SENTINEL_ALL_TESTS")
        result.update(added_test_rules)

    return result
