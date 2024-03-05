from localstack.testing.testselection.matchersv2 import MATCHING_RULES


def get_affected_tests_from_changes(changed_files: [str]) -> "set[str]":
    # TODO: reduce based on inclusion (won't hurt but is a bit weird)
    # e.g. Number of affected test determined: 3
    # {'tests/aws/services/stepfunctions/',
    #  'tests/aws/services/stepfunctions/templates/scenarios/scenarios_templates.py',
    #  'tests/aws/services/stepfunctions/v2/scenarios/test_base_scenarios.py'}
    # should only really have 'tests/aws/services/stepfunctions'

    result = set()

    for changed_file in changed_files:
        for rule in MATCHING_RULES:
            result.update(rule(changed_file))

    return result
