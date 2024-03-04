"""
This module provides a method to select tests based on detected changes in the git history
"""

import re
import subprocess

from localstack.utils.bootstrap import API_DEPENDENCIES

SENTINEL_NO_TEST = "SENTINEL_NO_TEST"  # a line item which signals that we don't default to everything, we just don't want to actually want to run a test => useful to differentiate between empty / nothing
SENTINEL_ALL_TESTS = "SENTINEL_ALL_TESTS"  # a line item which signals that we don't default to everything, we just don't want to actually want to run a test => useful to differentiate between empty / nothing

# FIXME: replace glob with regex
ALL_TESTS = [
    ".github",
    ".circleci",
    "setup.cfg",
    r"requirements.+\.txt",
    "pyproject.toml",
    "**/conftest.py",
    "**/fixtures.py",  # TODO: could scope this down a bit
    # TODO: uncomment before merge
    # "localstack/testing",
    "bin/",
]

NO_TEST = [
    "README.md",
]


def get_changed_files_from_git_diff(repo: str, base_ref: str, head_ref: str) -> [str]:
    """
    Find list of files that are affected by changes made on head_ref in comparison to the base_ref.
    The base_ref is usually a merge-base of the actual base ref (just like how GitHub shows you the changes in comparison to latest master)
    """
    cmd = ["git", "-C", repo, "diff", "--name-only", base_ref, head_ref]
    output = subprocess.check_output(cmd, encoding="UTF-8")
    return [line.strip() for line in output.splitlines() if line.strip()]


###############################################################
####################  UTILS              ######################
###############################################################
REGEX_SERVICE = "localstack/services/([^/]+)/.+"
REGEX_TEST = r"^tests/.+\.py$"


def is_service(change_path: str) -> bool:
    return bool(re.match(REGEX_SERVICE, change_path))


def is_scenario(change_path: str) -> bool:
    return "tests/aws/scenarios" in change_path


def determine_service_test(changed_file: str) -> str:
    svc = re.findall(REGEX_SERVICE, changed_file)[0]
    return f"tests/aws/services/{svc}/"


def is_test(changed_file: str) -> bool:
    return bool(re.match(REGEX_TEST, changed_file))


###############################################################
####################  SERVICE EXPANSION  ######################
###############################################################

PACKAGE_TO_SVC_MAP = {"lambda_": "lambda"}


def _get_service_for_module(module_name: str) -> str:
    # TODO: might need to do some generic string manipulation if svc not found in map (e.g. - to _)
    return PACKAGE_TO_SVC_MAP.get(module_name)


# TODO: could cache this, but a bit premature to optimize
def _expand_api_dependencies(svc_name: str) -> "set[str]":
    result = set()
    dependencies = API_DEPENDENCIES.get(svc_name, [])
    result.update(dependencies)

    for dep in dependencies:
        sub_deps = _expand_api_dependencies(dep)  # recursive call
        result.update(sub_deps)
    return result


def resolve_dependencies(module_name: str) -> "set[str]":
    svc_name = _get_service_for_module(module_name)
    return _expand_api_dependencies(svc_name)


###############################################################
#################### CHANGE COLLECTION   ######################
###############################################################


def get_affected_tests_from_changes(changed_files: [str]) -> "set[str]":
    # TODO: reduce based on inclusion (won't hurt but is a bit weird)
    # e.g. Number of affected test determined: 3
    # {'tests/aws/services/stepfunctions/',
    #  'tests/aws/services/stepfunctions/templates/scenarios/scenarios_templates.py',
    #  'tests/aws/services/stepfunctions/v2/scenarios/test_base_scenarios.py'}
    # should only really have 'tests/aws/services/stepfunctions'

    result = set()

    for changed_file in changed_files:
        # TODO: generalize a bit and make this extensible
        if is_service(changed_file):
            # execute corresponding service test suite
            corresponding_svc_test = determine_service_test(changed_file)
            result.add(corresponding_svc_test)

        if is_test(changed_file):
            # only execute that one file
            result.add(changed_file)
    return result


def find_merge_base(repo: str, base_branch: str, head_branch: str) -> str:
    cmd = ["git", "-C", repo, "merge-base", base_branch, head_branch]
    output = subprocess.check_output(cmd, encoding="UTF-8")
    return output.strip()
