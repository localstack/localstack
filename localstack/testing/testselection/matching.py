import fnmatch
import re
from typing import Callable

# TODO: extract API Dependencies and composites to constants or similar
from localstack.utils.bootstrap import API_DEPENDENCIES

SENTINEL_NO_TEST = "SENTINEL_NO_TEST"  # a line item which signals that we don't default to everything, we just don't want to actually want to run a test => useful to differentiate between empty / nothing
SENTINEL_ALL_TESTS = "SENTINEL_ALL_TESTS"  # a line item which signals that we don't default to everything, we just don't want to actually want to run a test => useful to differentiate between empty / nothing

PACKAGE_TO_SVC_MAP = {"lambda_": "lambda"}


def _get_service_for_module(module_name: str) -> str:
    # TODO: might need to do some generic string manipulation if svc not found in map (e.g. - to _)
    return PACKAGE_TO_SVC_MAP.get(module_name)


def resolve_dependencies(module_name: str) -> set[str]:
    svc_name = _get_service_for_module(module_name)
    return _expand_api_dependencies(svc_name)


def _expand_api_dependencies(svc_name: str) -> set[str]:
    result = set()
    dependencies = API_DEPENDENCIES.get(svc_name, [])
    result.update(dependencies)

    for dep in dependencies:
        sub_deps = _expand_api_dependencies(dep)  # recursive call
        result.update(sub_deps)
    return result


def get_test_dir_for_service(svc: str):
    return f"tests/aws/services/{svc}"


class Matcher:
    def __init__(self, matching_func: Callable[[str], bool]):
        self.matching_func = matching_func

    def full_suite(self):
        return lambda t: [SENTINEL_ALL_TESTS] if self.matching_func(t) else []

    def ignore(self):
        return lambda t: [SENTINEL_NO_TEST] if self.matching_func(t) else []

    def service_tests(self, services: list[str]):
        return (
            lambda t: [get_test_dir_for_service(svc) for svc in services]
            if self.matching_func(t)
            else []
        )

    def passthrough(self):
        return lambda t: [t] if self.matching_func(t) else []


class Matchers:
    @staticmethod
    def glob(glob: str) -> Matcher:
        return Matcher(lambda t: fnmatch.fnmatch(t, glob))

    @staticmethod
    def regex(glob: str) -> Matcher:
        return Matcher(lambda t: bool(re.match(t, glob)))

    @staticmethod
    def prefix(prefix: str) -> Matcher:
        return Matcher(lambda t: t.startswith(prefix))


def generic_service_tests(t: str) -> list[str]:
    """
    Generic matching of changes in service files to their tests
    """
    # TODO: also match /aws/api/
    # TODO: consider API_DEPENDENCIES, API_COMPOSITES
    # TODO: consider "safety-mapping"
    # service_name = service_name.replace("-", "_")
    # # handle service names which are reserved keywords in python (f.e. lambda)
    # if is_keyword(service_name):
    #     service_name += "_"
    match = re.findall("localstack/services/([^/]+)/.+", t)
    if match:
        svc = match[0]
        return [f"tests/aws/services/{svc}/"]
    return []


MatchingRule = Callable[[str], list[str]]

# TODO: maintenance utils
# TODO: build util that shows rules that don't cover a single file
MATCHING_RULES: list[MatchingRule] = [
    # Generic rules
    generic_service_tests,  # always *at least* the service tests and dependencies
    Matchers.glob(
        "tests/**/test_*.py"
    ).passthrough(),  # changes in a test file should always at least test that file
    # CI
    Matchers.glob(".github/**").full_suite(),
    Matchers.glob(".circleci/**").full_suite(),
    # dependencies / project setup
    Matchers.glob("requirements*.txt").full_suite(),
    Matchers.glob("setup.cfg").full_suite(),
    Matchers.glob("setup.py").full_suite(),
    Matchers.glob("pyproject.toml").full_suite(),
    Matchers.glob("Dockerfile").full_suite(),
    Matchers.glob("Makefile").full_suite(),
    Matchers.glob("bin/**").full_suite(),
    Matchers.glob("localstack/config.py").full_suite(),
    Matchers.glob("localstack/constants.py").full_suite(),
    Matchers.glob("localstack/plugins.py").full_suite(),
    Matchers.glob("localstack/utils.py").full_suite(),
    # testing
    Matchers.glob("localstack/testing/**").full_suite(),
    Matchers.glob("**/conftest.py").full_suite(),
    Matchers.glob("**/fixtures.py").full_suite(),
    # ignore
    Matchers.glob("**/.md").ignore(),
    Matchers.glob("doc/**").ignore(),
    # lambda
    Matchers.glob("tests/aws/services/lambda_/functions/**").service_tests(services=["lambda"]),
]
