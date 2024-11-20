import fnmatch
import pathlib
import re
from collections import defaultdict
from typing import Callable, Iterable, Optional

from localstack.aws.scaffold import is_keyword

# TODO: extract API Dependencies and composites to constants or similar

SENTINEL_NO_TEST = "SENTINEL_NO_TEST"  # a line item which signals that we don't default to everything, we just don't want to actually want to run a test => useful to differentiate between empty / nothing
SENTINEL_ALL_TESTS = "SENTINEL_ALL_TESTS"  # a line item which signals that we don't default to everything, we just don't want to actually want to run a test => useful to differentiate between empty / nothing

DEFAULT_SEARCH_PATTERNS = (
    r"localstack/services/([^/]+)/.+",
    r"localstack/aws/api/([^/]+)/__init__\.py",
    r"tests/aws/services/([^/]+)/.+",
)


def _map_to_module_name(service_name: str) -> str:
    """sanitize a service name like we're doing when scaffolding, e.g. lambda => lambda_"""
    service_name = service_name.replace("-", "_")
    # handle service names which are reserved keywords in python (f.e. lambda)
    if is_keyword(service_name):
        service_name += "_"
    return service_name


def _map_to_service_name(module_name: str) -> str:
    """map a sanitized module name to a service name, e.g. lambda_ => lambda"""
    if module_name.endswith("_"):
        return module_name[:-1]
    return module_name.replace("_", "-")


def resolve_dependencies(module_name: str, api_dependencies: dict[str, Iterable[str]]) -> set[str]:
    """
    Resolves dependencies for a given service module name

    :param module_name: the name of the service to resolve (e.g. lambda_)
    :param api_dependencies: dict of API dependencies where each key is the service and its value a list of services it
                             depends on
    :return: set of resolved _service names_ that the service depends on (e.g. sts)
    """
    svc_name = _map_to_service_name(module_name)
    return set(_reverse_dependency_map(api_dependencies).get(svc_name, []))


# TODO: might want to cache that, but for now it shouldn't be too much overhead
def _reverse_dependency_map(dependency_map: dict[str, Iterable[str]]) -> dict[str, Iterable[str]]:
    """
    The current API_DEPENDENCIES actually maps the services to their own dependencies.
    In our case here we need the inverse of this, we need to of which other services this service is a dependency of.
    """
    result = {}
    for svc, deps in dependency_map.items():
        for dep in deps:
            result.setdefault(dep, set()).add(svc)
    return result


def get_test_dir_for_service(svc: str) -> str:
    return f"tests/aws/services/{svc}"


def get_directory(t: str) -> str:
    # we take the parent of the match file, and we split it in parts
    parent_parts = pathlib.PurePath(t).parent.parts
    # we remove any parts that can be present in front of the first `tests` folder, could be caused by namespacing
    root = parent_parts.index("tests")
    folder_path = "/".join(parent_parts[root:]) + "/"
    return folder_path


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

    def directory(self, paths: list[str] = None):
        """Enables executing tests on a full directory if the file is matched.
        By default, it will return the directory of the modified file.
        If the argument `paths` is provided, it will instead return the provided list.
        """
        return lambda t: (paths or [get_directory(t)]) if self.matching_func(t) else []


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


def generic_service_test_matching_rule(
    changed_file_path: str,
    api_dependencies: Optional[dict[str, Iterable[str]]] = None,
    search_patterns: Iterable[str] = DEFAULT_SEARCH_PATTERNS,
    test_dirs: Iterable[str] = ("tests/aws/services",),
) -> set[str]:
    """
    Generic matching of changes in service files to their tests

    :param api_dependencies: dict of API dependencies where each key is the service and its value a list of services it depends on
    :param changed_file_path: the file path of the detected change
    :param search_patterns: list of regex patterns to search for in the changed file path
    :param test_dirs: list of test directories to match for a changed service
    :return: list of partial test file path filters for the matching service and all services it depends on
    """
    # TODO: consider API_COMPOSITES

    if api_dependencies is None:
        from localstack.utils.bootstrap import API_DEPENDENCIES, API_DEPENDENCIES_OPTIONAL

        # merge the mandatory and optional service dependencies
        api_dependencies = defaultdict(set)
        for service, mandatory_dependencies in API_DEPENDENCIES.items():
            api_dependencies[service].update(mandatory_dependencies)

        for service, optional_dependencies in API_DEPENDENCIES_OPTIONAL.items():
            api_dependencies[service].update(optional_dependencies)

    match = None
    for pattern in search_patterns:
        match = re.findall(pattern, changed_file_path)
        if match:
            break

    if match:
        changed_service = match[0]
        changed_services = [changed_service]
        service_dependencies = resolve_dependencies(changed_service, api_dependencies)
        changed_services.extend(service_dependencies)
        changed_service_module_names = [_map_to_module_name(svc) for svc in changed_services]
        return {
            f"{test_dir}/{svc}/" for test_dir in test_dirs for svc in changed_service_module_names
        }

    return set()


MatchingRule = Callable[[str], Iterable[str]]


def check_rule_has_matches(rule: MatchingRule, files: Iterable[str]) -> bool:
    """maintenance utility to check if a rule has any matches at all in the given directory"""
    detected_tests = set()
    for file in files:
        detected_tests.update(rule(file))
    return len(detected_tests) > 0


MATCHING_RULES: list[MatchingRule] = [
    # Generic rules
    generic_service_test_matching_rule,  # always *at least* the service tests and dependencies
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
    Matchers.glob("localstack/utils/**").full_suite(),
    # testing
    Matchers.glob("localstack/testing/**").full_suite(),
    Matchers.glob("**/conftest.py").directory(),
    Matchers.glob("**/fixtures.py").full_suite(),
    # ignore
    Matchers.glob("**/*.md").ignore(),
    Matchers.glob("doc/**").ignore(),
    Matchers.glob("CODEOWNERS").ignore(),
    Matchers.glob(".gitignore").ignore(),
    Matchers.glob(".git-blame-ignore-revs").ignore(),
    # lambda
    Matchers.glob("tests/aws/services/lambda_/functions/**").service_tests(services=["lambda"]),
]
