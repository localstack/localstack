import glob
import os
from pathlib import Path

import pytest

from localstack.testing.testselection.matching import (
    MATCHING_RULES,
    SENTINEL_ALL_TESTS,
    Matchers,
    check_rule_has_matches,
    generic_service_test_matching_rule,
    resolve_dependencies,
)
from localstack.testing.testselection.testselection import get_affected_tests_from_changes


def test_service_dependency_resolving_no_deps():
    api_dependencies = {"lambda": ["s3"], "cloudformation": ["s3", "sts"]}
    svc_including_deps = resolve_dependencies("lambda_", api_dependencies)
    assert len(svc_including_deps) == 0


def test_service_dependency_resolving_with_dependencies():
    api_dependencies = {
        "lambda": ["s3"],
        "cloudformation": ["s3"],
        "transcribe": ["s3"],
        "s3": ["sts"],
    }
    svc_including_deps = resolve_dependencies("s3", api_dependencies)
    assert svc_including_deps >= {"lambda", "cloudformation", "transcribe"}


def test_generic_service_matching_rule():
    assert generic_service_test_matching_rule("localstack/aws/api/cloudformation/__init__.py") == {
        "tests/aws/services/cloudformation/",
    }
    assert generic_service_test_matching_rule(
        "localstack/services/cloudformation/test_somefile.py"
    ) == {
        "tests/aws/services/cloudformation/",
    }
    assert generic_service_test_matching_rule(
        "tests/aws/services/cloudformation/templates/sometemplate.yaml"
    ) == {
        "tests/aws/services/cloudformation/",
    }


def test_generic_service_matching_rule_with_dependencies():
    api_dependencies = {
        "lambda": ["s3"],
        "cloudformation": ["s3"],
        "transcribe": ["s3"],
    }
    assert generic_service_test_matching_rule(
        "localstack/aws/api/s3/__init__.py", api_dependencies
    ) == {
        "tests/aws/services/cloudformation/",
        "tests/aws/services/lambda_/",
        "tests/aws/services/s3/",
        "tests/aws/services/transcribe/",
    }


def test_generic_service_matching_rule_defaults_to_api_deps():
    """
    Test that the generic service test matching rule uses both API_DEPENDENCIES and API_DEPENDENCIES_OPTIONAL
    if no api dependencies are explicitly set.
    """
    # match on code associated with OpenSearch
    result = generic_service_test_matching_rule("localstack/services/opensearch/test_somefile.py")
    # the result needs to contain at least:
    # - elasticsearch since it has opensearch as a mandatory requirement
    assert "tests/aws/services/es/" in result
    # - firehose since it has opensearch as an optional dependency used for one of its integrations
    assert "tests/aws/services/firehose/" in result
    # - opensearch because it is the actually changed service
    assert "tests/aws/services/opensearch/"


def test_service_dependency_resolving_with_co_dependencies():
    """
    Test to validate that we don't encounter issue when services are co-dependent on each other
    """
    api_dependencies = {
        "ses": ["sns"],
        "sns": ["sqs", "lambda", "firehose", "ses", "logs"],
        "logs": ["lambda", "kinesis", "firehose"],
        "lambda": ["logs", "cloudwatch"],
    }
    svc_including_deps = resolve_dependencies("ses", api_dependencies)
    assert svc_including_deps >= {"sns"}

    svc_including_deps = resolve_dependencies("logs", api_dependencies)
    assert svc_including_deps >= {"sns", "lambda"}

    svc_including_deps = resolve_dependencies("lambda", api_dependencies)
    assert svc_including_deps >= {"sns", "logs"}


@pytest.mark.skip(reason="mostly just useful for local execution as a sanity check")
def test_rules_are_matching_at_least_one_file():
    root_dir = Path(__file__).parent.parent.parent.parent.parent
    files = glob.glob(f"{root_dir}/**", root_dir=root_dir, recursive=True, include_hidden=True)
    files = [os.path.relpath(f, root_dir) for f in files]
    for rule_id, rule in enumerate(MATCHING_RULES):
        assert check_rule_has_matches(rule, files), f"no match for rule {rule_id}"


def test_directory_rules_with_paths():
    feature_path = "localstack/my_feature"
    test_path = "test/my_feature"
    matcher = Matchers.glob(f"{feature_path}/**").directory(paths=[test_path])
    selected_tests = get_affected_tests_from_changes([f"{feature_path}/__init__.py"], [matcher])

    assert selected_tests == [test_path]


def test_directory_rules_no_paths():
    conftest_path = "**/conftest.py"
    matcher = Matchers.glob(conftest_path).directory()

    selected_tests = get_affected_tests_from_changes(
        ["tests/aws/service/sns/conftest.py"], [matcher]
    )

    assert selected_tests == ["tests/aws/service/sns/"]


def test_directory_rules_no_match():
    feature_path = "localstack/my_feature"
    test_path = "test/my_feature"
    matcher = Matchers.glob(f"{feature_path}/**").directory(paths=[test_path])
    selected_tests = get_affected_tests_from_changes(
        ["localstack/not_my_feature/__init__.py"], [matcher]
    )

    assert selected_tests == [SENTINEL_ALL_TESTS]
