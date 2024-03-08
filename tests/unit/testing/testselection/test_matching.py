import glob
import os
from pathlib import Path

import pytest

from localstack.testing.testselection.matching import (
    MATCHING_RULES,
    check_rule_has_matches,
    generic_service_test_matching_rule,
    resolve_dependencies,
)


def test_service_dependency_resolving_no_deps():
    svc_including_deps = resolve_dependencies("lambda_")
    assert len(svc_including_deps) == 0


def test_service_dependency_resolving_with_dependencies():
    svc_including_deps = resolve_dependencies("s3")
    assert svc_including_deps == {"lambda", "cloudformation", "transcribe"}


def test_service_dependency_resolving():
    svc_including_deps = resolve_dependencies("kinesis")
    assert svc_including_deps == {"dynamodbstreams", "dynamodb", "firehose"}


def test_generic_service_matching_rule():
    assert generic_service_test_matching_rule("localstack/aws/api/cloudformation/__init__.py") == {
        "tests/aws/services/cloudformation/",
    }


def test_generic_service_matching_rule_with_dependencies():
    assert generic_service_test_matching_rule("localstack/aws/api/s3/__init__.py") == {
        "tests/aws/services/cloudformation/",
        "tests/aws/services/lambda_/",
        "tests/aws/services/s3/",
        "tests/aws/services/transcribe/",
    }


@pytest.mark.skip(reason="mostly just useful for local execution as a sanity check")
def test_rules_are_matching_at_least_one_file():
    root_dir = Path(__file__).parent.parent.parent.parent.parent
    files = glob.glob(f"{root_dir}/**", root_dir=root_dir, recursive=True, include_hidden=True)
    files = [os.path.relpath(f, root_dir) for f in files]
    for rule_id, rule in enumerate(MATCHING_RULES):
        assert check_rule_has_matches(rule, files), f"no match for rule {rule_id}"
