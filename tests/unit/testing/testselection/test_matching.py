from localstack.testing.testselection.matching import (
    generic_service_test_matching_rule,
    resolve_dependencies,
)


def test_service_dependency_resolving():
    svc_including_deps = resolve_dependencies("lambda_")
    assert svc_including_deps == {"s3", "sts", "sqs"}


def test_generic_service_matching_rule():
    assert generic_service_test_matching_rule("localstack/aws/api/cloudformation/__init__.py") == {
        "tests/aws/services/cloudformation/",
        "tests/aws/services/s3/",
        "tests/aws/services/sts/",
    }
