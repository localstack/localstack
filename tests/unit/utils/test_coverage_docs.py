from localstack.utils.coverage_docs import get_coverage_link_for_service


def test_coverage_link_for_existing_service():
    coverage_link = get_coverage_link_for_service("s3", "random_action")
    assert coverage_link == (
        "The API action 'random_action' for service 's3' is either not available in your current "
        "license plan or has not yet been emulated by LocalStack. "
        "Please refer to https://docs.localstack.cloud/references/coverage/ for more information."
    )


def test_coverage_link_for_non_existing_service():
    coverage_link = get_coverage_link_for_service("dummy_service", "random_action")
    assert coverage_link == (
        "The API for service 'dummy_service' is either not included in your current license plan or "
        "has not yet been emulated by LocalStack. "
        "Please refer to https://docs.localstack.cloud/references/coverage/ for more details."
    )
