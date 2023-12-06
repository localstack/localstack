from localstack.utils.coverage_docs import get_coverage_link_for_service


def test_coverage_link_for_existing_service():
    coverage_link = get_coverage_link_for_service("s3", "random_action")
    assert (
        coverage_link
        == "API action 'random_action' for service 's3' not yet implemented or pro feature - please check https://docs.localstack.cloud/references/coverage/coverage_s3/ for further information"
    )


def test_coverage_link_for_non_existing_service():
    coverage_link = get_coverage_link_for_service("dummy_service", "random_action")
    assert (
        coverage_link
        == "API for service 'dummy_service' not yet implemented or pro feature - please check https://docs.localstack.cloud/references/coverage/ for further information"
    )
