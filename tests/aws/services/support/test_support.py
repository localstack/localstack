import pytest

from localstack.constants import AWS_REGION_US_EAST_1
from localstack.testing.pytest import markers

TEST_SUPPORT_CASE = {
    "subject": "Urgent - DynamoDB is down",
    "serviceCode": "general-info",
    "categoryCode": "Service is down",
    "ccEmailAddresses": ["my-email-address@example.com"],
    "language": "en",
}


class TestConfigService:
    @pytest.fixture
    def support_client(self, aws_client_factory):
        # support is only available in us-east-1
        return aws_client_factory(region_name=AWS_REGION_US_EAST_1).support

    @pytest.fixture
    def case_id_test(self, support_client) -> str:
        response = support_client.create_case(
            subject=TEST_SUPPORT_CASE["subject"],
            serviceCode=TEST_SUPPORT_CASE["serviceCode"],
            severityCode="low",
            categoryCode=TEST_SUPPORT_CASE["categoryCode"],
            communicationBody="Testing support case",
            ccEmailAddresses=TEST_SUPPORT_CASE["ccEmailAddresses"],
            language=TEST_SUPPORT_CASE["language"],
            issueType="technical",
        )
        return response["caseId"]

    @markers.aws.unknown
    def test_create_support_case(self, support_client, case_id_test):
        support_cases = support_client.describe_cases()["cases"]
        assert len(support_cases) == 1
        assert support_cases[0]["caseId"] == case_id_test
        for key in TEST_SUPPORT_CASE.keys():
            assert support_cases[0][key] == TEST_SUPPORT_CASE[key]

    @markers.aws.unknown
    def test_resolve_case(self, support_client, case_id_test):
        response = support_client.resolve_case(caseId=case_id_test)
        assert response["finalCaseStatus"] == "resolved"
