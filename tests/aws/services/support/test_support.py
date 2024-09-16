import pytest

from localstack.constants import AWS_REGION_US_EAST_1
from localstack.testing.pytest import markers

TEST_SUPPORT_CASE = {
    "subject": "TEST CASE-Please ignore",
    "serviceCode": "general-info",
    "categoryCode": "Service is down",
    "ccEmailAddresses": ["my-email-address@example.com"],
    "language": "en",
}


class TestConfigService:
    """
    https://docs.aws.amazon.com/awssupport/latest/user/about-support-api.html
    > Important
    If you call the CreateCase operation to create test support cases, we recommend that you include a subject line,
    such as TEST CASE-Please ignore. After you're done with your test support case, call the ResolveCase operation
    to resolve it.
    To call the AWS Trusted Advisor operations in the AWS Support API, you must use the US East (N. Virginia) endpoint.
    Currently, the US West (Oregon) and Europe (Ireland) endpoints don't support the Trusted Advisor operations.
    """

    @pytest.fixture
    def support_client(self, aws_client_factory):
        # support is only available in us-east-1
        return aws_client_factory(region_name=AWS_REGION_US_EAST_1).support

    @pytest.fixture
    def create_case(self, support_client):
        cases = []

        def _create_case(**kwargs):
            response = support_client.create_case(**kwargs)
            cases.append(response["caseId"])
            return response

        yield _create_case

        # DescribeCases does not include resolved cases by default
        describe_cases = support_client.describe_cases()
        open_cases_id = [case["caseId"] for case in describe_cases["cases"]]
        for case_id in cases:
            if case_id in open_cases_id:
                support_client.resolve_case(caseId=case_id)

    @markers.aws.needs_fixing
    # we cannot use APIs from AWS Support due to the following:
    # An error occurred (SubscriptionRequiredException) when calling the DescribeCases/CreateCase operation:
    # Amazon Web Services Premium Support Subscription is required to use this service.
    def test_support_case_lifecycle(self, support_client, create_case):
        create_case = create_case(
            subject=TEST_SUPPORT_CASE["subject"],
            serviceCode=TEST_SUPPORT_CASE["serviceCode"],
            severityCode="low",
            categoryCode=TEST_SUPPORT_CASE["categoryCode"],
            communicationBody="Testing support case",
            ccEmailAddresses=TEST_SUPPORT_CASE["ccEmailAddresses"],
            language=TEST_SUPPORT_CASE["language"],
            issueType="technical",
        )
        case_id = create_case["caseId"]

        # DescribeCases does not include resolved cases by default
        describe_cases = support_client.describe_cases()
        cases = describe_cases["cases"]
        assert cases[0]["caseId"] == case_id
        for key in TEST_SUPPORT_CASE.keys():
            assert cases[0][key] == TEST_SUPPORT_CASE[key]

        response = support_client.resolve_case(caseId=case_id)
        assert response["finalCaseStatus"] == "resolved"
