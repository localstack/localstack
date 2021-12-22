import unittest

from localstack.utils.aws import aws_stack

TEST_SUPPORT_CASE = {
    "subject": "Urgent - DynamoDB is down",
    "serviceCode": "general-info",
    "categoryCode": "Service is down",
    "ccEmailAddresses": ["my-email-address@example.com"],
    "language": "en",
}


class TestConfigService(unittest.TestCase):
    def setUp(self):
        # support is only available in us-east-1
        self.support_client = aws_stack.create_external_boto_client(
            "support", region_name="us-east-1"
        )

    def create_case(self):
        response = self.support_client.create_case(
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

    def test_create_support_case(self):
        test_case_id = self.create_case()
        support_cases = self.support_client.describe_cases()["cases"]
        self.assertEqual(1, len(support_cases))
        self.assertEqual(test_case_id, support_cases[0]["caseId"])
        for key in TEST_SUPPORT_CASE.keys():
            self.assertEqual(TEST_SUPPORT_CASE[key], support_cases[0][key])

    def test_resolve_case(self):
        test_case_id = self.create_case()
        response = self.support_client.resolve_case(caseId=test_case_id)
        self.assertEqual("resolved", response["finalCaseStatus"])
