import json

import requests

from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.aws import aws_stack
from localstack.utils.aws.request_context import mock_aws_request_headers
from tests.aws.services.stepfunctions.templates.test_case.test_case_templates import (
    TestCaseTemplate as TCT,
)


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestTestCaseScenarios:
    @staticmethod
    def _http_json_headers(amz_target: str) -> dict:
        headers = mock_aws_request_headers(
            "stepfunctions",
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            region_name=TEST_AWS_REGION_NAME,
        )
        headers["X-Amz-Target"] = amz_target
        return headers

    @staticmethod
    def _http_json_post(amz_target: str, http_body: json) -> requests.Response:
        ep_url: str = aws_stack.get_local_service_url("stepfunctions")
        http_headers: dict = TestTestCaseScenarios._http_json_headers(amz_target)
        return requests.post(ep_url, headers=http_headers, data=json.dumps(http_body))

    @staticmethod
    def _test_case_request(parameters: dict) -> requests.Response:
        return TestTestCaseScenarios._http_json_post(
            "stepfunctions.CreateStateMachine", parameters
        ).json()

    @markers.aws.validated
    def test_test_case_info(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot
    ):
        template = TCT.load_sfn_template(TCT.BASE_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Value": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._test_case_request(
            {"definition": definition, "roleArn": sfn_role_arn, "input": exec_input}
        )
        sfn_snapshot.match("test_case_output", test_case_output)
