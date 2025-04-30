from localstack import config
from localstack.services.stepfunctions.mocking.mock_config import (
    MockTestCase,
    load_mock_test_case_for,
)
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.mocked_service_integrations.mocked_service_integrations import (
    MockedServiceIntegrationsLoader,
)


class TestMockConfigFile:
    @markers.aws.only_localstack
    def test_is_mock_config_flag_detected_unset(self, mock_config_file):
        mock_test_case = load_mock_test_case_for(
            state_machine_name="state_machine_name", test_case_name="test_case_name"
        )
        assert mock_test_case is None

    @markers.aws.only_localstack
    def test_is_mock_config_flag_detected_set(self, mock_config_file, monkeypatch):
        lambda_200_string_body = MockedServiceIntegrationsLoader.load(
            MockedServiceIntegrationsLoader.MOCKED_RESPONSE_LAMBDA_200_STRING_BODY
        )
        # TODO: add typing for MockConfigFile.json components
        mock_config = {
            "StateMachines": {
                "S0": {"TestCases": {"BaseTestCase": {"LambdaState": "lambda_200_string_body"}}}
            },
            "MockedResponses": {"lambda_200_string_body": lambda_200_string_body},
        }
        mock_config_file_path = mock_config_file(mock_config)
        monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
        mock_test_case: MockTestCase = load_mock_test_case_for(
            state_machine_name="S0", test_case_name="BaseTestCase"
        )
        assert mock_test_case is not None
