from localstack import config
from localstack.services.stepfunctions.mocking.mock_config import load_sfn_mock_config_file
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.mocked_responses.mocked_response_loader import (
    MockedResponseLoader,
)


class TestMockConfigFile:
    @markers.aws.only_localstack
    def test_is_mock_config_flag_detected_unset(self, mock_config_file):
        loaded_mock_config_file = load_sfn_mock_config_file()
        assert loaded_mock_config_file is None

    @markers.aws.only_localstack
    def test_is_mock_config_flag_detected_set(self, mock_config_file, monkeypatch):
        lambda_200_string_body = MockedResponseLoader.load(
            MockedResponseLoader.LAMBDA_200_STRING_BODY
        )
        # TODO: add typing for MockConfigFile.json components
        mock_config = {
            "StateMachines": {"S0": {"TestCases": {"LambdaState": "lambda_200_string_body"}}},
            "MockedResponses": {"lambda_200_string_body": lambda_200_string_body},
        }
        mock_config_file_path = mock_config_file(mock_config)
        monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
        loaded_mock_config_file = load_sfn_mock_config_file()
        assert loaded_mock_config_file == mock_config
