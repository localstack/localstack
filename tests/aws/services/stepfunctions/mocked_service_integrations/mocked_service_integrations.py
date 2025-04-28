import abc
import copy
import os
from typing import Final

import json5

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))
_LOAD_CACHE: Final[dict[str, dict]] = dict()


class MockedServiceIntegrationsLoader(abc.ABC):
    MOCKED_RESPONSE_LAMBDA_200_STRING_BODY: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/lambda/200_string_body.json5"
    )
    MOCKED_RESPONSE_LAMBDA_NOT_READY_TIMEOUT_200_STRING_BODY: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/lambda/not_ready_timeout_200_string_body.json5"
    )
    MOCKED_RESPONSE_SQS_200_SEND_MESSAGE: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/sqs/200_send_message.json5"
    )
    MOCKED_RESPONSE_SNS_200_PUBLISH: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/sns/200_publish.json5"
    )
    MOCKED_RESPONSE_EVENTS_200_PUT_EVENTS: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/events/200_put_events.json5"
    )
    MOCKED_RESPONSE_DYNAMODB_200_PUT_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/dynamodb/200_put_item.json5"
    )
    MOCKED_RESPONSE_DYNAMODB_200_GET_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/dynamodb/200_get_item.json5"
    )
    MOCKED_RESPONSE_STATES_200_START_EXECUTION_SYNC: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/states/200_start_execution_sync.json5"
    )
    MOCKED_RESPONSE_STATES_200_START_EXECUTION_SYNC2: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/states/200_start_execution_sync2.json5"
    )

    MOCK_CONFIG_FILE_LAMBDA_SQS_INTEGRATION: Final[str] = os.path.join(
        _THIS_FOLDER, "mock_config_files/lambda_sqs_integration.json5"
    )

    @staticmethod
    def load(file_path: str) -> dict:
        template = _LOAD_CACHE.get(file_path)
        if template is None:
            with open(file_path, "r") as df:
                template = json5.load(df)
            _LOAD_CACHE[file_path] = template
        return copy.deepcopy(template)
