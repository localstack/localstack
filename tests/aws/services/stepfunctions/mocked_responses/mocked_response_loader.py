import abc
import copy
import os
from typing import Final

import json5

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))
_LOAD_CACHE: Final[dict[str, dict]] = dict()


class MockedResponseLoader(abc.ABC):
    LAMBDA_200_STRING_BODY: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/lambda/200_string_body.json5"
    )
    LAMBDA_NOT_READY_TIMEOUT_200_STRING_BODY: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/lambda/not_ready_timeout_200_string_body.json5"
    )
    SQS_200_SEND_MESSAGE: Final[str] = os.path.join(
        _THIS_FOLDER, "mocked_responses/sqs/200_send_message.json5"
    )

    @staticmethod
    def load(file_path: str) -> dict:
        template = _LOAD_CACHE.get(file_path)
        if template is None:
            with open(file_path, "r") as df:
                template = json5.load(df)
            _LOAD_CACHE[file_path] = template
        return copy.deepcopy(template)
