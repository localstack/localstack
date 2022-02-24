from typing import Optional

from localstack.aws.proxy import AwsApiListener
from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.services.logs.provider import LogsProvider
from localstack.services.messages import Headers, MessagePayload, Response
from localstack.services.moto import MotoFallbackDispatcher


class LogsAwsApiListener(AwsApiListener):
    def __init__(self):
        self.provider = LogsProvider()
        super().__init__("logs", MotoFallbackDispatcher(self.provider))

    def return_response(
        self,
        method: str,
        path: str,
        data: MessagePayload,
        headers: Headers,
        response: Response,
    ) -> Optional[Response]:
        # Fix Incorrect response content-type header from cloudwatch logs #1343.
        # True for all logs api responses.
        response.headers["content-type"] = APPLICATION_AMZ_JSON_1_1
        return None
