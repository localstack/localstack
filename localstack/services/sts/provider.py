import logging
import re
from typing import Optional

import xmltodict

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.sts import GetCallerIdentityResponse, StsApi
from localstack.aws.proxy import AwsApiListener
from localstack.constants import APPLICATION_JSON
from localstack.http import Response
from localstack.services.messages import Headers, MessagePayload, Request
from localstack.services.moto import MotoFallbackDispatcher, call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.strings import to_str
from localstack.utils.time import parse_timestamp
from localstack.utils.xml import strip_xmlns

LOG = logging.getLogger(__name__)


class StsProvider(StsApi, ServiceLifecycleHook):
    def get_caller_identity(self, context: RequestContext) -> GetCallerIdentityResponse:
        result = call_moto(context)
        username = config.TEST_IAM_USER_NAME or "localstack"
        result["Arn"] = result["Arn"].replace("user/moto", f"user/{username}")
        if config.TEST_IAM_USER_ID:
            result["UserId"] = config.TEST_IAM_USER_ID
        return result


class StsAwsApiListener(AwsApiListener):
    def __init__(self):
        self.provider = StsProvider()
        super().__init__("sts", MotoFallbackDispatcher(self.provider))

    def return_response(
        self, method: str, path: str, data: MessagePayload, headers: Headers, response: Response
    ) -> Optional[Response]:
        if headers.get("Accept") == APPLICATION_JSON:
            try:
                if response._content or b"".startswith(b"<"):
                    content = xmltodict.parse(to_str(response._content))
                    stripped_content = strip_xmlns(content)
                    response._content = stripped_content
            except Exception as e:
                LOG.debug("Unable to convert XML response to JSON", exc_info=e)
        return super().return_response(method, path, data, headers, response)

    def request(self, request: Request) -> Response:
        response = super().request(request)

        if request.headers.get("Accept") == APPLICATION_JSON:
            # convert "Expiration" to int for JSON response format (tested against AWS)
            # TODO: introduce a proper/generic approach that works across arbitrary date fields in JSON

            def _replace(match):
                timestamp = parse_timestamp(match.group(1).strip())
                return f"<Expiration>{int(timestamp.timestamp())}</Expiration>"

            def _replace_response_content(_pattern, _replacement):
                content = to_str(response.data or "")
                response.data = re.sub(_pattern, _replacement, content)

            pattern = r"<Expiration>([^<]+)</Expiration>"
            _replace_response_content(pattern, _replace)

        return response
