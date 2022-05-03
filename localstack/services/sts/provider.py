import logging
import re

import xmltodict

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.sts import GetCallerIdentityResponse, StsApi
from localstack.aws.proxy import AwsApiListener
from localstack.constants import APPLICATION_JSON
from localstack.http import Request, Response
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
                data = re.sub(_pattern, _replacement, content)
                content = xmltodict.parse(data)
                stripped_content = strip_xmlns(content)
                response.set_json(stripped_content)

            pattern = r"<Expiration>([^<]+)</Expiration>"
            _replace_response_content(pattern, _replace)

        return response
