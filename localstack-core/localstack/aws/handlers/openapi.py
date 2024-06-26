"""
Handlers for validating request and response schema against OpenAPI specs.
"""

from openapi_core import OpenAPI
from openapi_core.contrib.werkzeug import WerkzeugOpenAPIRequest, WerkzeugOpenAPIResponse

from localstack import spec
from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.constants import INTERNAL_RESOURCE_PATH
from localstack.http import Response


class OpenAPIRequestValidator(Handler):
    def __init__(self):
        self.openapi = OpenAPI.from_dict(spec.OPENAPI)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        path = context.request.path

        if path.startswith(INTERNAL_RESOURCE_PATH) or path.startswith("/_aws/"):
            self.openapi.validate_request(WerkzeugOpenAPIRequest(context.request))


class OpenAPIResponseValidator(OpenAPIRequestValidator):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        path = context.request.path

        if path.startswith(INTERNAL_RESOURCE_PATH) or path.startswith("/_aws/"):
            self.openapi.validate_response(
                WerkzeugOpenAPIRequest(context.request),
                WerkzeugOpenAPIResponse(response),
            )
