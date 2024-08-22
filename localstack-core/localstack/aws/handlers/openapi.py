"""
Handlers for validating request and response schema against OpenAPI specs.
"""

import logging

from openapi_core import OpenAPI
from openapi_core.contrib.werkzeug import WerkzeugOpenAPIRequest, WerkzeugOpenAPIResponse
from openapi_core.exceptions import OpenAPIError
from openapi_core.validation.request.exceptions import (
    RequestValidationError,
)

from localstack import config, spec
from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.constants import INTERNAL_RESOURCE_PATH
from localstack.http import Response

LOG = logging.getLogger(__name__)


class OpenAPIRequestValidator(Handler):
    """
    Validates the internal requests with the OpenAPI spec.
    """

    def __init__(self):
        self.openapi = OpenAPI.from_dict(spec.OPENAPI)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not config.OPENAPI_VALIDATE_REQUEST:
            return

        path = context.request.path

        if path.startswith(f"{INTERNAL_RESOURCE_PATH}/") or path.startswith("/_aws/"):
            try:
                self.openapi.validate_request(WerkzeugOpenAPIRequest(context.request))
            except OpenAPIError as e:
                # Note: we only check request validations.
                #   We could be more strict here and check for things such as ServerNotFound or OperationNotFound.
                #   PathNotFound is handled by the last handler in request_handlers.
                match e:
                    case RequestValidationError():
                        response.status_code = 400
                        response.set_json({"error": "Bad Request", "message": str(e)})
                        chain.stop()
                    case _:
                        LOG.debug("Uncaught exception: (%s): %s", e.__class__.__name__, str(e))


class OpenAPIResponseValidator(OpenAPIRequestValidator):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # We are more lenient in validating the responses, since there is no users fault involved.
        #   We can eventually leverage this feature flag and be more strict in out test pipeline.
        if not config.OPENAPI_VALIDATE_RESPONSE:
            return

        path = context.request.path

        if path.startswith(INTERNAL_RESOURCE_PATH) or path.startswith("/_aws/"):
            try:
                self.openapi.validate_response(
                    WerkzeugOpenAPIRequest(context.request),
                    WerkzeugOpenAPIResponse(response),
                )
            except OpenAPIError as exc:
                LOG.debug(exc)
                response.status_code = 400
                response.set_json({"error": exc.__class__.__name__, "message": str(exc)})
                chain.stop()
