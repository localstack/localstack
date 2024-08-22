"""
Handlers for validating request and response schema against OpenAPI specs.
"""

import logging

from openapi_core import OpenAPI
from openapi_core.contrib.werkzeug import WerkzeugOpenAPIRequest, WerkzeugOpenAPIResponse
from openapi_core.exceptions import OpenAPIError
from openapi_core.templating.paths.exceptions import OperationNotFound, PathNotFound, ServerNotFound
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
        path = context.request.path

        def _create_response(exception: OpenAPIError, status_code: int) -> None:
            """Utility function that populated the response and stops the chain."""
            doc = {"error": exception.__class__.__name__, "message": str(exception)}
            response.status_code = status_code
            response.set_json(doc)
            chain.stop()

        if path.startswith(f"{INTERNAL_RESOURCE_PATH}/") or path.startswith("/_aws/"):
            try:
                self.openapi.validate_request(WerkzeugOpenAPIRequest(context.request))
            except OpenAPIError as e:
                LOG.error(e)
                match e:
                    case PathNotFound():
                        _create_response(e, 404)
                    case RequestValidationError() | ServerNotFound():
                        _create_response(e, 400)
                    case OperationNotFound():
                        _create_response(e, 405)
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
