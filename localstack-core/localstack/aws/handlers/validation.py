"""
Handlers for validating request and response schema against OpenAPI specs.
"""

import logging
import os
from pathlib import Path

from openapi_core import OpenAPI
from openapi_core.contrib.werkzeug import WerkzeugOpenAPIRequest, WerkzeugOpenAPIResponse
from openapi_core.exceptions import OpenAPIError
from openapi_core.validation.request.exceptions import (
    RequestValidationError,
)

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.constants import INTERNAL_RESOURCE_PATH
from localstack.http import Response

LOG = logging.getLogger(__name__)


# TODO: replace with from importlib.resources.files when https://github.com/python/importlib_resources/issues/311 is
#   resolved. Import from a namespace package is broken when installing in editable mode.
oas_path = os.path.join(os.path.dirname(__file__), "..", "..", "openapi.yaml")


class OpenAPIValidator(Handler):
    openapi: "OpenAPI"

    def __init__(self) -> None:
        path = Path(oas_path)
        assert path.exists()
        self.openapi = OpenAPI.from_path(path)


class OpenAPIRequestValidator(OpenAPIValidator):
    """
    Validates the requests to the LocalStack public endpoints (the ones with a _localstack or _aws prefix) against
    a OpenAPI specification.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not config.OPENAPI_VALIDATE_REQUEST:
            return

        path = context.request.path

        if path.startswith(f"{INTERNAL_RESOURCE_PATH}/") or path.startswith("/_aws/"):
            try:
                self.openapi.validate_request(WerkzeugOpenAPIRequest(context.request))
            except RequestValidationError as e:
                # Note: in this handler we only check validation errors, e.g., wrong body, missing required in the body.
                response.status_code = 400
                response.set_json({"error": "Bad Request", "message": str(e)})
                chain.stop()
            except OpenAPIError:
                # Other errors can be raised when validating a request against the OpenAPI specification.
                #   The most common are: ServerNotFound, OperationNotFound, or PathNotFound.
                #   We explicitly do not check any other error but RequestValidationError ones.
                #   We shallow the exception to avoid excessive logging (e.g., a lot of ServerNotFound), as the only
                #   purpose of this handler is to check for request validation errors.
                pass


class OpenAPIResponseValidator(OpenAPIValidator):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # We are more lenient in validating the responses. The use of this flag is intended for test.
        if not config.OPENAPI_VALIDATE_RESPONSE:
            return

        path = context.request.path

        if path.startswith(f"{INTERNAL_RESOURCE_PATH}/") or path.startswith("/_aws/"):
            try:
                self.openapi.validate_response(
                    WerkzeugOpenAPIRequest(context.request),
                    WerkzeugOpenAPIResponse(response),
                )
            except OpenAPIError as exc:
                LOG.error("Response validation failed for %s: $s", path, exc)
                response.status_code = 500
                response.set_json({"error": exc.__class__.__name__, "message": str(exc)})
                chain.stop()
