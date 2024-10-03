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
from openapi_core.validation.response.exceptions import ResponseValidationError
from plux import PluginManager

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.constants import INTERNAL_RESOURCE_PATH
from localstack.http import Response

LOG = logging.getLogger(__name__)


class OpenAPIValidator(Handler):
    open_apis: list["OpenAPI"]

    def __init__(self) -> None:
        self._load_specs()

    def _load_specs(self) -> None:
        """Load the openapi spec plugins iff at least one between request and response validation is set."""
        if not (config.OPENAPI_VALIDATE_REQUEST or config.OPENAPI_VALIDATE_RESPONSE):
            return
        specs = PluginManager("localstack.openapi.spec").load_all()
        self.open_apis = []
        for spec in specs:
            self.open_apis.append(OpenAPI.from_path(spec.spec_path))


class OpenAPIRequestValidator(OpenAPIValidator):
    """
    Validates the requests to the LocalStack public endpoints (the ones with a _localstack or _aws prefix) against
    a OpenAPI specification.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not config.OPENAPI_VALIDATE_REQUEST:
            return

        hasattr(self, "open_apis") or self._load_specs()
        path = context.request.path

        if path.startswith(f"{INTERNAL_RESOURCE_PATH}/") or path.startswith("/_aws/"):
            for openapi in self.open_apis:
                try:
                    openapi.validate_request(WerkzeugOpenAPIRequest(context.request))
                    # We stop the handler at the first succeeded validation, as the other spec might not even specify
                    #   this path.
                    break
                except RequestValidationError as e:
                    # Note: in this handler we only check validation errors, e.g., wrong body, missing required.
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
        # The use of this flag is intended for test only. Eventual errors are due to LocalStack implementation and not
        #   to improper user usage of the endpoints.
        if not config.OPENAPI_VALIDATE_RESPONSE:
            return

        hasattr(self, "open_apis") or self._load_specs()
        path = context.request.path

        if path.startswith(f"{INTERNAL_RESOURCE_PATH}/") or path.startswith("/_aws/"):
            for openapi in self.open_apis:
                try:
                    openapi.validate_response(
                        WerkzeugOpenAPIRequest(context.request),
                        WerkzeugOpenAPIResponse(response),
                    )
                    break
                except ResponseValidationError as exc:
                    LOG.error("Response validation failed for %s: %s", path, exc)
                    response.status_code = 500
                    response.set_json({"error": exc.__class__.__name__, "message": str(exc)})
                    chain.terminate()
                except OpenAPIError:
                    # Same logic from the request validator applies here.
                    pass
