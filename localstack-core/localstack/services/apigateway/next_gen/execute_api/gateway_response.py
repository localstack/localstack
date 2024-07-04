from enum import Enum

from localstack.aws.api.apigateway import (
    GatewayResponse,
    GatewayResponseType,
    MapOfStringToString,
    StatusCode,
)


class BaseGatewayException(Exception):
    """
    Base class for all Gateway exceptions
    Do not raise from this class directly. Instead, raise the specific Exception
    """

    message: str = "Unimplemented Response"
    type: GatewayResponseType
    status_code: int | str = None
    code: str = ""

    def __init__(self, message: str = None, status_code: int | str = None):
        if message is not None:
            self.message = message
        if status_code is not None:
            self.status_code = status_code


class Default4xxError(BaseGatewayException):
    """Do not raise from this class directly.
    Use one of the subclasses instead, as they contain the appropriate header
    """

    type: GatewayResponseType.DEFAULT_4XX
    status_code = 400


class Default5xxError(BaseGatewayException):
    """Do not raise from this class directly.
    Use one of the subclasses instead, as they contain the appropriate header
    """

    type: GatewayResponseType.DEFAULT_5XX
    status_code = 500


class BadRequestException(Default4xxError):
    code = "BadRequestException"


class InternalFailureException(Default5xxError):
    code = "InternalFailureException"


class InternalServerError(Default5xxError):
    code = "InternalServerErrorException"


class AccessDeniedError(BaseGatewayException):
    type = GatewayResponseType.ACCESS_DENIED
    # TODO validate this header with aws validated tests
    code = "AccessDeniedException"


class ApiConfigurationError(BaseGatewayException):
    type = GatewayResponseType.API_CONFIGURATION_ERROR
    # TODO validate this header with aws validated tests
    code = "ApiConfigurationException"


class AuthorizerConfigurationError(BaseGatewayException):
    type = GatewayResponseType.AUTHORIZER_CONFIGURATION_ERROR
    # TODO validate this header with aws validated tests
    code = "AuthorizerConfigurationException"


class AuthorizerFailureError(BaseGatewayException):
    type = GatewayResponseType.AUTHORIZER_FAILURE
    # TODO validate this header with aws validated tests
    code = "AuthorizerFailureException"


class BadRequestParametersError(BaseGatewayException):
    type = GatewayResponseType.BAD_REQUEST_PARAMETERS
    code = "BadRequestException"


class BadRequestBodyError(BaseGatewayException):
    type = GatewayResponseType.BAD_REQUEST_BODY
    code = "BadRequestException"


class ExpiredTokenError(BaseGatewayException):
    type = GatewayResponseType.EXPIRED_TOKEN
    # TODO validate this header with aws validated tests
    code = "ExpiredTokenException"


class IntegrationFailureError(BaseGatewayException):
    type = GatewayResponseType.INTEGRATION_FAILURE
    # TODO validate this header with aws validated tests
    code = "IntegrationFailureException"


class IntegrationTimeoutError(BaseGatewayException):
    type = GatewayResponseType.INTEGRATION_TIMEOUT
    code = "InternalServerErrorException"


class InvalidAPIKeyError(BaseGatewayException):
    type = GatewayResponseType.INVALID_API_KEY
    code = "ForbiddenException"


class InvalidSignatureError(BaseGatewayException):
    type = GatewayResponseType.INVALID_SIGNATURE
    # TODO validate this header with aws validated tests
    code = "InvalidSignatureException"


class MissingAuthTokenError(BaseGatewayException):
    type = GatewayResponseType.MISSING_AUTHENTICATION_TOKEN
    code = "MissingAuthenticationTokenException"


class QuotaExceededError(BaseGatewayException):
    type = GatewayResponseType.QUOTA_EXCEEDED
    code = "LimitExceededException"


class RequestTooLargeError(BaseGatewayException):
    type = GatewayResponseType.REQUEST_TOO_LARGE
    # TODO validate this header with aws validated tests
    code = "RequestTooLargeException"


class ResourceNotFoundError(BaseGatewayException):
    type = GatewayResponseType.RESOURCE_NOT_FOUND
    # TODO validate this header with aws validated tests
    code = "ResourceNotFoundException"


class ThrottledError(BaseGatewayException):
    type = GatewayResponseType.THROTTLED
    code = "TooManyRequestsException"


class UnauthorizedError(BaseGatewayException):
    type = GatewayResponseType.UNAUTHORIZED
    code = "UnauthorizedException"


class UnsupportedMediaTypeError(BaseGatewayException):
    type = GatewayResponseType.UNSUPPORTED_MEDIA_TYPE
    code = "BadRequestException"


class WafFilteredError(BaseGatewayException):
    type = GatewayResponseType.WAF_FILTERED
    # TODO validate this header with aws validated tests
    code = "WafFilteredException"


class GatewayResponseCode(StatusCode, Enum):
    REQUEST_TOO_LARGE = "413"
    RESOURCE_NOT_FOUND = "404"
    AUTHORIZER_CONFIGURATION_ERROR = "500"
    MISSING_AUTHENTICATION_TOKEN = "403"
    BAD_REQUEST_BODY = "400"
    INVALID_SIGNATURE = "403"
    INVALID_API_KEY = "403"
    BAD_REQUEST_PARAMETERS = "400"
    AUTHORIZER_FAILURE = "500"
    UNAUTHORIZED = "401"
    INTEGRATION_TIMEOUT = "504"
    ACCESS_DENIED = "403"
    DEFAULT_4XX = ""
    DEFAULT_5XX = ""
    WAF_FILTERED = "403"
    QUOTA_EXCEEDED = "429"
    THROTTLED = "429"
    API_CONFIGURATION_ERROR = "500"
    UNSUPPORTED_MEDIA_TYPE = "415"
    INTEGRATION_FAILURE = "504"
    EXPIRED_TOKEN = "403"


def build_gateway_response(
    response_type: GatewayResponseType,
    status_code: StatusCode = None,
    response_parameters: MapOfStringToString = None,
    response_templates: MapOfStringToString = None,
    default_response: bool = True,
) -> GatewayResponse:
    """Building a Gateway Response. Non provided attributes will use default."""
    response = GatewayResponse(
        responseParameters=response_parameters or {},
        responseTemplates=response_templates
        or {"application/json": '{"message":$context.error.messageString}'},
        responseType=response_type,
        defaultResponse=default_response,
    )
    if status_code or (status_code := GatewayResponseCode[response_type]):
        # DEFAULT_4XX and DEFAULT_5XX do not have `statusCode` present in the response
        response["statusCode"] = status_code
    return response


def get_gateway_response_or_default(
    response_type: GatewayResponseType,
    gateway_responses: dict[GatewayResponseType, GatewayResponse],
) -> GatewayResponse:
    """Utility function that will look for a matching Gateway Response in the following order.
    - If provided in the gateway_response, return the dicts value
    - If the DEFAULT_XXX was configured will create a new response
    - Otherwise we return from DEFAULT_GATEWAY_RESPONSE"""

    if response := gateway_responses.get(response_type):
        # User configured response
        return response
    response_code = GatewayResponseCode[response_type]
    if response_code == "":
        # DEFAULT_XXX response do not have a default code
        return DEFAULT_GATEWAY_RESPONSES.get(response_type)
    if response_code >= "500":
        # 5XX response will either get a user configured DEFAULT_5XX or the DEFAULT_GATEWAY_RESPONSES
        default = gateway_responses.get(GatewayResponseType.DEFAULT_5XX)
    else:
        # 4XX response will either get a user configured DEFAULT_4XX or the DEFAULT_GATEWAY_RESPONSES
        default = gateway_responses.get(GatewayResponseType.DEFAULT_4XX)

    if not default:
        # If DEFAULT_XXX was not provided return default
        return DEFAULT_GATEWAY_RESPONSES.get(response_type)

    return build_gateway_response(
        # Build a new response from default
        response_type,
        status_code=default.get("statusCode"),
        response_parameters=default.get("responseParameters"),
        response_templates=default.get("responseTemplates"),
    )


DEFAULT_GATEWAY_RESPONSES = {
    GatewayResponseType.REQUEST_TOO_LARGE: build_gateway_response(
        GatewayResponseType.REQUEST_TOO_LARGE
    ),
    GatewayResponseType.RESOURCE_NOT_FOUND: build_gateway_response(
        GatewayResponseType.RESOURCE_NOT_FOUND
    ),
    GatewayResponseType.AUTHORIZER_CONFIGURATION_ERROR: build_gateway_response(
        GatewayResponseType.AUTHORIZER_CONFIGURATION_ERROR
    ),
    GatewayResponseType.MISSING_AUTHENTICATION_TOKEN: build_gateway_response(
        GatewayResponseType.MISSING_AUTHENTICATION_TOKEN
    ),
    GatewayResponseType.BAD_REQUEST_BODY: build_gateway_response(
        GatewayResponseType.BAD_REQUEST_BODY
    ),
    GatewayResponseType.INVALID_SIGNATURE: build_gateway_response(
        GatewayResponseType.INVALID_SIGNATURE
    ),
    GatewayResponseType.INVALID_API_KEY: build_gateway_response(
        GatewayResponseType.INVALID_API_KEY
    ),
    GatewayResponseType.BAD_REQUEST_PARAMETERS: build_gateway_response(
        GatewayResponseType.BAD_REQUEST_PARAMETERS
    ),
    GatewayResponseType.AUTHORIZER_FAILURE: build_gateway_response(
        GatewayResponseType.AUTHORIZER_FAILURE
    ),
    GatewayResponseType.UNAUTHORIZED: build_gateway_response(GatewayResponseType.UNAUTHORIZED),
    GatewayResponseType.INTEGRATION_TIMEOUT: build_gateway_response(
        GatewayResponseType.INTEGRATION_TIMEOUT
    ),
    GatewayResponseType.ACCESS_DENIED: build_gateway_response(GatewayResponseType.ACCESS_DENIED),
    GatewayResponseType.DEFAULT_4XX: build_gateway_response(GatewayResponseType.DEFAULT_4XX),
    GatewayResponseType.DEFAULT_5XX: build_gateway_response(GatewayResponseType.DEFAULT_5XX),
    GatewayResponseType.WAF_FILTERED: build_gateway_response(GatewayResponseType.WAF_FILTERED),
    GatewayResponseType.QUOTA_EXCEEDED: build_gateway_response(GatewayResponseType.QUOTA_EXCEEDED),
    GatewayResponseType.THROTTLED: build_gateway_response(GatewayResponseType.THROTTLED),
    GatewayResponseType.API_CONFIGURATION_ERROR: build_gateway_response(
        GatewayResponseType.API_CONFIGURATION_ERROR
    ),
    GatewayResponseType.UNSUPPORTED_MEDIA_TYPE: build_gateway_response(
        GatewayResponseType.UNSUPPORTED_MEDIA_TYPE
    ),
    GatewayResponseType.INTEGRATION_FAILURE: build_gateway_response(
        GatewayResponseType.INTEGRATION_FAILURE
    ),
    GatewayResponseType.EXPIRED_TOKEN: build_gateway_response(GatewayResponseType.EXPIRED_TOKEN),
}
