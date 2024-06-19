from functools import cache

from localstack.aws.api.apigateway import (
    GatewayResponse,
    GatewayResponseCode,
    GatewayResponseType,
)

DEFAULT_GATEWAY_RESPONSE = {
    "responseParameters": {},
    "responseTemplates": {"application/json": '{"message":$context.error.messageString}'},
}


@cache
def build_default_response(type: GatewayResponseType) -> dict:
    response = GatewayResponse(**DEFAULT_GATEWAY_RESPONSE, responseType=type, defaultResponse=True)
    if status_code := GatewayResponseCode[type]:
        response["statusCode"] = status_code
    return response


class BaseGatewayException(Exception):
    """
    Base class for all Gateway exceptions
    Do not use this class directly. Instead, subclass from Default4xxError or Default5xxError.
    """

    message: str = "Unimplemented Response"
    status_code: str = ""
    type: GatewayResponseType = GatewayResponseType.DEFAULT_5XX
    default_type: GatewayResponseType = GatewayResponseType.DEFAULT_5XX

    def __init__(self, message: str = None, status_code: str = None):
        if message is not None:
            self.message = message
        if status_code:
            self.status_code = status_code


class Default4xxError(BaseGatewayException):
    default_type = GatewayResponseType.DEFAULT_4XX
    type: str = GatewayResponseType.DEFAULT_4XX


class Default5xxError(BaseGatewayException):
    type: GatewayResponseType = GatewayResponseType.DEFAULT_5XX
    default_type: GatewayResponseType = GatewayResponseType.DEFAULT_5XX


class AccessDeniedError(Default4xxError):
    status_code = GatewayResponseCode.ACCESS_DENIED
    type = GatewayResponseType.ACCESS_DENIED


class ApiConfigurationError(Default5xxError):
    status_code = GatewayResponseCode.API_CONFIGURATION_ERROR
    type = GatewayResponseType.API_CONFIGURATION_ERROR


class AuthorizerConfigurationError(Default5xxError):
    status_code = GatewayResponseCode.AUTHORIZER_CONFIGURATION_ERROR
    type = GatewayResponseType.AUTHORIZER_CONFIGURATION_ERROR


class AuthorizerFailureError(Default5xxError):
    status_code = GatewayResponseCode.AUTHORIZER_FAILURE
    type = GatewayResponseType.AUTHORIZER_FAILURE


class BadRequestParametersError(Default4xxError):
    status_code = GatewayResponseCode.BAD_REQUEST_PARAMETERS
    type = GatewayResponseType.BAD_REQUEST_PARAMETERS


class BadRequestBodyError(Default4xxError):
    status_code = GatewayResponseCode.BAD_REQUEST_BODY
    type = GatewayResponseType.BAD_REQUEST_BODY


class ExpiredTokenError(Default4xxError):
    status_code = GatewayResponseCode.EXPIRED_TOKEN
    type = GatewayResponseType.EXPIRED_TOKEN


class IntegrationFailureError(Default5xxError):
    status_code = GatewayResponseCode.INTEGRATION_FAILURE
    type = GatewayResponseType.INTEGRATION_FAILURE


class IntegrationTimeoutError(Default5xxError):
    status_code = GatewayResponseCode.INTEGRATION_TIMEOUT
    type = GatewayResponseType.INTEGRATION_TIMEOUT


class InvalidAPIKeyError(Default4xxError):
    status_code = GatewayResponseCode.INVALID_API_KEY
    type = GatewayResponseType.INVALID_API_KEY


class InvalidSignatureError(Default4xxError):
    status_code = GatewayResponseCode.INVALID_SIGNATURE
    type = GatewayResponseType.INVALID_SIGNATURE


class MissingAuthTokenError(Default4xxError):
    status_code = GatewayResponseCode.MISSING_AUTHENTICATION_TOKEN
    type = GatewayResponseType.MISSING_AUTHENTICATION_TOKEN


class QuotaExceededError(Default4xxError):
    status_code = GatewayResponseCode.QUOTA_EXCEEDED
    type = GatewayResponseType.QUOTA_EXCEEDED


class RequestTooLargeError(Default4xxError):
    status_code = GatewayResponseCode.REQUEST_TOO_LARGE
    type = GatewayResponseType.REQUEST_TOO_LARGE


class ResourceNotFoundError(Default4xxError):
    status_code = GatewayResponseCode.RESOURCE_NOT_FOUND
    type = GatewayResponseType.RESOURCE_NOT_FOUND


class ThrottledError(Default4xxError):
    status_code = GatewayResponseCode.THROTTLED
    type = GatewayResponseType.THROTTLED


class UnauthorizedError(Default4xxError):
    status_code = GatewayResponseCode.UNAUTHORIZED
    type = GatewayResponseType.UNAUTHORIZED


class UnsupportedMediaTypeError(Default4xxError):
    status_code = GatewayResponseCode.UNSUPPORTED_MEDIA_TYPE
    type = GatewayResponseType.UNSUPPORTED_MEDIA_TYPE


class WafFilteredError(Default4xxError):
    status_code = GatewayResponseCode.WAF_FILTERED
    type = GatewayResponseType.WAF_FILTERED
