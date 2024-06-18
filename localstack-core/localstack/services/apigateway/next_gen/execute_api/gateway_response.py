from localstack.aws.api.apigateway import GatewayResponseType


class BaseGatewayResponse(Exception):
    """
    Base class for all Gateway exceptions
    Do not use this class directly. Instead, subclass from Default4xxError or Default5xxError.
    """

    message: str = "Unimplemented Response"
    status_code: int = 500
    type: GatewayResponseType = GatewayResponseType.DEFAULT_5XX
    default_type: GatewayResponseType = GatewayResponseType.DEFAULT_5XX

    def __init__(self, message: str = None, status_code: int = None):
        if message is not None:
            self.message = message
        if status_code is not None:
            self.status_code = status_code


class Default4xxError(BaseGatewayResponse):
    status_code = 400
    default_type = GatewayResponseType.DEFAULT_4XX
    type: str = GatewayResponseType.DEFAULT_4XX


class Default5xxError(BaseGatewayResponse):
    type: GatewayResponseType = GatewayResponseType.DEFAULT_5XX
    default_type: GatewayResponseType = GatewayResponseType.DEFAULT_5XX


class AccessDeniedError(Default4xxError):
    status_code = 403
    type = GatewayResponseType.ACCESS_DENIED


class ApiConfigurationError(Default5xxError):
    status_code = 500
    type = GatewayResponseType.API_CONFIGURATION_ERROR


class AuthorizerConfigurationError(Default5xxError):
    status_code = 500
    type = GatewayResponseType.AUTHORIZER_CONFIGURATION_ERROR


class AuthorizerFailureError(Default5xxError):
    status_code = 500
    type = GatewayResponseType.AUTHORIZER_FAILURE


class BadRequestParametersError(Default4xxError):
    status_code = 400
    type = GatewayResponseType.BAD_REQUEST_PARAMETERS


class BadRequestBodyError(Default4xxError):
    status_code = 400
    type = GatewayResponseType.BAD_REQUEST_BODY


class ExpiredTokenError(Default4xxError):
    status_code = 403
    type = GatewayResponseType.EXPIRED_TOKEN


class IntegrationFailureError(Default5xxError):
    status_code = 504
    type = GatewayResponseType.INTEGRATION_FAILURE


class IntegrationTimeoutError(Default5xxError):
    status_code = 504
    type = GatewayResponseType.INTEGRATION_TIMEOUT


class InvalidAPIKeyError(Default4xxError):
    status_code = 403
    type = GatewayResponseType.INVALID_API_KEY


class InvalidSignatureError(Default4xxError):
    status_code = 403
    type = GatewayResponseType.INVALID_SIGNATURE


class MissingAuthTokenError(Default4xxError):
    status_code = 403
    type = GatewayResponseType.MISSING_AUTHENTICATION_TOKEN


class QuotaExceededError(Default4xxError):
    status_code = 429
    type = GatewayResponseType.QUOTA_EXCEEDED


class RequestTooLargeError(Default4xxError):
    status_code = 413
    type = GatewayResponseType.REQUEST_TOO_LARGE


class ResourceNotFoundError(Default4xxError):
    status_code = 404
    type = GatewayResponseType.RESOURCE_NOT_FOUND


class ThrottledError(Default4xxError):
    status_code = 429
    type = GatewayResponseType.THROTTLED


class UnauthorizedError(Default4xxError):
    status_code = 401
    type = GatewayResponseType.UNAUTHORIZED


class UnsupportedMediaTypeError(Default4xxError):
    status_code = 415
    type = GatewayResponseType.UNSUPPORTED_MEDIA_TYPE


class WafFilteredError(Default4xxError):
    status_code = 403
    type = GatewayResponseType.WAF_FILTERED
