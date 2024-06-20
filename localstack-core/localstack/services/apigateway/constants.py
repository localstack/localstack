from enum import Enum

from localstack.aws.api.apigateway import GatewayResponse, GatewayResponseType, StatusCode


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


def build_default_response(type: GatewayResponseType) -> dict:
    response = GatewayResponse(
        responseParameters={},
        responseTemplates={"application/json": '{"message":$context.error.messageString}'},
        responseType=type,
        defaultResponse=True,
    )
    if status_code := GatewayResponseCode[type]:
        # DEFAULT_4XX and DEFAULT_5XX do not have `statusCode` present in the response
        response["statusCode"] = status_code
    return response


# This list created in that order as we have snapshot tests making assertion on its order.
# TODO we should look at the impacted tests and ensure they pass regardless of order
DEFAULT_GATEWAY_RESPONSES = [
    build_default_response(GatewayResponseType.REQUEST_TOO_LARGE),
    build_default_response(GatewayResponseType.RESOURCE_NOT_FOUND),
    build_default_response(GatewayResponseType.AUTHORIZER_CONFIGURATION_ERROR),
    build_default_response(GatewayResponseType.MISSING_AUTHENTICATION_TOKEN),
    build_default_response(GatewayResponseType.BAD_REQUEST_BODY),
    build_default_response(GatewayResponseType.INVALID_SIGNATURE),
    build_default_response(GatewayResponseType.INVALID_API_KEY),
    build_default_response(GatewayResponseType.BAD_REQUEST_PARAMETERS),
    build_default_response(GatewayResponseType.AUTHORIZER_FAILURE),
    build_default_response(GatewayResponseType.UNAUTHORIZED),
    build_default_response(GatewayResponseType.INTEGRATION_TIMEOUT),
    build_default_response(GatewayResponseType.ACCESS_DENIED),
    build_default_response(GatewayResponseType.DEFAULT_4XX),
    build_default_response(GatewayResponseType.DEFAULT_5XX),
    build_default_response(GatewayResponseType.WAF_FILTERED),
    build_default_response(GatewayResponseType.QUOTA_EXCEEDED),
    build_default_response(GatewayResponseType.THROTTLED),
    build_default_response(GatewayResponseType.API_CONFIGURATION_ERROR),
    build_default_response(GatewayResponseType.UNSUPPORTED_MEDIA_TYPE),
    build_default_response(GatewayResponseType.INTEGRATION_FAILURE),
    build_default_response(GatewayResponseType.EXPIRED_TOKEN),
]
