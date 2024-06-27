from http import HTTPMethod
from typing import Optional, TypedDict

from rolo import Request
from rolo.gateway import RequestContext
from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Method, Resource
from localstack.services.apigateway.models import RestApiDeployment

from .variables import ContextVariables, LoggingContextVariables


class InvocationRequest(TypedDict, total=False):
    http_method: Optional[HTTPMethod]
    """HTTP Method of the incoming request"""
    raw_path: Optional[str]
    """Raw path of the incoming request with no modification, needed to keep double forward slashes"""
    path: Optional[str]
    """Path of the request with no URL decoding"""
    path_parameters: Optional[dict[str, str]]
    """Path parameters of the request"""
    query_string_parameters: Optional[dict[str, str]]
    """Query string parameters of the request"""
    # TODO: need to check if we need the raw headers (as it's practical for casing reasons)
    raw_headers: Optional[Headers]
    """Raw headers using the Headers datastructure which allows access with no regards to casing"""
    headers: Optional[dict[str, str]]
    """Headers of the request"""
    multi_value_query_string_parameters: Optional[dict[str, list[str]]]
    """Multi value query string parameters of the request"""
    multi_value_headers: Optional[dict[str, list[str]]]
    """Multi value headers of the request"""
    body: Optional[bytes]
    """Body content of the request"""


class IntegrationRequest(TypedDict, total=False):
    http_method: Optional[HTTPMethod]
    """HTTP Method of the incoming request"""
    uri: Optional[str]
    """URI of the integration"""
    query_string_parameters: Optional[dict[str, str]]
    """Query string parameters of the request"""
    headers: Optional[dict[str, str]]
    """Headers of the request"""
    multi_value_query_string_parameters: Optional[dict[str, list[str]]]
    """Multi value query string parameters of the request"""
    multi_value_headers: Optional[dict[str, list[str]]]
    """Multi value headers of the request"""
    body: Optional[bytes]
    """Body content of the request"""


class AuthorizerContext(TypedDict, total=False):
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
    claims: Optional[dict[str, str]]
    """Claims returned from the Amazon Cognito user pool after the method caller is successfully authenticated"""
    principal_id: Optional[str]
    """The principal user identification associated with the token sent by the client and returned from an API Gateway Lambda authorizer"""
    context: Optional[dict[str, str]]
    """The stringified value of the specified key-value pair of the context map returned from an API Gateway Lambda authorizer function"""


class IdentityContext(TypedDict, total=False):
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
    accountId: Optional[str]
    """The AWS account ID associated with the request."""
    apiKey: Optional[str]
    """For API methods that require an API key, this variable is the API key associated with the method request."""
    apiKeyId: Optional[str]
    """The API key ID associated with an API request that requires an API key."""
    caller: Optional[str]
    """The principal identifier of the caller that signed the request. Supported for resources that use IAM authorization."""
    cognitoAuthenticationProvider: Optional[str]
    """A comma-separated list of the Amazon Cognito authentication providers used by the caller making the request"""
    cognitoAuthenticationType: Optional[str]
    """The Amazon Cognito authentication type of the caller making the request"""
    cognitoIdentityId: Optional[str]
    """The Amazon Cognito identity ID of the caller making the request"""
    cognitoIdentityPoolId: Optional[str]
    """The Amazon Cognito identity pool ID of the caller making the request"""
    principalOrgId: Optional[str]
    """The AWS organization ID."""
    sourceIp: Optional[str]
    """The source IP address of the immediate TCP connection making the request to the API Gateway endpoint"""
    clientCert: Optional[dict[str, str]]
    """Certificate that a client presents. Present only in access logs if mutual TLS authentication fails."""
    vpcId: Optional[str]
    """The VPC ID of the VPC making the request to the API Gateway endpoint."""
    vpceId: Optional[str]
    """The VPC endpoint ID of the VPC endpoint making the request to the API Gateway endpoint."""
    user: Optional[str]
    """The principal identifier of the user that will be authorized against resource access for resources that use IAM authorization."""
    userAgent: Optional[str]
    """The User-Agent header of the API caller."""
    userArn: Optional[str]
    """The Amazon Resource Name (ARN) of the effective user identified after authentication."""


class RestApiInvocationContext(RequestContext):
    """
    This context is going to be used to pass relevant information across an API Gateway invocation.
    """

    invocation_request: Optional[InvocationRequest]
    """Contains the data relative to the invocation request"""
    deployment: Optional[RestApiDeployment]
    """Contains the invoked REST API Resources"""
    api_id: Optional[str]
    """The REST API identifier of the invoked API"""
    stage: Optional[str]
    """The REST API stage linked to this invocation"""
    region: Optional[str]
    """The region the REST API is living in."""
    account_id: Optional[str]
    """The account the REST API is living in."""
    resource: Optional[Resource]
    """The resource the invocation matched"""  # TODO: verify if needed through the invocation
    resource_method: Optional[Method]
    """The method of the resource the invocation matched"""
    stage_variables: Optional[dict[str, str]]
    """The Stage variables, also used in parameters mapping and mapping templates"""
    context_variables: Optional[ContextVariables]
    """The $context used in data models, authorizers, mapping templates, and CloudWatch access logging"""
    logging_context_variables: Optional[LoggingContextVariables]
    """Additional $context variables available only for access logging, not yet implemented"""
    integration_request: Optional[IntegrationRequest]
    """Contains the data needed to construct an HTTP request to an Integration"""

    def __init__(self, request: Request):
        super().__init__(request)
        self.deployment = None
        self.api_id = None
        self.stage = None
        self.account_id = None
        self.region = None
        self.invocation_request = None
        self.resource = None
        self.resource_method = None
        self.stage_variables = None
        self.context_variables = None
        self.logging_context_variables = None
        self.integration_request = None
