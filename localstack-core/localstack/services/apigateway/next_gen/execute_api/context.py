from http import HTTPMethod
from typing import Optional, TypedDict

from rolo import Request
from rolo.gateway import RequestContext
from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration, Method, Resource
from localstack.services.apigateway.models import RestApiDeployment

from .variables import ContextVariableOverrides, ContextVariables, LoggingContextVariables


class InvocationRequest(TypedDict, total=False):
    http_method: HTTPMethod
    """HTTP Method of the incoming request"""
    raw_path: Optional[str]
    # TODO: verify if raw_path is needed
    """Raw path of the incoming request with no modification, needed to keep double forward slashes"""
    path: Optional[str]
    """Path of the request with no URL decoding"""
    path_parameters: Optional[dict[str, str]]
    """Path parameters of the request"""
    query_string_parameters: dict[str, str]
    """Query string parameters of the request"""
    headers: Headers
    """Raw headers using the Headers datastructure which allows access with no regards to casing"""
    multi_value_query_string_parameters: dict[str, list[str]]
    """Multi value query string parameters of the request"""
    body: bytes
    """Body content of the request"""


class IntegrationRequest(TypedDict, total=False):
    http_method: HTTPMethod
    """HTTP Method of the incoming request"""
    uri: str
    """URI of the integration"""
    query_string_parameters: dict[str, str | list[str]]
    """Query string parameters of the request"""
    headers: Headers
    """Headers of the request"""
    body: bytes
    """Body content of the request"""


class BaseResponse(TypedDict):
    """Base class for Response objects in the context"""

    status_code: int
    """Status code of the response"""
    headers: Headers
    """Headers of the response"""
    body: bytes
    """Body content of the response"""


class EndpointResponse(BaseResponse):
    """Represents the response coming from an integration, called Endpoint Response in AWS"""

    pass


class InvocationResponse(BaseResponse):
    """Represents the response coming after being serialized in an Integration Response in AWS"""

    pass


class RestApiInvocationContext(RequestContext):
    """
    This context is going to be used to pass relevant information across an API Gateway invocation.
    """

    deployment: Optional[RestApiDeployment]
    """Contains the invoked REST API Resources"""
    integration: Optional[Integration]
    """The Method Integration for the invoked request"""
    api_id: Optional[str]
    """The REST API identifier of the invoked API"""
    stage: Optional[str]
    """The REST API stage linked to this invocation"""
    base_path: Optional[str]
    """The REST API base path mapped to the stage of this invocation"""
    deployment_id: Optional[str]
    """The REST API deployment linked to this invocation"""
    region: Optional[str]
    """The region the REST API is living in."""
    account_id: Optional[str]
    """The account the REST API is living in."""
    trace_id: Optional[str]
    """The X-Ray trace ID for the request."""
    resource: Optional[Resource]
    """The resource the invocation matched"""
    resource_method: Optional[Method]
    """The method of the resource the invocation matched"""
    stage_variables: Optional[dict[str, str]]
    """The Stage variables, also used in parameters mapping and mapping templates"""
    context_variables: Optional[ContextVariables]
    """The $context used in data models, authorizers, mapping templates, and CloudWatch access logging"""
    context_variable_overrides: Optional[ContextVariableOverrides]
    """requestOverrides and responseOverrides are passed from request templates to response templates but are
    not in the integration context"""
    logging_context_variables: Optional[LoggingContextVariables]
    """Additional $context variables available only for access logging, not yet implemented"""
    invocation_request: Optional[InvocationRequest]
    """Contains the data relative to the invocation request"""
    integration_request: Optional[IntegrationRequest]
    """Contains the data needed to construct an HTTP request to an Integration"""
    endpoint_response: Optional[EndpointResponse]
    """Contains the data returned by an Integration"""
    invocation_response: Optional[InvocationResponse]
    """Contains the data serialized and to be returned by an invocation"""

    def __init__(self, request: Request):
        super().__init__(request)
        self.deployment = None
        self.api_id = None
        self.stage = None
        self.base_path = None
        self.deployment_id = None
        self.account_id = None
        self.region = None
        self.invocation_request = None
        self.resource = None
        self.resource_method = None
        self.integration = None
        self.stage_variables = None
        self.context_variables = None
        self.logging_context_variables = None
        self.integration_request = None
        self.endpoint_response = None
        self.invocation_response = None
        self.trace_id = None
        self.context_variable_overrides = None
