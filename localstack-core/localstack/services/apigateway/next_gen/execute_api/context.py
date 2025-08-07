from http import HTTPMethod
from typing import TypedDict

from rolo import Request
from rolo.gateway import RequestContext
from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration, Method, Resource, Stage
from localstack.services.apigateway.models import RestApiDeployment

from .variables import ContextVariableOverrides, ContextVariables, LoggingContextVariables


class InvocationRequest(TypedDict, total=False):
    http_method: HTTPMethod
    """HTTP Method of the incoming request"""
    raw_path: str | None
    # TODO: verify if raw_path is needed
    """Raw path of the incoming request with no modification, needed to keep double forward slashes"""
    path: str | None
    """Path of the request with no URL decoding"""
    path_parameters: dict[str, str] | None
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

    deployment: RestApiDeployment | None
    """Contains the invoked REST API Resources"""
    integration: Integration | None
    """The Method Integration for the invoked request"""
    api_id: str | None
    """The REST API identifier of the invoked API"""
    stage: str | None
    """The REST API stage name linked to this invocation"""
    base_path: str | None
    """The REST API base path mapped to the stage of this invocation"""
    deployment_id: str | None
    """The REST API deployment linked to this invocation"""
    region: str | None
    """The region the REST API is living in."""
    account_id: str | None
    """The account the REST API is living in."""
    trace_id: str | None
    """The X-Ray trace ID for the request."""
    resource: Resource | None
    """The resource the invocation matched"""
    resource_method: Method | None
    """The method of the resource the invocation matched"""
    stage_variables: dict[str, str] | None
    """The Stage variables, also used in parameters mapping and mapping templates"""
    stage_configuration: Stage | None
    """The Stage configuration, containing canary deployment settings"""
    is_canary: bool | None
    """If the current call was directed to a canary deployment"""
    context_variables: ContextVariables | None
    """The $context used in data models, authorizers, mapping templates, and CloudWatch access logging"""
    context_variable_overrides: ContextVariableOverrides | None
    """requestOverrides and responseOverrides are passed from request templates to response templates but are
    not in the integration context"""
    logging_context_variables: LoggingContextVariables | None
    """Additional $context variables available only for access logging, not yet implemented"""
    invocation_request: InvocationRequest | None
    """Contains the data relative to the invocation request"""
    integration_request: IntegrationRequest | None
    """Contains the data needed to construct an HTTP request to an Integration"""
    endpoint_response: EndpointResponse | None
    """Contains the data returned by an Integration"""
    invocation_response: InvocationResponse | None
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
        self.stage_configuration = None
        self.is_canary = None
        self.context_variables = None
        self.logging_context_variables = None
        self.integration_request = None
        self.endpoint_response = None
        self.invocation_response = None
        self.trace_id = None
        self.context_variable_overrides = None
