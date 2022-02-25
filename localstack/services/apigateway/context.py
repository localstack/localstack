from enum import Enum
from typing import Any, Dict, Optional, Union

# type definition for data parameters (i.e., invocation payloads)
from responses import Response

from localstack.utils.aws.aws_responses import parse_query_string

InvocationPayload = Union[Dict, str, bytes]


class ApiGatewayVersion(Enum):
    V1 = "v1"
    V2 = "v2"


class ApiInvocationContext:
    """Represents the context for an incoming API Gateway invocation."""

    # basic (raw) HTTP invocation details (method, path, data, headers)
    method: str
    path: str
    data: InvocationPayload
    headers: Dict[str, str]

    # invocation context
    context: Dict[str, Any]
    # authentication info for this invocation
    auth_info: Dict[str, Any]

    # target API/resource details extracted from the invocation
    apigw_version: ApiGatewayVersion
    api_id: str
    stage: str
    region_name: str
    # resource path, including any path parameter placeholders (e.g., "/my/path/{id}")
    resource_path: str
    integration: Dict
    resource: Dict
    # Invocation path with query string, e.g., "/my/path?test". Defaults to "path", can be used
    #  to overwrite the actual API path, in case the path format "../_user_request_/.." is used.
    _path_with_query_string: str

    # response templates to be applied to the invocation result
    response_templates: Dict

    route: Dict
    connection_id: str
    path_params: Dict

    # response object
    response: Response

    def __init__(
        self,
        method,
        path,
        data,
        headers,
        api_id=None,
        stage=None,
        context=None,
        auth_info=None,
    ):
        self.method = method
        self.path = path
        self.data = data
        self.headers = headers
        self.context = {} if context is None else context
        self.auth_info = {} if auth_info is None else auth_info
        self.apigw_version = None
        self.api_id = api_id
        self.stage = stage
        self.region_name = None
        self.integration = None
        self.resource = None
        self.resource_path = None
        self.path_with_query_string = None
        self.response_templates = {}

    @property
    def resource_id(self) -> Optional[str]:
        return (self.resource or {}).get("id")

    @property
    def invocation_path(self) -> str:
        """Return the plain invocation path, without query parameters."""
        path = self.path_with_query_string or self.path
        return path.split("?")[0]

    @property
    def path_with_query_string(self) -> str:
        """Return invocation path with query string - defaults to the value of 'path', unless customized."""
        return self._path_with_query_string or self.path

    @path_with_query_string.setter
    def path_with_query_string(self, new_path: str):
        """Set a custom invocation path with query string (used to handle "../_user_request_/.." paths)."""
        self._path_with_query_string = new_path

    def query_params(self) -> Dict:
        """Extract the query parameters from the target URL or path in this request context."""
        query_string = self.path_with_query_string.partition("?")[2]
        return parse_query_string(query_string)

    @property
    def integration_uri(self) -> Optional[str]:
        integration = self.integration or {}
        return integration.get("uri") or integration.get("integrationUri")

    @property
    def auth_context(self) -> Optional[Dict]:
        if isinstance(self.auth_info, dict):
            context = self.auth_info.setdefault("context", {})
            principal = self.auth_info.get("principalId")
            if principal:
                context["principalId"] = principal
            return context

    @property
    def auth_identity(self) -> Optional[Dict]:
        if isinstance(self.auth_info, dict):
            if self.auth_info.get("identity") is None:
                self.auth_info["identity"] = {}
            return self.auth_info["identity"]

    def is_websocket_request(self):
        upgrade_header = str(self.headers.get("upgrade") or "")
        return upgrade_header.lower() == "websocket"

    def is_v1(self):
        """Whether this is an API Gateway v1 request"""
        return self.apigw_version == ApiGatewayVersion.V1
