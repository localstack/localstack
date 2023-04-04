import base64
import json
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from responses import Response

from localstack.constants import HEADER_LOCALSTACK_EDGE_URL
from localstack.utils.aws.aws_responses import parse_query_string
from localstack.utils.strings import short_uid, to_str

# type definition for data parameters (i.e., invocation payloads)
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
    auth_context: Dict[str, Any]

    # target API/resource details extracted from the invocation
    apigw_version: ApiGatewayVersion
    api_id: str
    stage: str
    account_id: str
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

    # dict of stage variables (mapping names to values)
    stage_variables: Dict[str, str]

    # websockets route selection
    ws_route: str

    def __init__(
        self,
        method: str,
        path: str,
        data: Union[str, bytes],
        headers: Dict[str, str],
        api_id: str = None,
        stage: str = None,
        context: Dict[str, Any] = None,
        auth_context: Dict[str, Any] = None,
    ):
        self.method = method
        self.path = path
        self.data = data
        self.headers = headers
        self.context = {"requestId": short_uid()} if context is None else context
        self.auth_context = {} if auth_context is None else auth_context
        self.apigw_version = None
        self.api_id = api_id
        self.stage = stage
        self.region_name = None
        self.account_id = None
        self.integration = None
        self.resource = None
        self.resource_path = None
        self.path_with_query_string = None
        self.response_templates = {}
        self.stage_variables = {}
        self.path_params = {}
        self.route = None
        self.ws_route = None
        self.response = None

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

    def query_params(self) -> Dict[str, str]:
        """Extract the query parameters from the target URL or path in this request context."""
        query_string = self.path_with_query_string.partition("?")[2]
        return parse_query_string(query_string)

    @property
    def integration_uri(self) -> Optional[str]:
        integration = self.integration or {}
        return integration.get("uri") or integration.get("integrationUri")

    @property
    def auth_identity(self) -> Optional[Dict]:
        if isinstance(self.auth_context, dict):
            if self.auth_context.get("identity") is None:
                self.auth_context["identity"] = {}
            return self.auth_context["identity"]

    @property
    def authorizer_type(self) -> str:
        if isinstance(self.auth_context, dict):
            return self.auth_context.get("authorizer_type") if self.auth_context else None

    @property
    def authorizer_result(self) -> Dict[str, Any]:
        if isinstance(self.auth_context, dict):
            return self.auth_context.get("authorizer") if self.auth_context else {}

    def is_websocket_request(self) -> bool:
        upgrade_header = str(self.headers.get("upgrade") or "")
        return upgrade_header.lower() == "websocket"

    def is_v1(self) -> bool:
        """Whether this is an API Gateway v1 request"""
        return self.apigw_version == ApiGatewayVersion.V1

    def cookies(self) -> Optional[List[str]]:
        if cookies := self.headers.get("cookie") or "":
            return list(cookies.split(";"))
        return None

    @property
    def is_data_base64_encoded(self) -> bool:
        try:
            json.dumps(self.data) if isinstance(self.data, (dict, list)) else to_str(self.data)
            return False
        except UnicodeDecodeError:
            return True

    def data_as_string(self) -> str:
        try:
            return (
                json.dumps(self.data) if isinstance(self.data, (dict, list)) else to_str(self.data)
            )
        except UnicodeDecodeError:
            # we string encode our base64 as string as well
            return to_str(base64.b64encode(self.data))

    def _extract_host_from_header(self) -> str:
        host = self.headers.get(HEADER_LOCALSTACK_EDGE_URL) or self.headers.get("host", "")
        return host.split("://")[-1].split("/")[0].split(":")[0]

    @property
    def domain_name(self) -> str:
        return self._extract_host_from_header()

    @property
    def domain_prefix(self) -> str:
        host = self._extract_host_from_header()
        return host.split(".")[0]
