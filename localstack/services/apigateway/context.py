import json
from enum import Enum
from typing import Any, Dict, Optional, Union

from localstack.constants import HEADER_LOCALSTACK_EDGE_URL
from localstack.http import Request, Response
from localstack.http.request import restore_payload
from localstack.utils.strings import short_uid, to_str

# type definition for data parameters (i.e., invocation payloads)
InvocationPayload = Union[Dict, str, bytes]


class ApiGatewayVersion(Enum):
    V1 = "v1"
    V2 = "v2"


class ApiInvocationContext:
    """Represents the context for an incoming API Gateway invocation."""

    # Werkzeug Request object
    request: Request
    # Werkzeug Response object
    response: Response
    # url parameters extracted from the URL matching rules
    url_params: Dict[str, Any]

    # Invocation path with query string, e.g., "/my/path?test". Defaults to "path", can be used
    #  to overwrite the actual API path, in case the path format "../_user_request_/.." is used.
    _path_with_query_string: Optional[str] = None

    # Region name (e.g., "us-east-1") of the API Gateway request
    region_name: Optional[str] = None

    # invocation context
    context: Dict[str, Any]
    # authentication info for this invocation
    auth_info: Dict[str, Any]

    # target API/resource details extracted from the invocation
    apigw_version: ApiGatewayVersion = None
    api_id: str
    stage: str
    account_id: str = None

    integration: Dict = None
    resource: Dict = None

    # response templates to be applied to the invocation result
    response_templates: Dict = None

    route: Dict = None
    connection_id: str = None
    path_params: Dict = None

    stage_variables: Dict = None

    def __init__(
        self,
        request: Request,
        url_params: Dict = None,
        context=None,
        auth_info=None,
    ):
        self.request = request
        self.url_params = url_params or {}
        self.context = {"requestId": short_uid()} if context is None else context
        self.api_id = url_params.get("api_id")
        self.stage = url_params.get("stage")
        self.path = url_params.get("path")
        self.auth_info = auth_info or {}

    @property
    def resource_id(self) -> Optional[str]:
        return (self.resource or {}).get("id")

    @property
    def resource_path(self) -> str:
        """The resource path of the ApiGateway.V1 (e.g., "/my/path/{id}")"""
        return self.resource.get("path")

    @property
    def invocation_path(self) -> str:
        # invocation path differs from url_params["path"] because it includes a leading slash and
        # trailing slash, if the request.path includes a trailing slash,e.g.: /my/path/? or
        # /my/path?. Both examples are valid invocation paths for the same resource path /my/path
        invocation_path = self.path
        if self.request.path.endswith("/"):
            invocation_path = f"{invocation_path}/"
        return invocation_path if self.path.startswith("/") else f"/{invocation_path}"

    @property
    def path_with_query_string(self) -> str:
        return (
            self._path_with_query_string
            or f"{self.invocation_path}?" f"{to_str(self.request.query_string)}"
        )

    @property
    def integration_uri(self) -> Optional[str]:
        integration = self.integration or {}
        return integration.get("uri") or integration.get("integrationUri")

    @property
    def auth_context(self) -> Optional[Dict]:
        if isinstance(self.auth_info, dict):
            context = self.auth_info.setdefault("context", {})
            if principal := self.auth_info.get("principalId"):
                context["principalId"] = principal
            return context

    @property
    def auth_identity(self) -> Optional[Dict]:
        if isinstance(self.auth_info, dict):
            if self.auth_info.get("identity") is None:
                self.auth_info["identity"] = {}
            return self.auth_info["identity"]

    @property
    def authorizer_type(self) -> str:
        if isinstance(self.auth_info, dict):
            return self.auth_info.get("authorizer_type") if self.auth_info else None

    def is_websocket_request(self):
        upgrade_header = str(self.request.headers.get("upgrade") or "")
        return upgrade_header.lower() == "websocket"

    def is_v1(self):
        """Whether this is an API Gateway v1 request"""
        return self.apigw_version == ApiGatewayVersion.V1

    def cookies(self):
        if cookies := self.request.headers.get("cookie") or "":
            return list(cookies.split(";"))
        return []

    @property
    def is_data_base64_encoded(self):
        try:
            json.dumps(self.data) if isinstance(self.data, (dict, list)) else to_str(self.data)
            return False
        except UnicodeDecodeError:
            return True

    def _extract_host_from_header(self):
        host = self.request.headers.get(HEADER_LOCALSTACK_EDGE_URL) or self.request.headers.get(
            "host", ""
        )
        return host.split("://")[-1].split("/")[0].split(":")[0]

    @property
    def domain_name(self):
        return self._extract_host_from_header()

    @property
    def domain_prefix(self):
        host = self._extract_host_from_header()
        return host.split(".")[0]

    @property
    def method(self):
        return self.request.method

    @property
    def query_params(self):
        return self.request.args

    @property
    def headers(self):
        return self.request.headers

    @property
    def data(self):
        return restore_payload(self.request)
