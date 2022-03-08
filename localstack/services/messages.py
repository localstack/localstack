import dataclasses
import json
from typing import Dict, Optional, Union

from localstack.utils.strings import to_str

MessagePayload = Union[str, bytes]
Headers = Dict[str, str]


@dataclasses.dataclass
class Request:
    method: str
    path: str
    data: MessagePayload
    headers: Headers

    def __init__(
        self,
        method: str = None,
        path: str = None,
        data: MessagePayload = None,
        headers: Headers = None,
    ):
        self.method = method
        self.path = path
        self.data = data
        self.headers = headers

    @property
    def host(self) -> Optional[str]:
        return self.headers.get("Host")

    def json(self):
        return json.loads(to_str(self.data or "{}"))

    def copy(self) -> "Request":
        """Return a shallow copy of this Request object (i.e., does NOT create a copy of the mutable headers)."""
        return Request(method=self.method, path=self.path, data=self.data, headers=self.headers)


@dataclasses.dataclass
class Response:
    _request: Request
    status_code: int
    content: MessagePayload
    headers: Headers

    def __init__(
        self, status_code: int = None, content: MessagePayload = None, headers: Headers = None
    ):
        self.status_code = status_code
        self.content = content
        self.headers = headers

    def json(self):
        return json.loads(to_str(self.content or "{}"))
