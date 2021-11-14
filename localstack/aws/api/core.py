import functools
import json
import sys
from io import BytesIO
from typing import IO, Any, Callable, Dict, NamedTuple, Optional, Type, Union

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from botocore.model import OperationModel, ServiceModel
from werkzeug.datastructures import Headers
from werkzeug.sansio.request import Request as _SansIORequest
from werkzeug.utils import cached_property
from werkzeug.wrappers import Response


class ServiceRequest(TypedDict):
    pass


ServiceResponse = Any


class ServiceException(Exception):
    """
    An exception that indicates that a service error occurred.
    These exceptions, when raised during the execution of a service function, will be serialized and sent to the client.
    Do not use this exception directly (use the generated subclasses or CommonsServiceException instead).
    """

    pass


class CommonServiceException(ServiceException):
    """
    An exception which can be raised within a service during its execution, even if it is not specified (i.e. it's not
    generated based on the service specification).
    In the AWS API references, this kind of errors are usually referred to as "Common Errors", f.e.:
    https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/CommonErrors.html
    """

    def __init__(self, code: str, message: str, status_code: int = 400, sender_fault: bool = False):
        self.code = code
        self.status_code = status_code
        self.sender_fault = sender_fault
        self.message = message
        super().__init__(self.message)


Operation = Type[ServiceRequest]


class HttpRequest(_SansIORequest):
    """
    A HttpRequest object. Creates basic compatibility with werkzeug's WSGI compliant Request objects, but also allows
    simple requests without a web server environment.
    """

    def __init__(
        self,
        method: str = "GET",
        path: str = "",
        headers: Union[Dict, Headers] = None,
        body: Union[bytes, str] = None,
        scheme: str = "http",
        root_path: str = "/",
        query_string: bytes = b"",
        remote_addr: str = None,
    ):
        if not headers:
            self.headers = Headers()
        elif isinstance(headers, Headers):
            self.headers = headers
        else:
            self.headers = Headers(headers)

        if not body:
            self._body = b""
        elif isinstance(body, str):
            self._body = body.encode("utf-8")
        else:
            self._body = body

        super(HttpRequest, self).__init__(
            method=method,
            scheme=scheme,
            server=("127.0.0.1", None),
            root_path=root_path,
            path=path,
            query_string=query_string,  # TODO: create query string from path
            headers=headers,
            remote_addr=remote_addr,
        )

    # properties for compatibility with werkzeug wsgi Request wrapper

    @cached_property
    def stream(self) -> IO[bytes]:
        return BytesIO(self._body)

    @cached_property
    def data(self) -> bytes:
        return self.get_data()

    @cached_property
    def json(self) -> Optional[Any]:
        return self.get_json()

    @property
    def form(self):
        raise NotImplementedError

    @property
    def values(self):
        raise NotImplementedError

    @property
    def files(self):
        raise NotImplementedError

    @cached_property
    def url_root(self) -> str:
        return self.root_url

    def get_data(
        self, cache: bool = True, as_text: bool = False, parse_form_data: bool = False
    ) -> Union[bytes, str]:
        # copied from werkzeug.wrappers.Request
        rv = getattr(self, "_cached_data", None)
        if rv is None:
            if parse_form_data:
                self._load_form_data()
            rv = self.stream.read()
            if cache:
                self._cached_data = rv
        if as_text:
            rv = rv.decode(self.charset, self.encoding_errors)

        return rv  # type: ignore

    _cached_json: Optional[None] = None

    def get_json(
        self, force: bool = False, silent: bool = False, cache: bool = True
    ) -> Optional[Any]:

        if cache and self._cached_json:
            return self._cached_json

        if not (force or self.is_json):
            return None

        try:
            doc = json.loads(self.get_data(cache=cache))
            if cache:
                self._cached_json = doc
            return doc
        except ValueError:
            if silent:
                return None
            raise

    def _load_form_data(self):
        pass

    def close(self) -> None:
        pass


class HttpResponse(Response):
    def update_from(self, other: Response):
        self.status_code = other.status_code
        self.data = other.data
        self.headers.update(other.headers)

    def set_json(self, doc: Dict):
        self.data = json.dumps(doc)

    def set_response(self, payload):
        if payload is None:
            self.response = []
        elif isinstance(payload, (str, bytes, bytearray)):
            self.data = payload
        else:
            self.response = payload

    def to_readonly_response_dict(self) -> Dict:
        """
        Returns a read-only version of a response dictionary as it is often expected by other libraries like boto.
        """
        return {
            "body": self.get_data(as_text=True).encode("utf-8"),
            "status_code": self.status_code,
            "headers": dict(self.headers),
        }


class ServiceOperation(NamedTuple):
    service: str
    operation: str


class RequestContext:
    service: ServiceModel
    operation: OperationModel
    region: str
    account_id: str
    request: HttpRequest
    service_request: ServiceRequest

    def __init__(self) -> None:
        super().__init__()
        self.service = None
        self.operation = None
        self.region = None
        self.account_id = None
        self.request = None
        self.service_request = None

    @property
    def service_operation(self) -> ServiceOperation:
        return ServiceOperation(self.service.service_name, self.operation.name)


ServiceRequestHandler = Callable[[RequestContext, ServiceRequest], Optional[ServiceResponse]]


def handler(operation: str = None, context: bool = True, expand: bool = True):
    """
    Decorator that indicates that the given function is a handler
    """

    def wrapper(fn):
        @functools.wraps(fn)
        def operation_marker(*args, **kwargs):
            return fn(*args, **kwargs)

        operation_marker.operation = operation
        operation_marker.expand_parameters = expand
        operation_marker.pass_context = context

        return operation_marker

    return wrapper
