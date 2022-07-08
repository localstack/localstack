import functools
import sys
from typing import Any, NamedTuple, Optional, Type, Union

if sys.version_info >= (3, 8):
    from typing import Protocol, TypedDict
else:
    from typing_extensions import Protocol, TypedDict

from botocore.model import OperationModel, ServiceModel

from localstack.http import Request, Response

# FIXME: deprecated, use localstack.http.Request and localstack.http.Response instead
HttpRequest = Request
HttpResponse = Response


class ServiceRequest(TypedDict):
    pass


ServiceResponse = Any


class ServiceException(Exception):
    """
    An exception that indicates that a service error occurred.
    These exceptions, when raised during the execution of a service function, will be serialized and sent to the client.
    Do not use this exception directly (use the generated subclasses or CommonsServiceException instead).
    """

    code: str
    status_code: int
    sender_fault: bool
    message: str

    def __init__(self, *args):
        super(ServiceException, self).__init__(*args)

        if len(args) >= 1:
            self.message = args[0]
        else:
            self.message = ""


class CommonServiceException(ServiceException):
    """
    An exception which can be raised within a service during its execution, even if it is not specified (i.e. it's not
    generated based on the service specification).
    In the AWS API references, this kind of errors are usually referred to as "Common Errors", f.e.:
    https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/CommonErrors.html
    """

    def __init__(self, code: str, message: str, status_code: int = 400, sender_fault: bool = False):
        super(CommonServiceException, self).__init__(message)
        self.code = code
        self.status_code = status_code
        self.sender_fault = sender_fault


Operation = Type[ServiceRequest]


class ServiceOperation(NamedTuple):
    service: str
    operation: str


class RequestContext:
    request: Optional[Request]
    service: Optional[ServiceModel]
    operation: Optional[OperationModel]
    region: Optional[str]
    account_id: Optional[str]
    service_request: Optional[ServiceRequest]
    service_response: Optional[ServiceResponse]
    service_exception: Optional[ServiceException]

    def __init__(self) -> None:
        self.service = None
        self.operation = None
        self.region = None
        self.account_id = None
        self.request = None
        self.service_request = None
        self.service_response = None
        self.service_exception = None

    @property
    def service_operation(self) -> Optional[ServiceOperation]:
        if not self.service or not self.operation:
            return None
        return ServiceOperation(self.service.service_name, self.operation.name)

    def __repr__(self):
        return f"<RequestContext {self.service=}, {self.operation=}, {self.region=}, {self.account_id=}, {self.request=}>"


class ServiceRequestHandler(Protocol):
    def __call__(
        self, context: RequestContext, request: ServiceRequest
    ) -> Optional[Union[ServiceResponse, Response]]:
        raise NotImplementedError


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
