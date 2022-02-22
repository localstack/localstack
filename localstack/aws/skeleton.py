import inspect
import logging
from typing import Any, Callable, Dict, NamedTuple, Optional, Union

from botocore import xform_name
from botocore.model import ServiceModel

from localstack.aws.api import (
    CommonServiceException,
    HttpResponse,
    RequestContext,
    ServiceException,
)
from localstack.aws.api.core import ServiceRequest, ServiceRequestHandler, ServiceResponse
from localstack.aws.protocol.parser import create_parser
from localstack.aws.protocol.serializer import create_serializer
from localstack.aws.spec import load_service
from localstack.utils import analytics

LOG = logging.getLogger(__name__)

DispatchTable = Dict[str, ServiceRequestHandler]


def create_skeleton(service: Union[str, ServiceModel], delegate: Any):
    if isinstance(service, str):
        service = load_service(service)

    return Skeleton(service, create_dispatch_table(delegate))


class HandlerAttributes(NamedTuple):
    """
    Holder object of the attributes added to a function by the @handler decorator.
    """

    function_name: str
    operation: str
    pass_context: bool
    expand_parameters: bool


def create_dispatch_table(delegate: object) -> DispatchTable:
    """
    Creates a dispatch table for a given object. First, the entire class tree of the object is scanned to find any
    functions that are decorated with @handler. It then resolves those functions on the delegate.
    """
    # scan class tree for @handler wrapped functions (reverse class tree so that inherited functions overwrite parent
    # functions)
    cls_tree = inspect.getmro(delegate.__class__)
    handlers: Dict[str, HandlerAttributes] = {}
    cls_tree = reversed(list(cls_tree))
    for cls in cls_tree:
        if cls == object:
            continue

        for name, fn in inspect.getmembers(cls, inspect.isfunction):
            try:
                # attributes come from operation_marker in @handler wrapper
                handlers[fn.operation] = HandlerAttributes(
                    fn.__name__, fn.operation, fn.pass_context, fn.expand_parameters
                )
            except AttributeError:
                pass

    # create dispatch table from operation handlers by resolving bound functions on the delegate
    dispatch_table: DispatchTable = {}
    for handler in handlers.values():
        # resolve the bound function of the delegate
        bound_function = getattr(delegate, handler.function_name)
        # create a dispatcher
        dispatch_table[handler.operation] = ServiceRequestDispatcher(
            bound_function,
            operation=handler.operation,
            pass_context=handler.pass_context,
            expand_parameters=handler.expand_parameters,
        )

    return dispatch_table


class ServiceRequestDispatcher:
    fn: Callable
    operation: str
    expand_parameters: bool = True
    pass_context: bool = True

    def __init__(
        self,
        fn: Callable,
        operation: str,
        pass_context: bool = True,
        expand_parameters: bool = True,
    ):
        self.fn = fn
        self.operation = operation
        self.pass_context = pass_context
        self.expand_parameters = expand_parameters

    def __call__(
        self, context: RequestContext, request: ServiceRequest
    ) -> Optional[ServiceResponse]:
        args = []
        kwargs = {}

        if not self.expand_parameters:
            if self.pass_context:
                args.append(context)
            args.append(request)
        else:
            if request is None:
                kwargs = {}
            else:
                kwargs = {xform_name(k): v for k, v in request.items()}
            kwargs["context"] = context

        return self.fn(*args, **kwargs)


class Skeleton:
    service: ServiceModel
    dispatch_table: DispatchTable

    def __init__(self, service: ServiceModel, implementation: Union[Any, DispatchTable]):
        self.service = service
        self.parser = create_parser(service)
        self.serializer = create_serializer(service)

        if isinstance(implementation, dict):
            self.dispatch_table = implementation
        else:
            self.dispatch_table = create_dispatch_table(implementation)

    def invoke(self, context: RequestContext) -> HttpResponse:
        if context.operation and context.service_request:
            # if the parsed request is already set in the context, re-use them
            operation, instance = context.operation, context.service_request
        else:
            # otherwise, parse the incoming HTTPRequest
            operation, instance = self.parser.parse(context.request)
            context.operation = operation

        try:
            # Find the operation's handler in the dispatch table
            if operation.name not in self.dispatch_table:
                LOG.warning(
                    "missing entry in dispatch table for %s.%s",
                    self.service.service_name,
                    operation.name,
                )
                raise NotImplementedError

            return self.dispatch_request(context, instance)
        except ServiceException as e:
            return self.on_service_exception(context, e)
        except NotImplementedError:
            return self.on_not_implemented_error(context)

    def dispatch_request(self, context: RequestContext, instance: ServiceRequest) -> HttpResponse:
        operation = context.operation

        handler = self.dispatch_table[operation.name]

        # Call the appropriate handler
        result = handler(context, instance) or {}

        # if the service handler returned an HTTP request, forego serialization and return immediately
        if isinstance(result, HttpResponse):
            return result

        # Serialize result dict to an HTTPResponse and return it
        return self.serializer.serialize_to_response(result, operation)

    def on_service_exception(
        self, context: RequestContext, exception: ServiceException
    ) -> HttpResponse:
        """
        Called by invoke if the handler of the operation raised a ServiceException.

        :param context: the request context
        :param exception: the exception that was raised
        :return: an HttpResponse object
        """
        return self.serializer.serialize_error_to_response(exception, context.operation)

    def on_not_implemented_error(self, context: RequestContext) -> HttpResponse:
        """
        Called by invoke if either the dispatch table did not contain an entry for the operation, or the service
        provider raised a NotImplementedError
        :param context: the request context
        :return: an HttpResponse object
        """
        operation = context.operation
        serializer = self.serializer

        action_name = operation.name
        service_name = operation.service_model.service_name
        message = f"API action '{action_name}' for service '{service_name}' " f"not yet implemented"
        LOG.info(message)
        error = CommonServiceException("InternalFailure", message, status_code=501)
        # record event
        analytics.log.event(
            "services_notimplemented", payload={"s": service_name, "a": action_name}
        )
        return serializer.serialize_error_to_response(error, operation)
