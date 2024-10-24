import asyncio
import dataclasses
import inspect
import logging
from typing import Any, Callable, Dict, NamedTuple, Optional, Union

import nats
from botocore import xform_name
from botocore.model import ServiceModel
from orjson import orjson

from localstack.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceException,
)
from localstack.aws.api.core import ServiceRequest, ServiceRequestHandler, ServiceResponse
from localstack.aws.protocol.parser import create_parser
from localstack.aws.protocol.serializer import ResponseSerializer, create_serializer
from localstack.aws.spec import load_service
from localstack.http import Response
from localstack.utils import analytics
from localstack.utils.coverage_docs import get_coverage_link_for_service

LOG = logging.getLogger(__name__)

DispatchTable = Dict[str, ServiceRequestHandler]


@dataclasses.dataclass
class FakeOperation:
    name: str


@dataclasses.dataclass
class FakeService:
    protocol: str


@dataclasses.dataclass
class JsonContext:
    account_id: str
    region: str
    request_id: str
    partition: str
    operation: FakeOperation
    service: FakeService


def _copy_context(ctx: RequestContext) -> RequestContext:
    ctx_cpy = RequestContext(ctx.request)
    for attr in ("account_id", "region", "request_id", "request", "partition"):
        setattr(ctx_cpy, attr, getattr(ctx, attr))

    ctx_cpy.operation = FakeOperation(ctx.operation.name)
    ctx_cpy.service = FakeService(ctx.service.protocol)

    return ctx_cpy


def _copy_context_json(ctx: RequestContext) -> JsonContext:
    ctx_cpy = JsonContext(
        account_id=ctx.account_id,
        region=ctx.region,
        request_id=ctx.request_id,
        partition=ctx.partition,
        operation=FakeOperation(ctx.operation.name),
        service=FakeService(ctx.service.protocol),
    )

    return ctx_cpy


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
        self._nats_conn = None

        if isinstance(implementation, dict):
            self.dispatch_table = implementation
        else:
            self.dispatch_table = create_dispatch_table(implementation)

    def _get_client(self, loop):
        self._nats_conn = asyncio.run_coroutine_threadsafe(
            nats.connect("nats://localhost:4222"), loop
        ).result(timeout=3)

        return self._nats_conn

    def invoke(self, context: RequestContext) -> Response:
        serializer = create_serializer(context.service)

        if context.operation and context.service_request:
            # if the parsed request is already set in the context, re-use them
            operation, instance = context.operation, context.service_request
        else:
            # otherwise, parse the incoming HTTPRequest
            operation, instance = create_parser(context.service).parse(context.request)
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

            return self.dispatch_request(serializer, context, instance)
        except ServiceException as e:
            return self.on_service_exception(serializer, context, e)
        except NotImplementedError as e:
            return self.on_not_implemented_error(serializer, context, e)

    def dispatch_request(
        self, serializer: ResponseSerializer, context: RequestContext, instance: ServiceRequest
    ) -> Response:
        loop = context._loop

        if not self._nats_conn:
            self._get_client(loop)

        operation = context.operation

        req = orjson.dumps(
            {
                "context": _copy_context_json(context),
                "instance": instance,
            }
        )

        # hardcoded response
        # result = {
        #     "MessageId": "cfcd8be4-7d9e-42c4-965f-ada0d77c3779",
        #     "MD5OfMessageBody": "99914b932bd37a50b983c5e7c90ae93b",
        #     "MD5OfMessageAttributes": None,
        #     "SequenceNumber": None,
        #     "MD5OfMessageSystemAttributes": None,
        # }

        # empty payload
        # coro = self._nats_conn.request("services.sqs", b"", timeout=0.5)

        # subject = f"services.sqs.{context.account_id}"
        subject = f"services.sqs.{context.operation.name}"
        coro = self._nats_conn.request(subject, req, timeout=0.5)
        response = asyncio.run_coroutine_threadsafe(coro, loop).result()
        result = orjson.loads(response.data)

        # handler = self.dispatch_table[operation.name]
        # # Call the appropriate handler
        # result = handler(context, instance) or {}

        # if the service handler returned an HTTP request, forego serialization and return immediately
        if isinstance(result, Response):
            return result

        context.service_response = result

        # Serialize result dict to a Response and return it
        return serializer.serialize_to_response(
            result, operation, context.request.headers, context.request_id
        )

    def on_service_exception(
        self, serializer: ResponseSerializer, context: RequestContext, exception: ServiceException
    ) -> Response:
        """
        Called by invoke if the handler of the operation raised a ServiceException.

        :param serializer: serializer which should be used to serialize the exception
        :param context: the request context
        :param exception: the exception that was raised
        :return: a Response object
        """
        context.service_exception = exception

        return serializer.serialize_error_to_response(
            exception, context.operation, context.request.headers, context.request_id
        )

    def on_not_implemented_error(
        self,
        serializer: ResponseSerializer,
        context: RequestContext,
        exception: NotImplementedError,
    ) -> Response:
        """
        Called by invoke if either the dispatch table did not contain an entry for the operation, or the service
        provider raised a NotImplementedError
        :param serializer: the serialzier which should be used to serialize the NotImplementedError
        :param context: the request context
        :param exception: the NotImplementedError that was raised
        :return: a Response object
        """
        operation = context.operation

        action_name = operation.name
        service_name = operation.service_model.service_name
        exception_message: str | None = exception.args[0] if exception.args else None
        message = exception_message or get_coverage_link_for_service(service_name, action_name)
        LOG.info(message)
        error = CommonServiceException("InternalFailure", message, status_code=501)
        # record event
        analytics.log.event(
            "services_notimplemented", payload={"s": service_name, "a": action_name}
        )
        context.service_exception = error

        return serializer.serialize_error_to_response(
            error, operation, context.request.headers, context.request_id
        )
