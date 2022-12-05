"""A set of common handlers to parse and route AWS service requests."""
import logging
import traceback
from collections import defaultdict
from functools import lru_cache
from typing import Any, Dict, Optional, Union

from botocore.model import OperationModel, ServiceModel

from localstack import config
from localstack.http import Response

from ..api import CommonServiceException, RequestContext, ServiceException
from ..api.core import ServiceOperation
from ..chain import CompositeResponseHandler, ExceptionHandler, Handler, HandlerChain
from ..client import parse_response, parse_service_exception
from ..protocol.parser import RequestParser, create_parser
from ..protocol.serializer import create_serializer
from ..protocol.service_router import determine_aws_service_name
from ..skeleton import Skeleton, create_skeleton
from ..spec import load_service

LOG = logging.getLogger(__name__)


class ServiceNameParser(Handler):
    """
    A handler that parses heuristically from the request the AWS service the request is addressed to.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        service = determine_aws_service_name(context.request)

        if not service:
            return

        context.service = self.get_service_model(service)
        headers = context.request.headers
        headers["x-localstack-tgt-api"] = service  # TODO: probably no longer needed

    @lru_cache()
    def get_service_model(self, service: str) -> ServiceModel:
        return load_service(service)


class ServiceRequestParser(Handler):
    """
    A Handler that parses the service request operation and the instance from a Request. Requires the service to
    already be resolved in the RequestContext (e.g., through a ServiceNameParser)
    """

    parsers: Dict[str, RequestParser]

    def __init__(self):
        self.parsers = dict()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # determine service
        if not context.service:
            LOG.debug("no service set in context, skipping request parsing")
            return

        return self.parse_and_enrich(context)

    def get_parser(self, service: ServiceModel):
        name = service.service_name

        if name in self.parsers:
            return self.parsers[name]

        self.parsers[name] = create_parser(service)
        return self.parsers[name]

    def parse_and_enrich(self, context: RequestContext):
        parser = self.get_parser(context.service)
        operation, instance = parser.parse(context.request)

        # enrich context
        context.operation = operation
        context.service_request = instance


class SkeletonHandler(Handler):
    """
    Expose a Skeleton as a Handler.
    """

    def __init__(self, skeleton: Skeleton):
        self.skeleton = skeleton

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        skeleton_response = self.skeleton.invoke(context)
        response.update_from(skeleton_response)


class ServiceRequestRouter(Handler):
    """
    Routes ServiceOperations to Handlers.
    """

    handlers: Dict[ServiceOperation, Handler]

    def __init__(self):
        self.handlers = dict()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not context.service:
            return

        service_name = context.service.service_name
        operation_name = context.operation.name

        key = ServiceOperation(service_name, operation_name)

        handler = self.handlers.get(key)
        if not handler:
            error = self.create_not_implemented_response(context)
            response.update_from(error)
            chain.stop()
            return

        handler(chain, context, response)

    def add_handler(self, key: ServiceOperation, handler: Handler):
        if key in self.handlers:
            LOG.warning("overwriting existing route for %s", key)

        self.handlers[key] = handler

    def add_provider(self, provider: Any, service: Optional[Union[str, ServiceModel]] = None):
        if not service:
            service = provider.service

        self.add_skeleton(create_skeleton(service, provider))

    def add_skeleton(self, skeleton: Skeleton):
        """
        Creates for each entry in the dispatch table of the skeleton a new route.
        """
        service = skeleton.service.service_name
        handler = SkeletonHandler(skeleton)

        for operation in skeleton.dispatch_table.keys():
            self.add_handler(ServiceOperation(service, operation), handler)

    def create_not_implemented_response(self, context):
        operation = context.operation
        service_name = operation.service_model.service_name
        operation_name = operation.name
        message = f"no handler for operation '{operation_name}' on service '{service_name}'"
        error = CommonServiceException("InternalFailure", message, status_code=501)
        serializer = create_serializer(context.service)
        return serializer.serialize_error_to_response(error, operation, context.request.headers)


class ServiceExceptionSerializer(ExceptionHandler):
    """
    Exception handler that serializes the exception of AWS services.
    """

    handle_internal_failures: bool

    def __init__(self):
        self.handle_internal_failures = True

    def __call__(
        self,
        chain: HandlerChain,
        exception: Exception,
        context: RequestContext,
        response: Response,
    ):
        if not context.service:
            return

        error = self.create_exception_response(exception, context)
        if error:
            response.update_from(error)

    def create_exception_response(self, exception: Exception, context: RequestContext):
        operation = context.operation
        service_name = context.service.service_name
        error = exception

        if operation and isinstance(exception, NotImplementedError):
            action_name = operation.name
            message = (
                f"API action '{action_name}' for service '{service_name}' not yet implemented or pro feature"
                f" - check https://docs.localstack.cloud/user-guide/aws/feature-coverage for further information"
            )
            LOG.info(message)
            error = CommonServiceException("InternalFailure", message, status_code=501)
            context.service_exception = error

        elif not isinstance(exception, ServiceException):
            if not self.handle_internal_failures:
                return

            if config.DEBUG:
                exception = "".join(
                    traceback.format_exception(
                        type(exception), value=exception, tb=exception.__traceback__
                    )
                )

            # wrap exception for serialization
            if operation:
                operation_name = operation.name
                msg = "exception while calling %s.%s: %s" % (
                    service_name,
                    operation_name,
                    exception,
                )
            else:
                # just use any operation for mocking purposes (the parser needs it to populate the default response)
                operation = context.service.operation_model(context.service.operation_names[0])
                msg = "exception while calling %s with unknown operation: %s" % (
                    service_name,
                    exception,
                )

            status_code = 501 if config.FAIL_FAST else 500

            error = CommonServiceException("InternalError", msg, status_code=status_code)
            context.service_exception = error

        serializer = create_serializer(context.service)  # TODO: serializer cache
        return serializer.serialize_error_to_response(error, operation, context.request.headers)


class ServiceResponseParser(Handler):
    """
    This response handler makes sure that, if the current request in an AWS request, that either ``service_response``
    or ``service_exception`` of ``RequestContext`` is set to something sensible before other downstream response
    handlers are called. When the Skeleton invokes an ASF-native provider, this will mostly return immediately
    because the skeleton sets the service response directly to what comes out of the provider. When responses come
    back from backends like Moto, we may need to parse the raw HTTP response, since we sometimes proxy directly. If
    the ``service_response`` is an error, then we parse the response and create an appropriate exception from the
    error response. If ``service_exception`` is set, then we also try to make sure the exception attributes like
    code, sender_fault, and message have values.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not context.operation:
            return

        if context.service_response:
            return

        if exception := context.service_exception:
            if isinstance(exception, ServiceException):
                try:
                    exception.code
                except AttributeError:
                    # FIXME: we should set the exception attributes in the scaffold when we generate the exceptions.
                    #  this is a workaround for now, since we are not doing that yet, and the attributes may be unset.
                    self._set_exception_attributes(context.operation, exception)
                return
            # this shouldn't happen, but we'll log a warning anyway
            else:
                LOG.warning("Cannot parse exception %s", context.service_exception)
                return

        if response.content_length is None or context.operation.has_event_stream_output:
            # cannot/should not parse streaming responses
            context.service_response = {}
            return

        # in this case we need to parse the raw response
        parsed = parse_response(context.operation, response, include_response_metadata=False)
        if service_exception := parse_service_exception(response, parsed):
            context.service_exception = service_exception
        else:
            context.service_response = parsed

    @staticmethod
    def _set_exception_attributes(operation: OperationModel, error: ServiceException):
        """Sets the code, sender_fault, and status_code attributes of the ServiceException from the shape."""
        error_shape_name = error.__class__.__name__
        shape = operation.service_model.shape_for(error_shape_name)
        error_spec = shape.metadata.get("error", {})
        error.code = error_spec.get("code", shape.name)
        error.sender_fault = error_spec.get("senderFault", False)
        error.status_code = error_spec.get("httpStatusCode", 400)


class ServiceResponseHandlers(Handler):
    """
    A handler that triggers a CompositeResponseHandler based on an association with a particular service. Handlers
    are only called if the request context has a service, and there are handlers for that particular service.
    """

    handlers: Dict[str, CompositeResponseHandler]

    def __init__(self):
        self.handlers = defaultdict(CompositeResponseHandler)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not context.service:
            return

        if service_handler := self.handlers.get(context.service.service_name):
            service_handler(chain, context, response)

    def append(self, service: str, handler: Handler):
        """
        Appends a given handler to the list of service handlers.
        :param service: the service name, e.g., "dynamodb", or "sqs"
        :param handler: the handler to attach
        """
        self.handlers[service].append(handler)
