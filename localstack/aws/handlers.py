"""
A set of common handlers to build an AWS server application.
"""
import logging
import traceback
from functools import lru_cache
from typing import Any, Dict, Optional, Union

from botocore.model import ServiceModel
from werkzeug.datastructures import Headers
from werkzeug.exceptions import NotFound

from localstack import config, constants
from localstack.http import Request, Response, Router
from localstack.services.internal import LocalstackResources

from .api import CommonServiceException, RequestContext, ServiceException
from .api.core import ServiceOperation
from .chain import ExceptionHandler, Handler, HandlerChain, HandlerChainAdapter
from .protocol.parser import RequestParser, create_parser
from .protocol.serializer import create_serializer
from .protocol.service_router import determine_aws_service_name
from .skeleton import Skeleton, create_skeleton
from .spec import load_service

LOG = logging.getLogger(__name__)


class PushQuartContext(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # hack for legacy compatibility. this is wrong on so many levels i literally can't even.
        import quart.globals

        quart.globals._request_ctx_stack.push(context)


class PopQuartContext(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # hack for legacy compatibility
        import quart.globals

        quart.globals._request_ctx_stack.pop()


def inject_auth_header_if_missing(chain: HandlerChain, context: RequestContext, response: Response):
    # FIXME: this is needed for allowing access to resources via plain URLs where access is typically restricted (
    #  e.g., GET requests on S3 URLs or apigateway routes). this should probably be part of a general IAM middleware
    #  (that allows access to restricted resources by default)
    if not context.service:
        return
    from localstack.utils.aws import aws_stack

    api = context.service.service_name
    headers = context.request.headers

    if not headers.get("Authorization"):
        headers["Authorization"] = aws_stack.mock_aws_request_headers(api)["Authorization"]


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
        headers["x-localstack-tgt-api"] = service

    @lru_cache()
    def get_service_model(self, service: str) -> ServiceModel:
        return load_service(service)


class CustomServiceRules(HandlerChainAdapter):
    """
    HandlerChain that serves as container for custom service rules that can be dynamically added by services,
    like the SqsQueueActionHandler.
    """

    def __init__(self):
        super().__init__()
        # this makes sure errors are propagated to the outer handler chain, which will the one
        # built by the AWS gateway.
        self.chain.raise_on_error = True


class ServiceRequestParser(Handler):
    """
    A Handler that parses the service request operation and the instance from an Request. Requires the service to
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


class RegionContextEnricher(Handler):
    """
    A handler that sets the AWS region of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        context.region = self.get_region(context.request)

    @staticmethod
    def get_region(request: Request) -> str:
        from localstack.utils.aws.request_context import extract_region_from_headers

        return extract_region_from_headers(request.headers)


class DefaultAccountIdEnricher(Handler):
    """
    A handler that sets the AWS account of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # TODO: at some point we may want to get the account id from credentials (+ a user repository)
        from localstack import constants

        context.account_id = constants.TEST_AWS_ACCOUNT_ID


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
        return serializer.serialize_error_to_response(error, operation)


class RouterHandler(Handler):
    """
    Adapter to serve a Router as a Handler.
    """

    resources: Router

    def __init__(self, router: Router, respond_not_found=False) -> None:
        self.router = router
        self.respond_not_found = respond_not_found

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        try:
            router_response = self.router.dispatch(context.request)
            response.update_from(router_response)
            chain.stop()
        except NotFound:
            if self.respond_not_found:
                chain.respond(404)


class LocalstackResourceHandler(Handler):
    """
    Adapter to serve LocalstackResources as a Handler.
    """

    resources: LocalstackResources

    def __init__(self, resources: LocalstackResources = None) -> None:
        self.resources = resources or LocalstackResources()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        try:
            # serve
            response.update_from(self.resources.dispatch(context.request))
            chain.stop()
        except NotFound:
            path = context.request.path
            if path.startswith(constants.INTERNAL_RESOURCE_PATH + "/"):
                # only return 404 if we're accessing an internal resource, otherwise fall back to the other handlers
                LOG.warning("Unable to find resource handler for path: %s", path)
                chain.respond(404)


class ExceptionLogger(ExceptionHandler):
    """
    Logs exceptions into a logger.
    """

    def __init__(self, logger=None):
        self.logger = logger or LOG

    def __call__(
        self,
        chain: HandlerChain,
        exception: Exception,
        context: RequestContext,
        response: Response,
    ):
        if self.logger.isEnabledFor(level=logging.DEBUG):
            self.logger.exception("exception during call chain", exc_info=exception)
        else:
            self.logger.error("exception during call chain: %s", exception)


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
                f"API action '{action_name}' for service '{service_name}' " f"not yet implemented"
            )
            LOG.info(message)
            error = CommonServiceException("InternalFailure", message, status_code=501)

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

            error = CommonServiceException("LocalStackError", msg, status_code=status_code)

        serializer = create_serializer(context.service)  # TODO: serializer cache
        return serializer.serialize_error_to_response(error, operation)


class InternalFailureHandler(ExceptionHandler):
    """
    Exception handler that returns a generic error message if there is no response set yet.
    """

    def __call__(
        self,
        chain: HandlerChain,
        exception: Exception,
        context: RequestContext,
        response: Response,
    ):
        if response.response:
            # response already set
            return

        LOG.debug("setting internal failure response for %s", exception)
        response.status_code = 500
        response.set_json(
            {
                "message": "Unexpected exception",
                "error": str(exception),
                "type": str(exception.__class__.__name__),
            }
        )


class EmptyResponseHandler(Handler):
    """
    Handler that creates a default response if the response in the context is empty.
    """

    status_code: int
    body: bytes
    headers: dict

    def __init__(self, status_code=404, body=None, headers=None):
        self.status_code = status_code
        self.body = body or b""
        self.headers = headers or Headers()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if self.is_empty_response(response):
            self.populate_default_response(response)

    def is_empty_response(self, response: Response):
        return response.status_code in [0, None] and not response.response

    def populate_default_response(self, response: Response):
        response.status_code = self.status_code
        response.data = self.body
        response.headers.update(self.headers)


parse_service_name = ServiceNameParser()
parse_service_request = ServiceRequestParser()
process_custom_service_rules = CustomServiceRules()
add_default_account_id = DefaultAccountIdEnricher()
add_region_from_header = RegionContextEnricher()
log_exception = ExceptionLogger()
handle_service_exception = ServiceExceptionSerializer()
handle_internal_failure = InternalFailureHandler()
handle_empty_response = EmptyResponseHandler()
serve_localstack_resources = LocalstackResourceHandler()
# legacy compatibility handlers for when
pop_quart_context = PopQuartContext()
push_quart_context = PushQuartContext()
