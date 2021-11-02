"""
A set of common handlers to build an AWS server application.
"""
import logging
from typing import Any, Dict, Optional, Union

from botocore.model import ServiceModel
from werkzeug.datastructures import Headers

from .api import CommonServiceException, HttpRequest, HttpResponse, RequestContext
from .api.core import ServiceOperation
from .chain import ExceptionHandler, Handler, HandlerChain
from .protocol.parser import RequestParser, create_parser
from .protocol.serializer import create_serializer
from .skeleton import Skeleton, create_skeleton
from .spec import load_service

LOG = logging.getLogger(__name__)


class ServiceNameParser(Handler):
    """
    A handler that parses heuristically from the request the AWS service the request is addressed to.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        headers = context.request["headers"]

        LOG.info("determining service from headers %s", headers)

        # target = headers.get("x-amz-target", "")
        # host = headers.get("host", "")
        auth_header = headers.get("authorization", "")

        credential_scope = auth_header.split(",")[0].split()[1]
        _, _, _, service, _ = credential_scope.split("/")

        if not service:
            LOG.warning("unable to determine service from request")
            return

        LOG.info("service for request is %s", service)

        context.service = load_service(service)
        headers["x-localstack-tgt-api"] = str(service)


class ServiceRequestParser(Handler):
    """
    A Handler that parses the service request operation and the instance from an HttpRequest. Requires the service to
    already be resolved in the RequestContext (e.g., through a ServiceNameParser)
    """

    parsers: Dict[str, RequestParser]

    def __init__(self):
        self.parsers = dict()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        # determine service
        if not context.service:
            LOG.warning("no service set in context, cannot parse request")
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

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        context.region = self.get_region(context.request)

    @staticmethod
    def get_region(request: HttpRequest) -> str:
        from localstack.utils.aws.request_context import extract_region_from_headers

        return extract_region_from_headers(request["headers"])


class DefaultAccountIdEnricher(Handler):
    """
    A handler that sets the AWS account of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        # TODO: at some point we may want to get the account id from credentials (+ a user repository)
        from localstack import constants

        context.account_id = constants.TEST_AWS_ACCOUNT_ID


class SkeletonHandler(Handler):
    """
    Expose a Skeleton as a Handler.
    """

    def __init__(self, skeleton: Skeleton):
        self.skeleton = skeleton

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        skeleton_response = self.skeleton.invoke(context)
        response["status_code"] = skeleton_response["status_code"]
        response["body"] = skeleton_response["body"]
        response["headers"] = Headers(skeleton_response["headers"])


class ServiceRequestRouter(Handler):
    handlers: Dict[ServiceOperation, Handler]

    def __init__(self):
        self.handlers = dict()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        service_name = context.service.service_name
        operation_name = context.operation.name

        key = ServiceOperation(service_name, operation_name)

        handler = self.handlers.get(key)
        if not handler:
            error = self.create_not_implemented_response(context)
            response["body"] = error["body"]
            response["status_code"] = error["status_code"]
            response["headers"] = error["headers"]
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


class ExceptionLogger(ExceptionHandler):
    def __call__(
        self,
        chain: HandlerChain,
        exception: Exception,
        context: RequestContext,
        response: HttpResponse,
    ):
        if LOG.isEnabledFor(level=logging.DEBUG):
            LOG.exception("exception during call chain", exc_info=exception)
        else:
            LOG.error("exception during call chain: %s", exception)


class ExceptionSerializer(ExceptionHandler):
    def __call__(
        self,
        chain: HandlerChain,
        exception: Exception,
        context: RequestContext,
        response: HttpResponse,
    ):
        if context.operation:
            error = self.create_exception_response(exception, context)
            response["body"] = error["body"]
            response["status_code"] = error["status_code"]
            response["headers"] = error["headers"]

    def create_exception_response(self, exception, context):
        operation = context.operation
        service_name = operation.service_model.service_name
        operation_name = operation.name
        msg = "exception while calling %s.%s: %s" % (service_name, operation_name, exception)
        error = CommonServiceException("InternalFailure", msg, status_code=500)
        serializer = create_serializer(context.service)
        return serializer.serialize_error_to_response(error, operation)


class LegacyPluginHandler(Handler):
    """
    This adapter exposes Services that are developed as ProxyListener as Handler.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        from localstack.services.edge import do_forward_request

        request = context.request

        api = context.service.service_name
        method = request["method"]
        path = request["path"]
        data = request["body"]
        headers = request["headers"]

        result = do_forward_request(api, method, path, data, headers, port=None)
        # TODO: the edge proxy does a lot more to the result, so this may not work for all corner cases

        response["status_code"] = result.status_code
        response["body"] = result.content
        response["headers"] = dict(result.headers)


parse_service_name = ServiceNameParser()
parse_service_request = ServiceRequestParser()
add_default_account_id = DefaultAccountIdEnricher()
add_region_from_header = RegionContextEnricher()
log_exception = ExceptionLogger()
return_serialized_exception = ExceptionSerializer()
