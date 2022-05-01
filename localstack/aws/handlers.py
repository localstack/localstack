"""
A set of common handlers to build an AWS server application.
"""
import logging
from functools import lru_cache
from typing import Any, Dict, Optional, Union

from botocore.model import ServiceModel
from requests import Response as RequestsResponse
from werkzeug.datastructures import Headers
from werkzeug.exceptions import NotFound

from localstack import constants
from localstack.http import Request, Response, Router
from localstack.services.internal import LocalstackResources

from .api import CommonServiceException, RequestContext, ServiceException
from .api.core import ServiceOperation
from .chain import ExceptionHandler, Handler, HandlerChain, HandlerChainAdapter
from .protocol.parser import RequestParser, create_parser
from .protocol.serializer import create_serializer
from .skeleton import Skeleton, create_skeleton
from .spec import load_service

LOG = logging.getLogger(__name__)


class ServiceNameParser(Handler):
    """
    A handler that parses heuristically from the request the AWS service the request is addressed to.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        service = self.guess_aws_service(context.request)

        if not service:
            LOG.warning("unable to determine service from request")
            return
        else:
            LOG.debug("determined service %s", service)

        context.service = self.get_service_model(service)
        headers = context.request.headers
        headers["x-localstack-tgt-api"] = service

    @lru_cache()
    def get_service_model(self, service: str) -> ServiceModel:
        return load_service(service)

    def guess_aws_service(self, request: Request) -> Optional[str]:
        headers = request.headers

        host = request.host
        auth_header = headers.get("authorization", "")
        target = headers.get("x-amz-target", "")

        LOG.debug(
            "determining service from request host='%s', x-amz-target='%s', auth_header='%s'",
            host,
            target,
            auth_header,
        )

        if not auth_header and not target and "." not in host:
            # no way of determining target API
            return

        service = self.extract_service_name_from_auth_header(auth_header)

        if service:
            # check service aliases
            if service == "monitoring":
                return "cloudwatch"
            elif service == "email":
                return "ses"
            elif service == "execute-api":
                return "apigateway"
            elif service == "EventBridge":
                return "events"

            return service

        # check x-amz-target rules
        if target.startswith("Firehose_"):
            return "firehose"
        elif target.startswith("DynamoDB_"):
            return "dynamodb"
        elif target.startswith("DynamoDBStreams") or host.startswith("streams.dynamodb."):
            # Note: DDB streams requests use ../dynamodb/.. auth header, hence we also need to update result_before
            return "dynamodbstreams"
        elif target.startswith("AWSEvents"):
            return "events"
        elif target.startswith("ResourceGroupsTaggingAPI_"):
            return "resourcegroupstaggingapi"
        elif target.startswith("AWSCognitoIdentityProviderService") or "cognito-idp." in host:
            return "cognito-idp"
        elif target.startswith("AWSCognitoIdentityService") or "cognito-identity." in host:
            return "cognito-identity"

        # check host matching rules
        if host.endswith("cloudfront.net"):
            return "cloudfront"
        elif host.startswith("states."):
            return "stepfunctions"
        elif "route53." in host:
            return "route53"
        elif ".execute-api." in host:
            return "apigateway"

        # check special S3 rules
        if self.uses_host_addressing(headers):
            return "s3"

        return None

    @staticmethod
    def uses_host_addressing(headers):
        from localstack.services.s3.s3_utils import uses_host_addressing

        return uses_host_addressing(headers)

    @staticmethod
    def extract_service_name_from_auth_header(auth_header: str) -> Optional[str]:
        try:
            credential_scope = auth_header.split(",")[0].split()[1]
            _, _, _, service, _ = credential_scope.split("/")
            return service
        except Exception:
            return None


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

        if not context.operation:
            return

        error = self.create_exception_response(exception, context)
        if error:
            response.update_from(error)

    def create_exception_response(self, exception, context):
        operation = context.operation
        error = exception

        if isinstance(exception, NotImplementedError):
            action_name = operation.name
            service_name = operation.service_model.service_name
            message = (
                f"API action '{action_name}' for service '{service_name}' " f"not yet implemented"
            )
            LOG.info(message)
            error = CommonServiceException("InternalFailure", message, status_code=501)

        elif not isinstance(exception, ServiceException):
            if not self.handle_internal_failures:
                return
            # wrap exception for serialization
            service_name = operation.service_model.service_name
            operation_name = operation.name
            msg = "exception while calling %s.%s: %s" % (service_name, operation_name, exception)
            error = CommonServiceException("InternalFailure", msg, status_code=500)

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
        if response.data:
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


class LegacyPluginHandler(Handler):
    """
    This adapter exposes Services that are developed as ProxyListener as Handler.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        from localstack.services.edge import do_forward_request

        request = context.request

        result = do_forward_request(
            api=context.service.service_name,
            method=request.method,
            path=request.full_path if request.query_string else request.path,
            data=request.get_data(True),
            headers=request.headers,
            port=None,
        )

        if type(result) == int:
            chain.respond(status_code=result)
            return

        if isinstance(result, tuple):
            # special case for Kinesis SubscribeToShard
            if len(result) == 2:
                response.status_code = 200
                response.set_response(result[0])
                response.headers.update(dict(result[1]))
                chain.stop()
                return

        if isinstance(result, RequestsResponse):
            response.status_code = result.status_code
            response.headers.update(dict(result.headers))
            response.data = result.content
            chain.stop()
            return

        raise ValueError("cannot create response for result %s" % result)


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
        return response.status_code in [0, None] or not response.data

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
