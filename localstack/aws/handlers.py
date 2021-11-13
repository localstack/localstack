"""
A set of common handlers to build an AWS server application.
"""
import json
import logging
from typing import Any, Dict, Optional, Union

from botocore.model import ServiceModel
from werkzeug.datastructures import Headers

from .api import CommonServiceException, HttpRequest, HttpResponse, RequestContext, ServiceException
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
        service = self.guess_aws_service(context.request)

        if not service:
            LOG.warning("unable to determine service from request")
            return

        LOG.debug("loading service for request to %s", service)
        context.service = load_service(service)
        headers = context.request["headers"]
        headers["x-localstack-tgt-api"] = service

    def guess_aws_service(self, request: HttpRequest) -> Optional[str]:
        headers = request["headers"]

        target = headers.get("x-amz-target", "")
        host = headers.get("host", "")
        auth_header = headers.get("authorization", "")

        LOG.debug(
            "determining service from request host='%s', x-amz-target='%s', auth_header='%s'",
            target,
            host,
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
    """
    Routes ServiceOperations to Handlers.
    """

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
        response: HttpResponse,
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
        response: HttpResponse,
    ):
        if not context.service:
            return

        if not context.operation:
            return

        error = self.create_exception_response(exception, context)
        if error:
            response["body"] = error["body"]
            response["status_code"] = error["status_code"]
            response["headers"] = error["headers"]

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
    Exception handler that returns an generic error message if there is no response set yet.
    """

    def __call__(
        self,
        chain: HandlerChain,
        exception: Exception,
        context: RequestContext,
        response: HttpResponse,
    ):
        if response.get("status_code"):
            # response code already set
            return

        LOG.debug("setting internal failure response for %s", exception)
        response["status_code"] = 500
        response["body"] = json.dumps(
            {
                "message": "Unexpected exception",
                "error": str(exception),
                "type": str(exception.__class__.__name__),
            }
        ).encode("utf-8")


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

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        if self.is_empty_response(response):
            self.populate_default_response(response)

    def is_empty_response(self, response: HttpResponse):
        return response.get("status_code") in [0, None] and not response.get("body")

    def populate_default_response(self, response: HttpResponse):
        response["status_code"] = self.status_code
        response["body"] = self.body
        response["headers"] = self.headers


parse_service_name = ServiceNameParser()
parse_service_request = ServiceRequestParser()
add_default_account_id = DefaultAccountIdEnricher()
add_region_from_header = RegionContextEnricher()
log_exception = ExceptionLogger()
handle_service_exception = ServiceExceptionSerializer()
handle_internal_failure = InternalFailureHandler()
handle_empty_response = EmptyResponseHandler()
