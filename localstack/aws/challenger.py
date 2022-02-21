import importlib
import logging
from functools import lru_cache
from urllib.parse import urlsplit

from botocore.parsers import create_parser as botocore_create_parser

from localstack.aws.api import (
    CommonServiceException,
    HttpRequest,
    HttpResponse,
    RequestContext,
    ServiceException,
)
from localstack.aws.protocol.parser import create_parser as asf_create_parser
from localstack.aws.protocol.serializer import create_serializer
from localstack.aws.proxy import AwsApiListener
from localstack.aws.skeleton import Skeleton
from localstack.aws.spec import load_service
from localstack.utils.common import snake_to_camel_case, to_bytes

LOG = logging.getLogger(__name__)


class ChallengeFailed(Exception):
    pass


class Challenger(Skeleton):
    def __init__(self, service: str):
        service_name = service.replace("-", "_")
        class_name = service_name + "_api"
        class_name = snake_to_camel_case(class_name)
        module_name = f"localstack.aws.api.{service_name}"

        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        super(Challenger, self).__init__(load_service(service), cls())

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
                raise ChallengeFailed(
                    "missing entry in dispatch table for %s.%s",
                    self.service.service_name,
                    operation.name,
                )

            return self.dispatch_request(context, instance)
        except ServiceException as e:
            return self.on_service_exception(context, e)
        except NotImplementedError:
            return self.on_not_implemented_error(context)

    def on_service_exception(
        self, context: RequestContext, exception: ServiceException
    ) -> HttpResponse:
        raise ChallengeFailed("challenge failed: service error (whut?)") from exception

    def on_not_implemented_error(self, context: RequestContext) -> HttpResponse:
        raise NotImplementedError


class MockOperationModel:
    @property
    def http(self):
        return {}


class AsfChallengerListener(AwsApiListener):
    def __init__(self, api: str):
        self.service = load_service(api)
        module_name = f"localstack.aws.api.{self.service.service_name}"
        self.api_module = importlib.import_module(module_name)
        self.api = api
        self.serializer = create_serializer(self.service)

    def forward_request(self, method, path, data, headers):
        context = None
        try:
            # this may raise an exception when the skeleton and therefore the parser is created
            challenger = get_challenger(self.api)

            split_url = urlsplit(path)
            request = HttpRequest(
                method=method,
                path=split_url.path,
                query_string=split_url.query,
                headers=headers,
                body=data,
            )

            context = self.create_request_context(request)
            try:
                challenger.invoke(context)
            except NotImplementedError:
                # this one's OK
                return True

            raise ChallengeFailed("invocation returned a result, that's not right!")

        except Exception as e:
            LOG.exception(
                "parser challenge failed for request to %s method=%s path=%s data=%s headers=%s",
                self.service.service_name,
                method,
                path,
                data,
                headers,
            )
            # we'll try to create a proper HTTP response to the client so it doesn't keep retrying.
            return self._create_error_response(context, e)

    def return_response(self, method, path, data, headers, response):
        # Detect the operation (again)
        split_url = urlsplit(path)
        request = HttpRequest(
            method=method,
            path=split_url.path,
            query_string=split_url.query,
            headers=headers,
            body=data,
        )
        context = self.create_request_context(request)

        try:
            parser = asf_create_parser(self.service)
            operation, _ = parser.parse(context.request)

            serializer = create_serializer(self.service)
            response_parser = botocore_create_parser(self.service.protocol)
            parsed_response = response_parser.parse(
                {
                    "headers": response.headers,
                    "body": to_bytes(response.content),
                    "status_code": response.status_code,
                },
                operation.output_shape,
            )
            # Remove the "ResponseMetadata" (this is added by botocore)
            parsed_response.pop("ResponseMetadata")
            if response.status_code < 400:
                serialized = serializer.serialize_to_response(parsed_response, operation)
            else:
                if "Error" in parsed_response and "Code" in parsed_response["Error"]:
                    # Create the exception which will be serialized
                    code = parsed_response["Error"]["Code"]
                    exception_cls = getattr(self.api_module, code)
                    message = parsed_response["Error"].get(
                        "Message", parsed_response["Error"].get("message")
                    )
                    exception = exception_cls(message)
                    # Parse the error
                    serialized = serializer.serialize_error_to_response(exception, operation)
                else:
                    raise ChallengeFailed(
                        "Status code >= 400, but no error metadata in the response."
                    )
            # Parse the serialized response with botocore
            parsed_serialized = response_parser.parse(
                {
                    "headers": {key: value for key, value in serialized.headers},
                    "body": to_bytes(serialized.data),
                    "status_code": serialized.status_code,
                },
                operation.output_shape,
            )
            # Again, remove the "ResponseMetadata" (this is added by botocore)
            parsed_serialized.pop("ResponseMetadata")
            # TODO adjust the two here a bit, because this check seems to be a bit too strict?
            # Test if the initially parsed response and the parsed response which was created by the
            # serializer are equal
            assert parsed_serialized == parsed_response
        except Exception as e:
            LOG.exception(
                "serializer challenge failed for response of %s method=%s path=%s headers=%s",
                self.service.service_name,
                method,
                path,
                headers,
            )
            # we'll try to create a proper HTTP response to the client so it doesn't keep retrying.
            return self._create_error_response(context, e)

    def _create_error_response(self, context, e):
        try:
            if context and context.operation:
                op = context.operation
            else:
                # best-effort to return any type of error
                op = self.service.operation_model(self.service.operation_names[0])

            resp = self.serializer.serialize_error_to_response(
                CommonServiceException("ClientError", str(e), status_code=400),
                op,
            )
            return self.to_server_response(resp)
        except Exception:
            LOG.exception(
                "exception while trying to create a response. this is an implementation error of the "
                "challenger :("
            )


@lru_cache()
def get_asf_challenge_listener(service: str) -> AsfChallengerListener:
    return AsfChallengerListener(service)


@lru_cache()
def get_challenger(service: str) -> Challenger:
    return Challenger(service)
