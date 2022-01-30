import importlib
import logging
from functools import lru_cache
from urllib.parse import urlsplit

from localstack.aws.api import (
    CommonServiceException,
    HttpRequest,
    HttpResponse,
    RequestContext,
    ServiceException,
)
from localstack.aws.protocol.serializer import create_serializer
from localstack.aws.proxy import AwsApiListener
from localstack.aws.skeleton import Skeleton
from localstack.aws.spec import load_service
from localstack.utils.common import snake_to_camel_case

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
