import logging

from rolo import Request, Router
from rolo.dispatcher import Handler

from localstack.http import Response
from localstack.services.apigateway.execute_api import handlers

from ..models import RestApiDeployment
from .context import InvocationContext
from .gateway import ApiGateway
from .handlers.parse import InvocationRequestParser

LOG = logging.getLogger(__name__)


class RestApiHandler:
    def __init__(self, deployment: RestApiDeployment, stage: str):
        request_parser_handler = InvocationRequestParser(deployment, stage=stage)

        self.gateway = ApiGateway(
            request_handlers=[
                request_parser_handler,
                handlers.global_temporary_handler,
            ],
            response_handlers=[],
            exception_handlers=[],
            context_class=InvocationContext,
        )

    def __call__(self, request: Request, **kwargs) -> Response:
        response = Response()
        self.gateway.process(request, response)

        return response


def register_api_deployment(
    router: Router[Handler], deployment: RestApiDeployment, api_id: str, stage: str
):
    """Registers parameterized routes for API Gateway user invocations."""

    LOG.debug("Registering API Gateway routes for API ID '%s' and stage '%s'.", api_id, stage)
    host_pattern = "<regex('[^-]+'):api_id><regex('(-vpce-[^.]+)?'):vpce_suffix>.execute-api.<regex('.*'):server>"
    handler = RestApiHandler(deployment, stage)
    # TODO: use new `WithHost`?
    router.add(
        "/",
        host=host_pattern,
        endpoint=handler,
        defaults={"path": "", "stage": None},
        strict_slashes=True,
    )
    router.add(
        "/<stage>/",
        host=host_pattern,
        endpoint=handler,
        defaults={"path": ""},
        strict_slashes=False,
    )
    router.add(
        "/<stage>/<path:path>",
        host=host_pattern,
        endpoint=handler,
        strict_slashes=True,
    )

    # add the localstack-specific _user_request_ routes
    router.add(
        "/restapis/<api_id>/<stage>/_user_request_",
        endpoint=handler,
        defaults={"path": ""},
    )
    router.add(
        "/restapis/<api_id>/<stage>/_user_request_/<path:path>",
        endpoint=handler,
        strict_slashes=True,
    )
