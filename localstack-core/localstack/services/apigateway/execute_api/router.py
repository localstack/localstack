import logging

from rolo import Request, Router
from rolo.dispatcher import Handler
from werkzeug.routing import Rule

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
        # think about more composite handlers for the future?
        self.gateway = ApiGateway(
            request_handlers=[
                request_parser_handler,
                # TODO: for extending in -ext
                handlers.preprocess_request,
                handlers.method_request_handler,
                handlers.integration_request_handler,
                handlers.integration_handler,
                # temporary handler which executes everything for now
                handlers.global_temporary_handler,
            ],
            response_handlers=[
                handlers.integration_response_handler,
                handlers.method_response_handler,
                # add composite response handlers?
            ],
            exception_handlers=[
                # TODO: we need the exception handler instead of serializing them
            ],
            context_class=InvocationContext,
        )

    def __call__(self, request: Request, **kwargs) -> Response:
        LOG.info("Next-gen handler for APIGW v1 called")
        response = Response()
        self.gateway.process(request, response)

        return response


def register_api_deployment(
    router: Router[Handler], deployment: RestApiDeployment, api_id: str, stage: str
) -> list[Rule]:
    """Registers parameterized routes for API Gateway user invocations."""
    LOG.info("Registering API Gateway routes for API ID '%s' and stage '%s'.", api_id, stage)
    host_pattern = f"{api_id}<regex('(-vpce-[^.]+)?'):vpce_suffix>.execute-api.<regex('.*'):server>"
    handler = RestApiHandler(deployment, stage)
    # TODO: use new `WithHost`? simplify this
    routing_rules = []
    routing_rules.append(
        router.add(
            f"/{stage}/",
            host=host_pattern,
            endpoint=handler,
            defaults={"path": ""},
            strict_slashes=False,
        )
    )
    routing_rules.append(
        router.add(
            f"/{stage}/<path:path>",
            host=host_pattern,
            endpoint=handler,
            strict_slashes=True,
        )
    )

    # add the localstack-specific _user_request_ routes
    routing_rules.append(
        router.add(
            f"/restapis/{api_id}/{stage}/_user_request_",
            endpoint=handler,
            defaults={"path": ""},
        )
    )
    routing_rules.append(
        router.add(
            f"/restapis/{api_id}/{stage}/_user_request_/<path:path>",
            endpoint=handler,
            strict_slashes=True,
        )
    )
    return routing_rules
