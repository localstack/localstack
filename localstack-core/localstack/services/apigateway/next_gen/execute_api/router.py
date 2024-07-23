import logging

from rolo import Request, Router
from rolo.routing.handler import Handler
from werkzeug.routing import Rule

from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID
from localstack.http import Response
from localstack.services.apigateway.models import ApiGatewayStore, apigateway_stores
from localstack.services.edge import ROUTER

from .context import RestApiInvocationContext
from .gateway import RestApiGateway

LOG = logging.getLogger(__name__)


class ApiGatewayEndpoint:
    """
    This class is the endpoint for API Gateway invocations of the `execute-api` route. It will take the incoming
    invocation request, create a context from the API matching the route parameters, and dispatch the request to the
    Gateway to be processed by the handler chain.
    """

    def __init__(self, rest_gateway: RestApiGateway = None, store: ApiGatewayStore = None):
        self.rest_gateway = rest_gateway or RestApiGateway()
        # we only access CrossAccount attributes in the handler, so we use a global store in default account and region
        self._global_store = (
            store or apigateway_stores[DEFAULT_AWS_ACCOUNT_ID][AWS_REGION_US_EAST_1]
        )

    def __call__(self, request: Request, **kwargs) -> Response:
        # api_id can be cased because of custom-tag id
        api_id, stage = kwargs.get("api_id", "").lower(), kwargs.get("stage")
        if self.is_rest_api(api_id, stage):
            return self.process_rest_api_invocation(request, api_id, stage)

        else:
            # TODO: return right response
            return Response("Not authorized", status=403)

    def process_rest_api_invocation(self, request: Request, api_id: str, stage: str) -> Response:
        LOG.debug("APIGW v1 Endpoint called")
        response = Response()
        context = RestApiInvocationContext(request)
        self.populate_rest_api_invocation_context(context, api_id, stage)

        self.rest_gateway.process_with_context(context, response)

        return response

    def is_rest_api(self, api_id: str, stage: str):
        return (api_id, stage) in self._global_store.active_deployments

    def populate_rest_api_invocation_context(
        self, context: RestApiInvocationContext, api_id: str, stage: str
    ):
        try:
            deployment_id = self._global_store.active_deployments[(api_id, stage)]
            frozen_deployment = self._global_store.internal_deployments[(api_id, deployment_id)]

        except KeyError:
            # TODO: find proper error when trying to hit an API with no deployment/stage linked
            return

        context.deployment = frozen_deployment
        context.api_id = api_id
        context.stage = stage
        context.deployment_id = deployment_id


class ApiGatewayRouter:
    router: Router[Handler]
    handler: ApiGatewayEndpoint

    def __init__(self, router: Router[Handler] = None, handler: ApiGatewayEndpoint = None):
        self.router = router or ROUTER
        self.handler = handler or ApiGatewayEndpoint()
        self.registered_rules: list[Rule] = []

    def register_routes(self) -> None:
        LOG.debug("Registering API Gateway routes.")
        host_pattern = "<regex('[^-]+'):api_id><regex('(-vpce-[^.]+)?'):vpce_suffix>.execute-api.<regex('.*'):server>"
        rules = [
            self.router.add(
                path="/",
                host=host_pattern,
                endpoint=self.handler,
                defaults={"path": "", "stage": None},
                strict_slashes=True,
            ),
            self.router.add(
                path="/<stage>/",
                host=host_pattern,
                endpoint=self.handler,
                defaults={"path": ""},
                strict_slashes=False,
            ),
            self.router.add(
                path="/<stage>/<path:path>",
                host=host_pattern,
                endpoint=self.handler,
                strict_slashes=True,
            ),
            # add the localstack-specific _user_request_ routes
            self.router.add(
                path="/restapis/<api_id>/<stage>/_user_request_",
                endpoint=self.handler,
                defaults={"path": ""},
            ),
            self.router.add(
                path="/restapis/<api_id>/<stage>/_user_request_/<path:path>",
                endpoint=self.handler,
                strict_slashes=True,
            ),
        ]
        for rule in rules:
            self.registered_rules.append(rule)

    def unregister_routes(self):
        self.router.remove(self.registered_rules)
