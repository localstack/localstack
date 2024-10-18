import logging
from typing import TypedDict, Unpack

from rolo import Request, Router
from rolo.routing.handler import Handler
from werkzeug.routing import Rule

from localstack.constants import APPLICATION_JSON, AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID
from localstack.deprecations import deprecated_endpoint
from localstack.http import Response
from localstack.services.apigateway.models import ApiGatewayStore, apigateway_stores
from localstack.services.edge import ROUTER
from localstack.services.stores import AccountRegionBundle

from .context import RestApiInvocationContext
from .gateway import RestApiGateway

LOG = logging.getLogger(__name__)


class RouteHostPathParameters(TypedDict, total=False):
    """
    Represents the kwargs typing for calling APIGatewayEndpoint.
    Each field might be populated from the route host and path parameters, defined when registering a route.
    """

    api_id: str
    path: str
    port: int | None
    server: str | None
    stage: str | None
    vpce_suffix: str | None


class ApiGatewayEndpoint:
    """
    This class is the endpoint for API Gateway invocations of the `execute-api` route. It will take the incoming
    invocation request, create a context from the API matching the route parameters, and dispatch the request to the
    Gateway to be processed by the handler chain.
    """

    def __init__(self, rest_gateway: RestApiGateway = None, store: AccountRegionBundle = None):
        self.rest_gateway = rest_gateway or RestApiGateway()
        # we only access CrossAccount attributes in the handler, so we use a global store in default account and region
        self._store = store or apigateway_stores

    @property
    def _global_store(self) -> ApiGatewayStore:
        return self._store[DEFAULT_AWS_ACCOUNT_ID][AWS_REGION_US_EAST_1]

    def __call__(self, request: Request, **kwargs: Unpack[RouteHostPathParameters]) -> Response:
        """
        :param request: the incoming Request object
        :param kwargs: can contain all the field of RouteHostPathParameters. Those values are defined on the registered
        routes in ApiGatewayRouter, through host and path parameters in the shape <type:name> or <name> only.
        :return: the Response object to return to the client
        """
        # api_id can be cased because of custom-tag id
        api_id, stage = kwargs.get("api_id", "").lower(), kwargs.get("stage")
        if self.is_rest_api(api_id, stage):
            context, response = self.prepare_rest_api_invocation(request, api_id, stage)
            self.rest_gateway.process_with_context(context, response)
            return response
        else:
            return self.create_not_found_response(api_id)

    def prepare_rest_api_invocation(
        self, request: Request, api_id: str, stage: str
    ) -> tuple[RestApiInvocationContext, Response]:
        LOG.debug("APIGW v1 Endpoint called")
        response = self.create_response(request)
        context = RestApiInvocationContext(request)
        self.populate_rest_api_invocation_context(context, api_id, stage)

        return context, response

    def is_rest_api(self, api_id: str, stage: str):
        return stage in self._global_store.active_deployments.get(api_id, {})

    def populate_rest_api_invocation_context(
        self, context: RestApiInvocationContext, api_id: str, stage: str
    ):
        try:
            deployment_id = self._global_store.active_deployments[api_id][stage]
            frozen_deployment = self._global_store.internal_deployments[api_id][deployment_id]

        except KeyError:
            # TODO: find proper error when trying to hit an API with no deployment/stage linked
            return

        context.deployment = frozen_deployment
        context.api_id = api_id
        context.stage = stage
        context.deployment_id = deployment_id

    @staticmethod
    def create_response(request: Request) -> Response:
        # Creates a default apigw response.
        response = Response(headers={"Content-Type": APPLICATION_JSON})
        if not (connection := request.headers.get("Connection")) or connection != "close":
            # We only set the connection if it isn't close.
            # There appears to be in issue in Localstack, where setting "close" will result in "close, close"
            response.headers.set("Connection", "keep-alive")
        return response

    @staticmethod
    def create_not_found_response(api_id: str) -> Response:
        not_found = Response(status=404)
        not_found.set_json(
            {"message": f"The API id '{api_id}' does not correspond to a deployed API Gateway API"}
        )
        return not_found


class ApiGatewayRouter:
    router: Router[Handler]
    handler: ApiGatewayEndpoint
    EXECUTE_API_INTERNAL_PATH = "/_aws/execute-api"

    def __init__(self, router: Router[Handler] = None, handler: ApiGatewayEndpoint = None):
        self.router = router or ROUTER
        self.handler = handler or ApiGatewayEndpoint()
        self.registered_rules: list[Rule] = []

    def register_routes(self) -> None:
        LOG.debug("Registering API Gateway routes.")
        host_pattern = "<regex('[^-]+'):api_id><regex('(-vpce-[^.]+)?'):vpce_suffix>.execute-api.<regex('.*'):server>"
        deprecated_route_endpoint = deprecated_endpoint(
            endpoint=self.handler,
            previous_path="/restapis/<api_id>/<stage>/_user_request_",
            deprecation_version="3.8.0",
            new_path=f"{self.EXECUTE_API_INTERNAL_PATH}/<api_id>/<stage>",
        )
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
                path="/<stage>/<greedy_path:path>",
                host=host_pattern,
                endpoint=self.handler,
                strict_slashes=True,
            ),
            # add the deprecated localstack-specific _user_request_ routes
            self.router.add(
                path="/restapis/<api_id>/<stage>/_user_request_",
                endpoint=deprecated_route_endpoint,
                defaults={"path": "", "random": "?"},
            ),
            self.router.add(
                path="/restapis/<api_id>/<stage>/_user_request_/<greedy_path:path>",
                endpoint=deprecated_route_endpoint,
                strict_slashes=True,
            ),
            # add the localstack-specific so-called "path-style" routes when DNS resolving is not possible
            self.router.add(
                path=f"{self.EXECUTE_API_INTERNAL_PATH}/<api_id>/",
                endpoint=self.handler,
                defaults={"path": "", "stage": None},
                strict_slashes=True,
            ),
            self.router.add(
                path=f"{self.EXECUTE_API_INTERNAL_PATH}/<api_id>/<stage>/",
                endpoint=self.handler,
                defaults={"path": ""},
                strict_slashes=False,
            ),
            self.router.add(
                path=f"{self.EXECUTE_API_INTERNAL_PATH}/<api_id>/<stage>/<greedy_path:path>",
                endpoint=self.handler,
                strict_slashes=True,
            ),
        ]
        for rule in rules:
            self.registered_rules.append(rule)

    def unregister_routes(self):
        self.router.remove(self.registered_rules)
