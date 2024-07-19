import logging
from functools import cache
from http import HTTPMethod
from typing import Iterable

from werkzeug.exceptions import MethodNotAllowed, NotFound
from werkzeug.routing import Map, MapAdapter, Rule

from localstack.aws.api.apigateway import Resource
from localstack.aws.protocol.routing import (
    GreedyPathConverter,
    path_param_regex,
    post_process_arg_name,
    transform_path_params_to_rule_vars,
)
from localstack.http import Response
from localstack.services.apigateway.models import RestApiDeployment

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext
from ..variables import ContextVariables

LOG = logging.getLogger(__name__)


class ApiGatewayMethodRule(Rule):
    """
    Small extension to Werkzeug's Rule class which reverts unwanted assumptions made by Werkzeug.
    Reverted assumptions:
    - Werkzeug automatically matches HEAD requests to the corresponding GET request (i.e. Werkzeug's rule
      automatically adds the HEAD HTTP method to a rule which should only match GET requests).
    Added behavior:
    - ANY is equivalent to 7 HTTP methods listed. We manually set them to the rule's methods
    """

    def __init__(self, string: str, method: str, **kwargs) -> None:
        super().__init__(string=string, methods=[method], **kwargs)

        if method == "ANY":
            self.methods = {
                HTTPMethod.DELETE,
                HTTPMethod.GET,
                HTTPMethod.HEAD,
                HTTPMethod.OPTIONS,
                HTTPMethod.PATCH,
                HTTPMethod.POST,
                HTTPMethod.PUT,
            }
        else:
            # Make sure Werkzeug's Rule does not add any other methods
            # (f.e. the HEAD method even though the rule should only match GET)
            self.methods = {method.upper()}


class RestAPIResourceRouter:
    """
    A router implementation which abstracts the routing of incoming REST API Context to a specific
    resource of the Deployment.
    """

    _map: Map

    def __init__(self, deployment: RestApiDeployment):
        self._resources = deployment.rest_api.resources
        self._map = get_rule_map_for_resources(self._resources.values())

    def match(self, context: RestApiInvocationContext) -> tuple[Resource, dict[str, str]]:
        """
        Matches the given request to the resource it targets (or raises an exception if no resource matches).

        :param context:
        :return: A tuple with the matched resource and the (already parsed) path params
        :raises: TODO: Gateway exception in case the given request does not match any operation
        """

        request = context.request
        # bind the map to get the actual matcher
        matcher: MapAdapter = self._map.bind(context.request.host)

        # perform the matching
        try:
            # trailing slashes are ignored in APIGW
            path = context.invocation_request["path"].rstrip("/")

            rule, args = matcher.match(path, method=request.method, return_rule=True)
        except (MethodNotAllowed, NotFound) as e:
            # MethodNotAllowed (405) exception is raised if a path is matching, but the method does not.
            # Our router might handle this as a 404, validate with AWS.
            # TODO: raise proper Gateway exception
            raise Exception("Not found") from e

        # post process the arg keys and values
        # - the path param keys need to be "un-sanitized", i.e. sanitized rule variable names need to be reverted
        # - the path param values might still be url-encoded
        args = {post_process_arg_name(k): v for k, v in args.items()}

        # extract the operation model from the rule
        resource_id: str = rule.endpoint
        resource = self._resources[resource_id]

        return resource, args


class InvocationRequestRouter(RestApiGatewayHandler):
    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        self.route_and_enrich(context)

    def route_and_enrich(self, context: RestApiInvocationContext):
        router = self.get_router_for_deployment(context.deployment)

        resource, path_parameters = router.match(context)
        resource: Resource

        context.invocation_request["path_parameters"] = path_parameters
        context.resource = resource

        method = (
            resource["resourceMethods"].get(context.request.method)
            or resource["resourceMethods"]["ANY"]
        )
        context.resource_method = method

        self.update_context_variables_with_resource(context.context_variables, resource)

    @staticmethod
    def update_context_variables_with_resource(
        context_variables: ContextVariables, resource: Resource
    ):
        LOG.debug("Updating $context.resourcePath='%s'", resource["path"])
        context_variables["resourcePath"] = resource["path"]
        LOG.debug("Updating $context.resourceId='%s'", resource["id"])
        context_variables["resourceId"] = resource["id"]

    @staticmethod
    @cache
    def get_router_for_deployment(deployment: RestApiDeployment) -> RestAPIResourceRouter:
        return RestAPIResourceRouter(deployment)


def get_rule_map_for_resources(resources: Iterable[Resource]) -> Map:
    rules = []
    for resource in resources:
        for method, resource_method in resource.get("resourceMethods", {}).items():
            path = resource["path"]
            # translate the requestUri to a Werkzeug rule string
            rule_string = path_param_regex.sub(transform_path_params_to_rule_vars, path)
            rules.append(
                ApiGatewayMethodRule(string=rule_string, method=method, endpoint=resource["id"])
            )  # type: ignore

    return Map(
        rules=rules,
        # don't be strict about trailing slashes when matching
        strict_slashes=False,
        # we can't really use werkzeug's merge-slashes since it uses HTTP redirects to solve it
        merge_slashes=False,
        # get service-specific converters
        converters={"path": GreedyPathConverter},
    )
