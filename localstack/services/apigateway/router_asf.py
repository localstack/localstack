import logging
from typing import Any, Dict

from werkzeug.exceptions import NotFound

from localstack.constants import HEADER_LOCALSTACK_EDGE_URL
from localstack.http import Request, Response, Router
from localstack.http.dispatcher import Handler
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import get_api_account_id_and_region
from localstack.services.apigateway.invocations import invoke_rest_api_from_request

LOG = logging.getLogger(__name__)


def to_invocation_context(
    request: Request, url_params: Dict[str, Any] = None
) -> ApiInvocationContext:
    """
    Converts an HTTP Request object into an ApiInvocationContext.

    :param request: the original request
    :param url_params: the parameters extracted from the URL matching rules
    :return: the ApiInvocationContext
    """
    if url_params is None:
        url_params = {}

    # adjust the X-Forwarded-For header
    x_forwarded_for = request.headers.getlist("X-Forwarded-For")
    x_forwarded_for.append(request.remote_addr)
    x_forwarded_for.append(request.host)
    request.headers["X-Forwarded-For"] = ", ".join(x_forwarded_for)

    # set the x-localstack-edge header, it is used to parse the domain
    request.headers[HEADER_LOCALSTACK_EDGE_URL] = request.host_url.strip("/")

    return ApiInvocationContext(request=request, url_params=url_params)


class ApigatewayRouter:
    """
    Simple implementation around a Router to manage dynamic restapi routes (routes added by a user through the
    apigateway API).
    """

    router: Router[Handler]

    def __init__(self, router: Router[Handler]):
        self.router = router
        self.registered = False

    def register_routes(self) -> None:
        """Registers parameterized routes for API Gateway user invocations."""
        if self.registered:
            LOG.debug("Skipped API gateway route registration (routes already registered).")
            return
        self.registered = True
        LOG.debug("Registering parameterized API gateway routes.")
        self.router.add(
            "/",
            host="<api_id>.execute-api.<regex('.*'):server>",
            endpoint=self.invoke_rest_api,
            defaults={"path": "", "stage": None},
        )
        # For API Gateway v2 this can be <stage> and root "/" or default stage "$default" and
        # root "/my/path2". We do further check in the handler.
        # http://0v1p6q6.execute-api.localhost.localstack.cloud:4566/<stage>/my/path2
        # http://0v1p6q6.execute-api.localhost.localstack.cloud:4566/my/path2
        self.router.add(
            "/<stage>/",
            host="<api_id>.execute-api.<regex('.*'):server>",
            endpoint=self.invoke_rest_api,
            defaults={"path": ""},
        )
        # e.g, http://<apiId>.execute-api.localhost.localstack.cloud:4566/<stage>/<path>
        self.router.add(
            "/<stage>/<path:path>",
            host="<api_id>.execute-api.<regex('.*'):server>",
            endpoint=self.invoke_rest_api,
        )

        # add the localstack-specific _user_request_ routes
        self.router.add(
            "/restapis/<api_id>/<stage>/_user_request_",
            endpoint=self.invoke_rest_api,
            defaults={"path": ""},
        )
        self.router.add(
            "/restapis/<api_id>/<stage>/_user_request_/<path:path>",
            endpoint=self.invoke_rest_api,
        )

    def invoke_rest_api(self, request: Request, **url_params: Dict[str, Any]) -> Response:
        if not get_api_account_id_and_region(url_params["api_id"])[1]:
            return Response(status=404)
        invocation_context = to_invocation_context(request, url_params)
        account_id, region_name = get_api_account_id_and_region(url_params.get("api_id"))
        invocation_context.region_name = region_name
        invocation_context.account_id = account_id

        result = invoke_rest_api_from_request(invocation_context)
        if result is not None:
            return result
        raise NotFound()
