import logging
from typing import Any, Dict

from requests.models import Response as RequestsResponse
from requests.structures import CaseInsensitiveDict
from werkzeug.datastructures import Headers
from werkzeug.exceptions import NotFound

from localstack.http import Request, Response, Router
from localstack.http.dispatcher import Handler
from localstack.http.request import restore_payload
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import API_REGIONS
from localstack.services.apigateway.invocations import invoke_rest_api_from_request
from localstack.utils.aws.aws_responses import LambdaResponse

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

    method = request.method
    path = request.full_path if request.query_string else request.path
    data = restore_payload(request)
    headers = Headers(request.headers)

    # adjust the X-Forwarded-For header
    x_forwarded_for = headers.getlist("X-Forwarded-For")
    x_forwarded_for.append(request.remote_addr)
    x_forwarded_for.append(request.host)
    headers["X-Forwarded-For"] = ", ".join(x_forwarded_for)

    # this is for compatibility with the lower layers of apigw and lambda that make assumptions about header casing
    headers = CaseInsensitiveDict(
        {k.title(): ", ".join(headers.getlist(k)) for k in headers.keys()}
    )

    # FIXME: Use the already parsed url params instead of parsing them into the ApiInvocationContext part-by-part.
    #   We already would have all params at hand to avoid _all_ the parsing, but the parsing
    #   has side-effects (f.e. setting the region in a thread local)!
    #   It would be best to use a small (immutable) context for the already parsed params and the Request object
    #   and use it everywhere.
    return ApiInvocationContext(method, path, data, headers, stage=url_params.get("stage"))


def convert_response(result: RequestsResponse) -> Response:
    """
    Utility function to convert a response for the requests library to our internal (Werkzeug based) Response object.
    """
    if result is None:
        return Response()
    if isinstance(result, LambdaResponse):
        headers = Headers(dict(result.headers))
        for k, values in result.multi_value_headers.items():
            for value in values:
                headers.add(k, value)
    else:
        headers = dict(result.headers)
    return Response(
        response=result.content,
        status=result.status_code,
        headers=headers,
    )


class ApigatewayRouter:
    """
    Simple implementation around a Router to manage dynamic restapi routes (routes added by a user through the
    apigateway API).
    """

    router: Router[Handler]

    def __init__(self, router: Router[Handler]):
        self.router = router

    def register_routes(self) -> None:
        """Registers parameterized routes for API Gateway user invocations."""
        self.router.add(
            "/",
            host="<api_id>.execute-api.<regex('.*'):server>",
            endpoint=self.invoke_rest_api,
            defaults={"path": "", "stage": None},
        )
        self.router.add(
            "/<stage>/",
            host="<api_id>.execute-api.<regex('.*'):server>",
            endpoint=self.invoke_rest_api,
            defaults={"path": ""},
        )
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
        if not url_params["api_id"] in API_REGIONS:
            return Response(status=404)
        invocation_context = to_invocation_context(request, url_params)
        result = invoke_rest_api_from_request(invocation_context)
        if result is not None:
            return convert_response(result)
        raise NotFound()
