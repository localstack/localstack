import logging
from collections import defaultdict
from urllib.parse import urlparse

from rolo.request import Request, restore_payload
from werkzeug.datastructures import Headers, MultiDict

from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationRequest, RestApiInvocationContext

LOG = logging.getLogger(__name__)


class InvocationRequestParser(RestApiGatewayHandler):
    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        context.account_id = context.deployment.account_id
        context.region = context.deployment.region
        self.parse_and_enrich(context)

    def parse_and_enrich(self, context: RestApiInvocationContext):
        # first, create the InvocationRequest with the incoming request
        context.invocation_request = self.create_invocation_request(context.request)

    def create_invocation_request(self, request: Request) -> InvocationRequest:
        params, multi_value_params = self._get_single_and_multi_values_from_multidict(request.args)
        headers, multi_value_headers = self._get_single_and_multi_values_from_headers(
            request.headers
        )
        invocation_request = InvocationRequest(
            http_method=request.method,
            query_string_parameters=params,
            multi_value_query_string_parameters=multi_value_params,
            raw_headers=request.headers,
            headers=headers,
            multi_value_headers=multi_value_headers,
            body=restore_payload(request),
        )

        self._enrich_with_raw_path(request, invocation_request)

        return invocation_request

    @staticmethod
    def _enrich_with_raw_path(request: Request, invocation_request: InvocationRequest):
        # Base path is not URL-decoded, so we need to get the `RAW_URI` from the request
        raw_uri = request.environ.get("RAW_URI") or request.path

        # if the request comes from the LocalStack only `_user_request_` route, we need to remove this prefix from the
        # path, in order to properly route the request
        if "_user_request_" in raw_uri:
            raw_uri = raw_uri.partition("_user_request_")[2]

        if raw_uri.startswith("//"):
            # if the RAW_URI starts with double slashes, `urlparse` will fail to decode it as path only
            # it also means that we already only have the path, so we just need to remove the query string
            raw_uri = raw_uri.split("?")[0]
            raw_path = "/" + raw_uri.lstrip("/")

        else:
            # we need to make sure we have a path here, sometimes RAW_URI can be a full URI (when proxied)
            raw_path = raw_uri = urlparse(raw_uri).path

        invocation_request["path"] = raw_path
        invocation_request["raw_path"] = raw_uri

    @staticmethod
    def _get_single_and_multi_values_from_multidict(
        multi_dict: MultiDict,
    ) -> tuple[dict[str, str], dict[str, list[str]]]:
        single_values = {}
        multi_values = defaultdict(list)

        for key, value in multi_dict.items(multi=True):
            multi_values[key].append(value)
            # for the single value parameters, AWS only keeps the last value of the list
            single_values[key] = value

        return single_values, dict(multi_values)

    @staticmethod
    def _get_single_and_multi_values_from_headers(
        headers: Headers,
    ) -> tuple[dict[str, str], dict[str, list[str]]]:
        single_values = {}
        multi_values = {}

        for key in dict(headers).keys():
            # TODO: AWS verify multi value headers to see which one AWS keeps (first or last)
            if key not in single_values:
                single_values[key] = headers[key]

            multi_values[key] = headers.getlist(key)

        return single_values, multi_values
