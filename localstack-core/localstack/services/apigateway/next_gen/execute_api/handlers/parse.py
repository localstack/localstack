import logging
import re
from collections import defaultdict
from typing import Optional
from urllib.parse import urlparse

from rolo.request import Request, restore_payload
from werkzeug.datastructures import Headers, MultiDict

from localstack.aws.api.apigateway import Resource
from localstack.http import Response
from localstack.utils.json import json_safe

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationRequest, RestApiInvocationContext
from ..helpers import get_resources_from_deployment

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
        raw_uri = request.environ.get("RAW_URI")

        # if the request comes from the LocalStack only `_user_request_` route, we need to remove this prefix from the
        # path, in order to properly route the request
        if "_user_request_" in raw_uri:
            raw_uri = raw_uri.partition("_user_request_")[2]

        if raw_uri.startswith("//"):
            # if the RAW_URI starts with double slashes, `urlparse` will fail to decode it as path only
            # it also means that we already only have the path, so we just need to remove the query string
            raw_uri = raw_uri.split("?")[0]

        raw_path = urlparse(raw_uri or request.path).path

        invocation_request["raw_path"] = raw_path
        invocation_request["raw_uri_path"] = raw_uri

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

        return single_values, multi_values

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


class InvocationRequestRouter(RestApiGatewayHandler):
    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        # TODO: replace all the logic in this class by a `url_map` similar to the ServiceRequestRouter
        # we could create and cache the url_map when creating the deployment
        self.route_and_enrich(context)

    def route_and_enrich(self, context: RestApiInvocationContext):
        rest_apis_resource_map = self.get_rest_api_paths(context)
        path_with_no_trailing_slash = self.context.invocation_request["raw_path"].rstrip("/")
        request_method = context.request.method

        matched_path, resource = self.get_resource_for_path(
            path=path_with_no_trailing_slash,
            method=request_method,
            path_map=rest_apis_resource_map,
        )
        if not matched_path:
            # TODO: use Gateway Exceptions
            raise Exception("Not found")

        path_parameters = self.extract_path_params(
            request_path=path_with_no_trailing_slash,
            resource_path=matched_path,
        )
        context.invocation_request["path_parameters"] = path_parameters
        context.resource = resource

        method = (
            resource["resourceMethods"].get(request_method) or resource["resourceMethods"]["ANY"]
        )
        context.resource_method = method

    @staticmethod
    def get_rest_api_paths(context: RestApiInvocationContext) -> dict[str, Resource]:
        resources = get_resources_from_deployment(context.deployment)

        return {resource["path"]: resource for resource in resources}

    def get_resource_for_path(
        self, path: str, method: str, path_map: dict[str, Resource]
    ) -> tuple[
        Optional[str],
        Optional[Resource],
    ]:
        matches = []
        # creates a regex from the input path if there are parameters, e.g /foo/{bar}/baz -> /foo/[
        # ^\]+/baz, otherwise is a direct match.
        for resource_path, resource in path_map.items():
            api_path_regex = re.sub(r"{[^+]+\+}", r"[^\?#]+", resource_path)
            api_path_regex = re.sub(r"{[^}]+}", r"[^/]+", api_path_regex)
            if re.match(r"^%s$" % api_path_regex, path):
                matches.append((resource_path, resource))

        # if there are no matches, it's not worth to proceed, bail here!
        if not matches:
            LOG.debug(f"No match found for path: '{path}' and method: '{method}'")
            return None, None

        if len(matches) == 1:
            LOG.debug(f"Match found for path: '{path}' and method: '{method}'")
            return matches[0]

        # so we have more than one match
        # /{proxy+} and /api/{proxy+} for inputs like /api/foo/bar
        # /foo/{param1}/baz and /foo/{param1}/{param2} for inputs like /for/bar/baz
        proxy_matches = []
        param_matches = []
        for match in matches:
            match_methods = list(match[1].get("resourceMethods", {}).keys())
            # only look for path matches if the request method is in the resource
            if method.upper() in match_methods or "ANY" in match_methods:
                # check if we have an exact match (exact matches take precedence) if the method is the same
                if match[0] == path:
                    return match

                elif self.path_matches_pattern(path, match[0]):
                    # parameters can fit in
                    param_matches.append(match)
                    continue

                proxy_matches.append(match)

        if param_matches:
            # count the amount of parameters, return the one with the least which is the most precise
            sorted_matches = sorted(param_matches, key=lambda x: x[0].count("{"))
            LOG.debug(f"Match found for path: '{path}' and method: '{method}'")
            return sorted_matches[0]

        if proxy_matches:
            # at this stage, we still have more than one match, but we have an eager example like
            # /{proxy+} or /api/{proxy+}, so we pick the best match by sorting by length, only if they have a method
            # that could match
            sorted_matches = sorted(proxy_matches, key=lambda x: len(x[0]), reverse=True)
            LOG.debug(f"Match found for path: '{path}' and method: '{method}'")
            return sorted_matches[0]

        # if there are no matches with a method that would match, return
        LOG.debug(f"No match found for method: '{method}' for matched path: {path}")
        return None, None

    @staticmethod
    def tokenize_path(path):
        return path.lstrip("/").split("/")

    @staticmethod
    def path_matches_pattern(path: str, api_path: str) -> bool:
        api_paths = api_path.split("/")
        paths = path.split("/")
        reg_check = re.compile(r"{(.*)}")
        if len(api_paths) != len(paths):
            return False
        results = [
            part == paths[indx]
            for indx, part in enumerate(api_paths)
            if reg_check.match(part) is None and part
        ]

        return len(results) > 0 and all(results)

    def extract_path_params(self, request_path: str, resource_path: str) -> dict[str, str]:
        tokenized_extracted_path = self.tokenize_path(resource_path)
        # Looks for '{' in the tokenized extracted path
        path_params_list = [(i, v) for i, v in enumerate(tokenized_extracted_path) if "{" in v]
        tokenized_path = self.tokenize_path(request_path)
        path_params = {}
        for param in path_params_list:
            path_param_name = param[1][1:-1]
            path_param_position = param[0]
            # if this is a greedy path (aka proxy)
            if path_param_name.endswith("+"):
                path_params[path_param_name.rstrip("+")] = "/".join(
                    tokenized_path[path_param_position:]
                )
            else:
                path_params[path_param_name] = tokenized_path[path_param_position]

        # TODO: maybe move `json_safe` call at the end
        path_params = json_safe(path_params)
        return path_params
