import datetime
import logging
from collections import defaultdict
from typing import Optional
from urllib.parse import urlparse

from rolo.request import Request, restore_payload
from werkzeug.datastructures import Headers, MultiDict

from localstack.http import Response
from localstack.services.apigateway.helpers import REQUEST_TIME_DATE_FORMAT
from localstack.utils.strings import short_uid
from localstack.utils.time import timestamp

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationRequest, RestApiInvocationContext
from ..moto_helpers import get_stage_variables
from ..variables import ContextVariables

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
        # then we can create the ContextVariables, used throughout the invocation as payload and to render authorizer
        # payload, mapping templates and such.
        context.context_variables = self.create_context_variables(context)
        # TODO: maybe adjust the logging
        LOG.debug("Initializing $context='%s'", context.context_variables)
        # then populate the stage variables
        context.stage_variables = self.fetch_stage_variables(context)
        LOG.debug("Initializing $stageVariables='%s'", context.stage_variables)

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

    @staticmethod
    def create_context_variables(context: RestApiInvocationContext) -> ContextVariables:
        invocation_request: InvocationRequest = context.invocation_request
        domain_name = invocation_request["raw_headers"].get("Host", "")
        domain_prefix = domain_name.split(".")[0]
        now = datetime.datetime.now()

        # TODO: verify which values needs to explicitly have None set
        context_variables = ContextVariables(
            accountId=context.account_id,
            apiId=context.api_id,
            deploymentId=context.deployment_id,
            domainName=domain_name,
            domainPrefix=domain_prefix,
            extendedRequestId=short_uid(),  # TODO: use snapshot tests to verify format
            httpMethod=invocation_request["http_method"],
            path=invocation_request[
                "path"
            ],  # TODO: check if we need the raw path? with forward slashes
            protocol="HTTP/1.1",
            requestId=short_uid(),  # TODO: use snapshot tests to verify format
            requestTime=timestamp(time=now, format=REQUEST_TIME_DATE_FORMAT),
            requestTimeEpoch=int(now.timestamp() * 1000),
            stage=context.stage,
        )
        return context_variables

    @staticmethod
    def fetch_stage_variables(context: RestApiInvocationContext) -> Optional[dict[str, str]]:
        stage_variables = get_stage_variables(
            account_id=context.account_id,
            region=context.region,
            api_id=context.api_id,
            stage_name=context.stage,
        )
        if not stage_variables:
            # we need to set the stage variables to None in the context if we don't have at least one
            return None

        return stage_variables
