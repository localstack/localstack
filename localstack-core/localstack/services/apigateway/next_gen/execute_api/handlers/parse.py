import datetime
import logging
import re
from collections import defaultdict
from typing import Optional
from urllib.parse import urlparse

from rolo.request import restore_payload
from werkzeug.datastructures import Headers, MultiDict

from localstack.http import Response
from localstack.services.apigateway.helpers import REQUEST_TIME_DATE_FORMAT
from localstack.utils.strings import long_uid, short_uid
from localstack.utils.time import timestamp

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationRequest, RestApiInvocationContext
from ..header_utils import should_drop_header_from_invocation
from ..helpers import generate_trace_id, generate_trace_parent, parse_trace_id
from ..moto_helpers import get_stage_variables
from ..variables import ContextVariables, ContextVarsIdentity

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
        context.invocation_request = self.create_invocation_request(context)
        # then we can create the ContextVariables, used throughout the invocation as payload and to render authorizer
        # payload, mapping templates and such.
        context.context_variables = self.create_context_variables(context)
        # TODO: maybe adjust the logging
        LOG.debug("Initializing $context='%s'", context.context_variables)
        # then populate the stage variables
        context.stage_variables = self.fetch_stage_variables(context)
        LOG.debug("Initializing $stageVariables='%s'", context.stage_variables)

        context.trace_id = self.populate_trace_id(context.request.headers)

    def create_invocation_request(self, context: RestApiInvocationContext) -> InvocationRequest:
        request = context.request
        params, multi_value_params = self._get_single_and_multi_values_from_multidict(request.args)
        headers = self._get_invocation_headers(request.headers)
        invocation_request = InvocationRequest(
            http_method=request.method,
            query_string_parameters=params,
            multi_value_query_string_parameters=multi_value_params,
            headers=headers,
            body=restore_payload(request),
        )
        self._enrich_with_raw_path(context, invocation_request)

        return invocation_request

    @staticmethod
    def _enrich_with_raw_path(
        context: RestApiInvocationContext, invocation_request: InvocationRequest
    ):
        # Base path is not URL-decoded, so we need to get the `RAW_URI` from the request
        request = context.request
        raw_uri = request.environ.get("RAW_URI") or request.path

        # if the request comes from the LocalStack only `_user_request_` route, we need to remove this prefix from the
        # path, in order to properly route the request
        if "_user_request_" in raw_uri:
            # in this format, the stage is before `_user_request_`, so we don't need to remove it
            raw_uri = raw_uri.partition("_user_request_")[2]
        else:
            if raw_uri.startswith("/_aws/execute-api"):
                # the API can be cased in the path, so we need to ignore it to remove it
                raw_uri = re.sub(
                    f"^/_aws/execute-api/{context.api_id}",
                    "",
                    raw_uri,
                    flags=re.IGNORECASE,
                )

            # remove the stage from the path, only replace the first occurrence
            raw_uri = raw_uri.replace(f"/{context.stage}", "", 1)

        if raw_uri.startswith("//"):
            # TODO: AWS validate this assumption
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
    def _get_invocation_headers(headers: Headers) -> Headers:
        invocation_headers = Headers()
        for key, value in headers:
            if should_drop_header_from_invocation(key):
                LOG.debug("Dropping header from invocation request: '%s'", key)
                continue
            invocation_headers.add(key, value)
        return invocation_headers

    @staticmethod
    def create_context_variables(context: RestApiInvocationContext) -> ContextVariables:
        invocation_request: InvocationRequest = context.invocation_request
        domain_name = invocation_request["headers"].get("Host", "")
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
            identity=ContextVarsIdentity(
                accountId=None,
                accessKey=None,
                caller=None,
                cognitoAuthenticationProvider=None,
                cognitoAuthenticationType=None,
                cognitoIdentityId=None,
                cognitoIdentityPoolId=None,
                principalOrgId=None,
                sourceIp="127.0.0.1",  # TODO: get the sourceIp from the Request
                user=None,
                userAgent=invocation_request["headers"].get("User-Agent"),
                userArn=None,
            ),
            path=f"/{context.stage}{invocation_request['raw_path']}",
            protocol="HTTP/1.1",
            requestId=long_uid(),
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

    @staticmethod
    def populate_trace_id(headers: Headers) -> str:
        incoming_trace = parse_trace_id(headers.get("x-amzn-trace-id", ""))
        # parse_trace_id always return capitalized keys

        trace = incoming_trace.get("Root", generate_trace_id())
        incoming_parent = incoming_trace.get("Parent")
        parent = incoming_parent or generate_trace_parent()
        sampled = incoming_trace.get("Sampled", "1" if incoming_parent else "0")
        # TODO: lineage? not sure what it related to
        return f"Root={trace};Parent={parent};Sampled={sampled}"
