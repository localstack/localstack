import datetime
import json
from urllib.parse import parse_qs

from rolo import Request
from rolo.gateway.chain import HandlerChain
from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import TestInvokeMethodRequest, TestInvokeMethodResponse
from localstack.constants import APPLICATION_JSON
from localstack.http import Response
from localstack.utils.strings import to_bytes, to_str

from ...models import RestApiDeployment
from . import handlers
from .context import InvocationRequest, RestApiInvocationContext
from .handlers.resource_router import RestAPIResourceRouter
from .header_utils import build_multi_value_headers
from .template_mapping import dict_to_string

# Sun Feb 04 18:48:23 UTC 2024
# TODO: we probably need to write and populate those logs as part of the handler chain itself
#  and store it in the InvocationContext. That way, we could also retrieve in when calling TestInvoke
# endpoint_request_headers -> truncated at 998 chars [TRUNCATED]


TEST_INVOKE_TEMPLATE = """Execution log for request {request_id}
{formatted_date} : Starting execution for request: {request_id}
{formatted_date} : HTTP Method: GET, Resource Path: {resource_path}
{formatted_date} : Method request path: {method_request_path_parameters}
{formatted_date} : Method request query string: {method_request_query_string}
{formatted_date} : Method request headers: {method_request_headers}
{formatted_date} : Method request body before transformations: {method_request_body}
{formatted_date} : Endpoint request URI: {endpoint_uri}
{formatted_date} : Endpoint request headers: {endpoint_request_headers}
{formatted_date} : Endpoint request body after transformations: {endpoint_request_body}
{formatted_date} : Sending request to {endpoint_uri}
{formatted_date} : Received response. Status: {endpoint_response_status_code}, Integration latency: {endpoint_response_latency} ms
{formatted_date} : Endpoint response headers: {endpoint_response_headers}
{formatted_date} : Endpoint response body before transformations: {endpoint_response_body}
{formatted_date} : Method response body after transformations: {method_response_body}
{formatted_date} : Method response headers: {method_response_headers}
{formatted_date} : Successfully completed execution
{formatted_date} : Method completed with status: {method_response_status}
"""


def _dump_headers(headers: Headers) -> str:
    if not headers:
        return "{}"
    multi_headers = {key: ",".join(headers.getlist(key)) for key in headers.keys()}
    string_headers = dict_to_string(multi_headers)
    if len(string_headers) > 998:
        return f"{string_headers[:998]} [TRUNCATED]"

    return string_headers


def log_template(invocation_context: RestApiInvocationContext) -> str:
    # formatted_date = date.strftime("%a %b %d %H:%M:%S %Z %Y")
    request = invocation_context.invocation_request
    context_var = invocation_context.context_variables
    integration_req = invocation_context.integration_request
    endpoint_resp = invocation_context.endpoint_response
    method_resp = invocation_context.invocation_response
    # TODO: if endpoint_uri is an ARN, it means it's an AWS_PROXY integration
    #  this should be transformed to the true URL of a lambda invoke call
    endpoint_uri = integration_req.get("uri", "")
    # TODO: funny enough, in AWS for the `endpoint_response_headers` in AWS_PROXY, they log the response headers from
    #  lambda HTTP Invoke call even though we use the headers from the lambda response itself

    return TEST_INVOKE_TEMPLATE.format(
        formatted_date="",
        request_id=context_var["requestId"],
        resource_path="",
        method_request_path_parameters=json.dumps(request["path_parameters"]),
        method_request_query_string="",
        method_request_headers=_dump_headers(request.get("headers")),
        method_request_body=to_str(request.get("body", "")),
        endpoint_uri=endpoint_uri,
        endpoint_request_headers=_dump_headers(integration_req.get("headers")),
        endpoint_request_body=to_str(integration_req.get("body", "")),
        endpoint_response_latency="",
        endpoint_response_status_code=endpoint_resp.get("status"),
        endpoint_response_body=to_str(endpoint_resp.get("body", "")),
        endpoint_response_headers=_dump_headers(endpoint_resp.get("headers")),
        method_response_status=method_resp.get("status"),
        method_response_body=to_str(method_resp.get("body", "")),
        method_response_headers=_dump_headers(method_resp.get("headers")),
    )


def create_test_chain() -> HandlerChain[RestApiInvocationContext]:
    return HandlerChain(
        request_handlers=[
            handlers.method_request_handler,
            handlers.integration_request_handler,
            handlers.integration_handler,
            handlers.integration_response_handler,
            handlers.method_response_handler,
        ],
        exception_handlers=[
            handlers.gateway_exception_handler,
        ],
    )


def create_test_invocation_context(
    test_request: TestInvokeMethodRequest,
    deployment: RestApiDeployment,
) -> RestApiInvocationContext:
    #     restApiId: String
    #     resourceId: String
    #     httpMethod: String
    #     pathWithQueryString: Optional[String]
    #     body: Optional[String]
    #     headers: Optional[MapOfStringToString]
    #     multiValueHeaders: Optional[MapOfStringToList]
    #     clientCertificateId: Optional[String]
    #     stageVariables: Optional[MapOfStringToString]

    # we do not need a true HTTP request for the context, as we are skipping all the parsing steps
    #
    parse_handler = handlers.parse_request
    http_method = test_request["httpMethod"]

    invocation_context = RestApiInvocationContext(
        request=Request(method=http_method),
    )
    path_query = test_request.get("pathWithQueryString", "/").split("?")
    path = path_query[0]
    multi_query_args: dict[str, list[str]] = {}

    if len(path_query) > 1:
        multi_query_args = parse_qs(path_query[1])

    # for the single value parameters, AWS only keeps the last value of the list
    single_query_args = {k: v[-1] for k, v in multi_query_args.items()}

    invocation_request = InvocationRequest(
        http_method=http_method,
        path=path,
        raw_path=path,
        query_string_parameters=single_query_args,
        multi_value_query_string_parameters=multi_query_args,
        headers=Headers(test_request.get("headers")),
        # TODO: handle multiValueHeaders
        body=to_bytes(test_request.get("body") or ""),
    )
    invocation_context.invocation_request = invocation_request

    _, path_parameters = RestAPIResourceRouter(deployment).match(invocation_context)
    invocation_request["path_parameters"] = path_parameters

    invocation_context.deployment = deployment
    invocation_context.api_id = test_request["restApiId"]
    invocation_context.stage = None
    invocation_context.deployment_id = ""
    invocation_context.account_id = deployment.account_id
    invocation_context.region = deployment.region
    invocation_context.stage_variables = test_request.get("stageVariables", {})
    invocation_context.context_variables = parse_handler.create_context_variables(
        invocation_context
    )
    invocation_context.trace_id = parse_handler.populate_trace_id({})

    resource = deployment.rest_api.resources[test_request["resourceId"]]
    resource_method = resource["resourceMethods"][http_method]
    invocation_context.resource = resource
    invocation_context.resource_method = resource_method
    invocation_context.integration = resource_method["methodIntegration"]

    return invocation_context


def run_test_invocation(
    test_request: TestInvokeMethodRequest, deployment: RestApiDeployment
) -> TestInvokeMethodResponse:
    # validate resource exists in deployment
    invocation_context = create_test_invocation_context(test_request, deployment)

    test_chain = create_test_chain()
    test_response = Response(headers={"Content-Type": APPLICATION_JSON})
    start_time = datetime.datetime.now()
    test_chain.handle(context=invocation_context, response=test_response)
    end_time = datetime.datetime.now()

    log = log_template(invocation_context)
    headers = dict(test_response.headers)
    multi_value_headers = build_multi_value_headers(test_response.headers)
    # we manually add the trace-id, as it is normally added by handlers.response_enricher which adds to much data for
    # the TestInvoke
    headers["X-Amzn-Trace-Id"] = invocation_context.trace_id
    multi_value_headers["X-Amzn-Trace-Id"] = [invocation_context.trace_id]

    return TestInvokeMethodResponse(
        log=log,
        status=test_response.status_code,
        body=test_response.get_data(as_text=True),
        headers=headers,
        multiValueHeaders=multi_value_headers,
        latency=int((end_time - start_time).total_seconds()),
    )
