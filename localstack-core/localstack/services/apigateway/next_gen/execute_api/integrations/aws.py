import base64
import json
import logging
from http import HTTPMethod
from typing import Optional, TypedDict

from botocore.exceptions import ClientError
from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration
from localstack.http import Response
from localstack.services.apigateway.integration import get_service_factory
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.collections import merge_dicts
from localstack.utils.strings import to_bytes, to_str

from ..context import InvocationRequest, RestApiInvocationContext
from ..helpers import (
    get_lambda_function_arn_from_invocation_uri,
    get_source_arn,
    validate_sub_dict_of_typed_dict,
)
from ..variables import ContextVariables
from .core import RestApiIntegration

LOG = logging.getLogger(__name__)


class LambdaProxyResponse(TypedDict, total=False):
    body: Optional[str]
    statusCode: Optional[int]
    headers: Optional[dict[str, str]]
    isBase64Encoded: Optional[bool]
    multiValueHeaders: Optional[dict[str, list[str]]]


class LambdaInputEvent(TypedDict, total=False):
    body: str
    isBase64Encoded: bool
    httpMethod: str | HTTPMethod
    resource: str
    path: str
    headers: dict[str, str]
    multiValueHeaders: dict[str, list[str]]
    queryStringParameters: dict[str, str]
    multiValueQueryStringParameters: dict[str, list[str]]
    requestContext: ContextVariables
    pathParameters: dict[str, str]
    stageVariables: dict[str, str]


class RestApiAwsIntegration(RestApiIntegration):
    """
    This is a REST API integration responsible to directly interact with AWS services. It uses the `uri` to
    map the incoming request to the concerned AWS service, and can have 2 types.
    - `path`: the request is targeting the direct URI of the AWS service, like you would with an HTTP client
     example: For S3 GetObject call: arn:aws:apigateway:us-west-2:s3:path/{bucket}/{key}
    - `action`: this is a simpler way, where you can pass the request parameters like you would do with an SDK, and you
     can specify the service action (for ex. here S3 `GetObject`). It seems the request parameters can be pass as query
     string parameters, JSON body and maybe more. TODO: verify, 2 documentation pages indicates divergent information.
    (one indicates parameters through QS, one through request body)
     example: arn:aws:apigateway:us-west-2:s3:action/GetObject&Bucket={bucket}&Key={key}

    https://docs.aws.amazon.com/apigateway/latest/developerguide/integration-request-basic-setup.html


    TODO: it seems we can global AWS integration type, we should not need to subclass for each service
     we just need to separate usage between the `path` URI type and the `action` URI type.
     - `path`, we can simply pass along the full rendered request along with specific `mocked` AWS headers
     that are dependant of the service (retrieving for the ARN in the uri)
     - `action`, we might need either a full Boto call or use the Boto request serializer, as it seems the request
     parameters are expected as parameters
    """

    name = "AWS"


class RestApiAwsProxyIntegration(RestApiIntegration):
    """
    This is a custom, simplified REST API integration focused only on the Lambda service, with minimal modification from
    API Gateway. It passes the incoming request almost as is, in a custom created event payload, to the configured
    Lambda function.

    https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    """

    name = "AWS_PROXY"

    def invoke(self, context: RestApiInvocationContext) -> Response:
        invocation_req: InvocationRequest = context.invocation_request
        integration: Integration = context.resource_method["methodIntegration"]
        # if the integration method is defined and is not ANY, we can use it for the integration
        if not (method := integration["httpMethod"]) or method == "ANY":
            # otherwise, fallback to the request's method
            method = invocation_req["http_method"]

        if method != HTTPMethod.POST:
            raise Exception
            # raise ApiGatewayIntegrationError("Internal server error", status_code=500)

        input_event = self.create_lambda_input_event(context)
        function_arn = get_lambda_function_arn_from_invocation_uri(integration["uri"])

        try:
            lambda_payload = self.call_lambda(
                function_arn=function_arn,
                event=to_bytes(json.dumps(input_event)),
                context=context,
            )
        except ClientError:
            # TODO
            raise
        except Exception:
            # TODO
            raise

        lambda_response = self.parse_lambda_response(lambda_payload)

        headers = merge_dicts(
            {"Content-Type": "application/json"},
            lambda_response.get("headers") or {},
            lambda_response.get("multiValueHeaders") or {},
        )

        response = Response(
            headers=Headers(headers),
        )
        response.data = lambda_response.get("body") or ""
        response.status_code = lambda_response.get("statusCode") or 200

        return response

    @staticmethod
    def call_lambda(
        function_arn: str,
        event: bytes,
        context: RestApiInvocationContext,
    ) -> bytes:
        # TODO: properly get the value out
        integration: Integration = context.resource_method["methodIntegration"]
        raw_headers = context.invocation_request["raw_headers"]
        is_invocation_asynchronous = raw_headers.get("X-Amz-Invocation-Type") == "'Event'"

        lambda_client = get_service_factory(
            region_name=extract_region_from_arn(function_arn),
            role_arn=integration.get("credentials"),
        ).lambda_
        inv_result = lambda_client.request_metadata(
            service_principal=ServicePrincipal.apigateway,
            source_arn=get_source_arn(context),
        ).invoke(
            FunctionName=function_arn,
            Payload=event,
            InvocationType="Event" if is_invocation_asynchronous else "RequestResponse",
        )
        if payload := inv_result.get("Payload"):
            return payload.read()
        return b""

    @staticmethod
    def parse_lambda_response(payload: bytes) -> LambdaProxyResponse:
        try:
            lambda_response = json.loads(payload)

        except json.JSONDecodeError:
            raise

        # none of the lambda response fields are mandatory, but you cannot return any other fields
        if not validate_sub_dict_of_typed_dict(LambdaProxyResponse, lambda_response):
            LOG.warning(
                'Lambda output should follow the next JSON format: { "isBase64Encoded": true|false, "statusCode": httpStatusCode, "headers": { "headerName": "headerValue", ... },"body": "..."} but was: %s',
                payload,
            )
            # status_code = 502
            # {"message": "Internal server error"}
            raise Exception

        # TODO: validate type of each values?

        return lambda_response

    def create_lambda_input_event(self, context: RestApiInvocationContext) -> LambdaInputEvent:
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
        invocation_req: InvocationRequest = context.invocation_request

        # TODO: binary support of APIGW
        body, is_b64_encoded = self._format_body(invocation_req["body"])

        input_event = LambdaInputEvent(
            headers=self._format_headers(invocation_req["headers"]),
            multiValueHeaders=self._format_headers(invocation_req["multi_value_headers"]),
            body=body or None,
            isBase64Encoded=is_b64_encoded,
            requestContext=context.context_variables,
            stageVariables=context.stage_variables,
            queryStringParameters=invocation_req["query_string_parameters"] or None,
            multiValueQueryStringParameters=invocation_req["multi_value_query_string_parameters"]
            or None,
            pathParameters=invocation_req["path_parameters"],
            httpMethod=invocation_req["http_method"],
            path=invocation_req["path"],
            resource=context.resource["path"],
        )

        return input_event

    @staticmethod
    def _format_headers(headers: dict[str, str | list[str]]) -> dict[str, str | list[str]]:
        # Some headers get capitalized like in CloudFront, see
        # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/add-origin-custom-headers.html#add-origin-custom-headers-forward-authorization
        # It seems AWS_PROXY lambda integrations are behind CloudFront, as seen by the returned headers in AWS
        to_capitalize: list[str] = ["authorization"]  # some headers get capitalized
        to_filter: list[str] = ["content-length", "connection"]
        headers = {
            k.capitalize() if k.lower() in to_capitalize else k: v
            for k, v in headers.items()
            if k.lower() not in to_filter
        }

        return headers

    @staticmethod
    def _format_body(body: bytes) -> tuple[str, bool]:
        try:
            return body.decode("utf-8"), False
        except UnicodeDecodeError:
            return to_str(base64.b64encode(body)), True
