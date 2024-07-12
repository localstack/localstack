import base64
import json
import logging
from functools import lru_cache
from http import HTTPMethod
from typing import Literal, Optional, TypedDict
from urllib.parse import urlparse

import requests
from botocore.exceptions import ClientError
from werkzeug.datastructures import Headers

from localstack import config
from localstack.aws.api.apigateway import Integration
from localstack.aws.connect import (
    INTERNAL_REQUEST_PARAMS_HEADER,
    InternalRequestParameters,
    connect_to,
    dump_dto,
)
from localstack.aws.protocol.service_router import get_service_catalog
from localstack.http import Response
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.collections import merge_dicts
from localstack.utils.strings import to_bytes, to_str

from ..context import IntegrationRequest, InvocationRequest, RestApiInvocationContext
from ..gateway_response import IntegrationFailureError, InternalServerError
from ..helpers import (
    get_lambda_function_arn_from_invocation_uri,
    get_source_arn,
    validate_sub_dict_of_typed_dict,
)
from ..variables import ContextVariables
from .core import RestApiIntegration

LOG = logging.getLogger(__name__)

NO_BODY_METHODS = {
    HTTPMethod.OPTIONS,
    HTTPMethod.GET,
    HTTPMethod.HEAD,
}


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


class ParsedAwsIntegrationUri(TypedDict):
    service_name: str
    region_name: str
    action_type: Literal["path", "action"]
    path: str


@lru_cache(maxsize=64)
def get_service_factory(region_name: str, role_arn: str):
    if role_arn:
        return connect_to.with_assumed_role(
            role_arn=role_arn,
            region_name=region_name,
            service_principal=ServicePrincipal.apigateway,
            session_name="BackplaneAssumeRoleSession",
        )
    else:
        return connect_to(region_name=region_name)


@lru_cache(maxsize=64)
def get_internal_mocked_headers(
    service_name: str,
    region_name: str,
    source_arn: str,
    role_arn: str | None,
) -> dict[str, str]:
    if role_arn:
        access_key_id = (
            connect_to()
            .sts.request_metadata(service_principal=ServicePrincipal.apigateway)
            .assume_role(RoleArn=role_arn, RoleSessionName="BackplaneAssumeRoleSession")[
                "Credentials"
            ]["AccessKeyId"]
        )
    else:
        access_key_id = None

    dto = InternalRequestParameters(
        service_principal=ServicePrincipal.apigateway, source_arn=source_arn
    )
    # TODO: maybe use the localstack.utils.aws.client.SigningHttpClient instead of directly mocking the Authorization
    #  header (but will need to select the right signer depending on the service?)
    headers = {
        "Authorization": (
            "AWS4-HMAC-SHA256 "
            + f"Credential={access_key_id}/20160623/{region_name}/{service_name}/aws4_request, "
            + "SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=1234"
        ),
        INTERNAL_REQUEST_PARAMS_HEADER: dump_dto(dto),
    }

    return headers


@lru_cache(maxsize=64)
def get_target_prefix_for_service(service_name: str) -> str | None:
    return get_service_catalog().get(service_name).metadata.get("targetPrefix")


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

    # TODO: it seems in AWS, you don't need to manually set the `X-Amz-Target` header when using the `action` type.
    #  for now, we know `events` needs the user to manually add the header, but Kinesis and DynamoDB don't.
    #  Maybe reverse the list to exclude instead of include.
    SERVICES_AUTO_TARGET = ["dynamodb", "kinesis", "ssm"]

    # TODO: some services still target the Query protocol (validated with AWS), even though SSM for example is JSON for
    #  as long as the Boto SDK exists. We will need to emulate the Query protocol and translate it to JSON
    SERVICES_LEGACY_QUERY_PROTOCOL = ["ssm"]

    def __init__(self):
        self._base_domain = config.internal_service_url()
        self._base_host = ""

    def invoke(self, context: RestApiInvocationContext) -> Response:
        integration: Integration = context.resource_method["methodIntegration"]
        integration_req: IntegrationRequest = context.integration_request
        method = integration_req["http_method"]
        parsed_uri = self.parse_aws_integration_uri(integration["uri"])
        service_name = parsed_uri["service_name"]
        integration_region = parsed_uri["region_name"]

        headers = integration_req["headers"] | get_internal_mocked_headers(
            service_name=service_name,
            region_name=integration_region,
            source_arn=get_source_arn(context),
            role_arn=integration.get("credentials"),
        )
        query_params = integration_req["query_string_parameters"].copy()
        data = integration_req["body"]

        if parsed_uri["action_type"] == "path":
            # the Path action type allows you to override the path the request is sent to, like you would send to AWS
            path = f"/{parsed_uri['path']}"
        else:
            # Action passes the `Action` query string parameter
            path = ""
            action = parsed_uri["path"]

            if target := self.get_action_service_target(service_name, action):
                headers["X-Amz-Target"] = target

            if service_name in self.SERVICES_LEGACY_QUERY_PROTOCOL:
                # this has been tested in AWS: for `ssm`, it fully overrides the body because SSM uses the Query
                # protocol, so we simulate it that way
                data = self.get_payload_from_query_string(query_params)

            query_params["Action"] = action

        url = f"{self._base_domain}{path}"
        headers["Host"] = self.get_internal_host_for_service(
            service_name=service_name, region_name=integration_region
        )

        request_parameters = {
            "method": method,
            "url": url,
            "params": integration_req["query_string_parameters"],
            "headers": headers,
        }

        if method not in NO_BODY_METHODS:
            request_parameters["data"] = data

        request_response = requests.request(**request_parameters)
        response_content = request_response.content

        if (
            parsed_uri["action_type"] == "action"
            and service_name in self.SERVICES_LEGACY_QUERY_PROTOCOL
        ):
            response_content = self.format_response_content_legacy(
                payload=response_content,
                service_name=service_name,
                action=parsed_uri["path"],
                request_id=context.context_variables["requestId"],
            )

        return Response(
            response=response_content,
            status=request_response.status_code,
            headers=Headers(dict(request_response.headers)),
        )

    @staticmethod
    def parse_aws_integration_uri(uri: str) -> ParsedAwsIntegrationUri:
        """
        The URI can be of 2 shapes: Path or Action.
        Path  : arn:aws:apigateway:us-west-2:s3:path/{bucket}/{key}
        Action: arn:aws:apigateway:us-east-1:kinesis:action/PutRecord
        :param uri: the URI of the AWS integration
        :return: a ParsedAwsIntegrationUri containing the service name, the region and the type of action
        """
        arn, _, path = uri.partition("/")
        split_arn = arn.split(":", maxsplit=5)
        *_, region_name, service_name, action_type = split_arn
        return ParsedAwsIntegrationUri(
            region_name=region_name,
            service_name=service_name,
            action_type=action_type,
            path=path,
        )

    def get_action_service_target(self, service_name: str, action: str) -> str | None:
        if service_name not in self.SERVICES_AUTO_TARGET:
            return None

        target_prefix = get_target_prefix_for_service(service_name)
        if not target_prefix:
            return None

        return f"{target_prefix}.{action}"

    def get_internal_host_for_service(self, service_name: str, region_name: str):
        url = self._base_domain
        if service_name == "sqs":
            # This follow the new SQS_ENDPOINT_STRATEGY=standard
            url = config.external_service_url(subdomains=f"sqs.{region_name}")

        return urlparse(url).netloc

    @staticmethod
    def get_payload_from_query_string(query_string_parameters: dict) -> str:
        return json.dumps(query_string_parameters)

    @staticmethod
    def format_response_content_legacy(
        service_name: str, action: str, payload: bytes, request_id: str
    ) -> bytes:
        # TODO: not sure how much we need to support this, this supports SSM for now, once we write more tests for
        #  `action` type, see if we can generalize more
        data = json.loads(payload)
        try:
            # we try to populate the missing fields from the OperationModel of the operation
            operation_model = get_service_catalog().get(service_name).operation_model(action)
            for key in operation_model.output_shape.members:
                if key not in data:
                    data[key] = None

        except Exception:
            # the operation above is only for parity reason, skips if it fail
            pass

        wrapped = {
            f"{action}Response": {
                f"{action}Result": data,
                "ResponseMetadata": {
                    "RequestId": request_id,
                },
            }
        }
        return to_bytes(json.dumps(wrapped))


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
            raise IntegrationFailureError("Internal server error")

        input_event = self.create_lambda_input_event(context)

        function_arn = get_lambda_function_arn_from_invocation_uri(integration["uri"])
        source_arn = get_source_arn(context)
        # TODO: properly get the value out/validate it?
        raw_headers = context.invocation_request["raw_headers"]
        is_invocation_asynchronous = raw_headers.get("X-Amz-Invocation-Type") == "'Event'"

        try:
            lambda_payload = self.call_lambda(
                function_arn=function_arn,
                event=to_bytes(json.dumps(input_event)),
                source_arn=source_arn,
                credentials=integration.get("credentials"),
                asynchronous=is_invocation_asynchronous,
            )
        except ClientError as e:
            # TODO: more data from the error message?
            LOG.warning(
                "Exception during integration invocation: '%s'",
                e,
            )
            raise IntegrationFailureError("Internal server error", status_code=502) from e
        except Exception as e:
            LOG.warning(
                "Unexpected exception during integration invocation: '%s'",
                e,
            )
            raise IntegrationFailureError("Internal server error", status_code=502) from e

        lambda_response = self.parse_lambda_response(lambda_payload)

        headers = merge_dicts(
            {"Content-Type": "application/json"},
            lambda_response.get("headers") or {},
            lambda_response.get("multiValueHeaders") or {},
        )
        # TODO: look into remapped headers (like HTTP_PROXY and integration response handlers)

        response = Response(
            headers=Headers(headers),
            response=lambda_response.get("body") or "",
            status=lambda_response.get("statusCode") or 200,
        )

        return response

    @staticmethod
    def call_lambda(
        function_arn: str,
        event: bytes,
        source_arn: str,
        credentials: str = None,
        asynchronous: bool = False,
    ) -> bytes:
        lambda_client = get_service_factory(
            region_name=extract_region_from_arn(function_arn),
            role_arn=credentials,
        ).lambda_
        inv_result = lambda_client.request_metadata(
            service_principal=ServicePrincipal.apigateway,
            source_arn=source_arn,
        ).invoke(
            FunctionName=function_arn,
            Payload=event,
            InvocationType="Event" if asynchronous else "RequestResponse",
        )
        if payload := inv_result.get("Payload"):
            return payload.read()
        return b""

    def parse_lambda_response(self, payload: bytes) -> LambdaProxyResponse:
        try:
            lambda_response = json.loads(payload)
        except json.JSONDecodeError:
            raise InternalServerError("Internal server error", status_code=502)

        # none of the lambda response fields are mandatory, but you cannot return any other fields
        if not self._is_lambda_response_valid(lambda_response):
            if "errorMessage" in lambda_response:
                LOG.debug(
                    "Lambda execution failed with status 200 due to customer function error: %s. Lambda request id: %s",
                    lambda_response["errorMessage"],
                    lambda_response["requestId"],
                )
            else:
                LOG.warning(
                    'Lambda output should follow the next JSON format: { "isBase64Encoded": true|false, "statusCode": httpStatusCode, "headers": { "headerName": "headerValue", ... },"body": "..."} but was: %s',
                    payload,
                )
                LOG.debug(
                    "Execution failed due to configuration error: Malformed Lambda proxy response"
                )
            raise InternalServerError("Internal server error", status_code=502)

        return lambda_response

    @staticmethod
    def _is_lambda_response_valid(lambda_response: dict) -> bool:
        if not isinstance(lambda_response, dict):
            return False

        if not validate_sub_dict_of_typed_dict(LambdaProxyResponse, lambda_response):
            return False

        if "headers" in lambda_response:
            headers = lambda_response["headers"]
            if not isinstance(headers, dict):
                return False
            if any(not isinstance(header_value, str) for header_value in headers.values()):
                return False

        # TODO: add more validations of the values' type
        return True

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
