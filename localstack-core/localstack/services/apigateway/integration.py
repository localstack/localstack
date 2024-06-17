import base64
import json
import logging
import re
from abc import ABC, abstractmethod
from functools import lru_cache
from http import HTTPMethod, HTTPStatus
from typing import Any, Dict
from urllib.parse import urljoin

import requests
from botocore.exceptions import ClientError
from moto.apigatewayv2.exceptions import BadRequestException
from requests import Response

from localstack import config
from localstack.aws.connect import (
    INTERNAL_REQUEST_PARAMS_HEADER,
    InternalRequestParameters,
    connect_to,
    dump_dto,
)
from localstack.constants import APPLICATION_JSON, HEADER_CONTENT_TYPE
from localstack.services.apigateway import helpers
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import (
    ApiGatewayIntegrationError,
    IntegrationParameters,
    RequestParametersResolver,
    ResponseParametersResolver,
    extract_path_params,
    extract_query_string_params,
    get_event_request_context,
    make_error_response,
    multi_value_dict_for_list,
)
from localstack.services.apigateway.templates import (
    MappingTemplates,
    RequestTemplates,
    ResponseTemplates,
)
from localstack.services.stepfunctions.stepfunctions_utils import await_sfn_execution_result
from localstack.utils import common
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.aws.aws_responses import (
    LambdaResponse,
    request_response_stream,
    requests_response,
)
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.aws.request_context import mock_aws_request_headers
from localstack.utils.aws.templating import VtlTemplate
from localstack.utils.collections import dict_multi_values, remove_attributes
from localstack.utils.common import make_http_request, to_str
from localstack.utils.http import add_query_params_to_url, canonicalize_headers, parse_request_data
from localstack.utils.json import json_safe, try_json
from localstack.utils.strings import camel_to_snake_case, to_bytes

LOG = logging.getLogger(__name__)


class IntegrationAccessError(ApiGatewayIntegrationError):
    """
    Error message when an integration cannot be accessed.
    """

    def __init__(self):
        super().__init__("Internal server error", 500)


class BackendIntegration(ABC):
    """Abstract base class representing a backend integration"""

    def __init__(self):
        self.request_templates = RequestTemplates()
        self.response_templates = ResponseTemplates()
        self.request_params_resolver = RequestParametersResolver()
        self.response_params_resolver = ResponseParametersResolver()

    @abstractmethod
    def invoke(self, invocation_context: ApiInvocationContext):
        pass

    @classmethod
    def _create_response(cls, status_code, headers, data=""):
        response = Response()
        response.status_code = status_code
        response.headers = headers
        response._content = data
        return response

    @classmethod
    def apply_request_parameters(
        cls, integration_params: IntegrationParameters, headers: Dict[str, Any]
    ):
        for k, v in integration_params.get("headers").items():
            headers.update({k: v})

    @classmethod
    def apply_response_parameters(
        cls, invocation_context: ApiInvocationContext, response: Response
    ):
        integration = invocation_context.integration
        integration_responses = integration.get("integrationResponses") or {}
        if not integration_responses:
            return response
        entries = list(integration_responses.keys())
        return_code = str(response.status_code)
        if return_code not in entries:
            if len(entries) > 1:
                LOG.info("Found multiple integration response status codes: %s", entries)
                return response
            return_code = entries[0]
        response_params = integration_responses[return_code].get("responseParameters", {})
        for key, value in response_params.items():
            # TODO: add support for method.response.body, etc ...
            if str(key).lower().startswith("method.response.header."):
                header_name = key[len("method.response.header.") :]
                response.headers[header_name] = value.strip("'")
        return response

    @classmethod
    def render_template_selection_expression(cls, invocation_context: ApiInvocationContext):
        integration = invocation_context.integration
        template_selection_expression = integration.get("templateSelectionExpression")

        # AWS template selection relies on the content type
        # to select an input template or output mapping AND template selection expressions.
        # All of them will fall back to the $default template if a matching template is not found.
        if not template_selection_expression:
            content_type = invocation_context.headers.get(HEADER_CONTENT_TYPE, APPLICATION_JSON)
            if integration.get("RequestTemplates", {}).get(content_type):
                return content_type
            return "$default"

        data = try_json(invocation_context.data)
        variables = {
            "request": {
                "header": invocation_context.headers,
                "querystring": invocation_context.query_params(),
                "body": data,
                "context": invocation_context.context or {},
                "stage_variables": invocation_context.stage_variables or {},
            }
        }
        return VtlTemplate().render_vtl(template_selection_expression, variables) or "$default"


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
    headers = mock_aws_request_headers(
        service=service_name, aws_access_key_id=access_key_id, region_name=region_name
    )

    dto = InternalRequestParameters(
        service_principal=ServicePrincipal.apigateway, source_arn=source_arn
    )
    headers[INTERNAL_REQUEST_PARAMS_HEADER] = dump_dto(dto)
    return headers


def get_source_arn(invocation_context: ApiInvocationContext):
    return f"arn:aws:execute-api:{invocation_context.region_name}:{invocation_context.account_id}:{invocation_context.api_id}/{invocation_context.stage}/{invocation_context.method}{invocation_context.path}"


def call_lambda(
    function_arn: str, event: bytes, asynchronous: bool, invocation_context: ApiInvocationContext
) -> str:
    clients = get_service_factory(
        region_name=extract_region_from_arn(function_arn),
        role_arn=invocation_context.integration.get("credentials"),
    )
    inv_result = clients.lambda_.request_metadata(
        service_principal=ServicePrincipal.apigateway, source_arn=get_source_arn(invocation_context)
    ).invoke(
        FunctionName=function_arn,
        Payload=event,
        InvocationType="Event" if asynchronous else "RequestResponse",
    )
    if payload := inv_result.get("Payload"):
        payload = to_str(payload.read())
        return payload
    return ""


class LambdaProxyIntegration(BackendIntegration):
    @classmethod
    def update_content_length(cls, response: Response):
        if response and response.content is not None:
            response.headers["Content-Length"] = str(len(response.content))

    @classmethod
    def lambda_result_to_response(cls, result) -> LambdaResponse:
        response = LambdaResponse()
        response.headers.update({"content-type": "application/json"})
        parsed_result = result if isinstance(result, dict) else json.loads(str(result or "{}"))
        parsed_result = common.json_safe(parsed_result)
        parsed_result = {} if parsed_result is None else parsed_result

        if set(parsed_result) - {
            "body",
            "statusCode",
            "headers",
            "isBase64Encoded",
            "multiValueHeaders",
        }:
            LOG.warning(
                'Lambda output should follow the next JSON format: { "isBase64Encoded": true|false, "statusCode": httpStatusCode, "headers": { "headerName": "headerValue", ... },"body": "..."}\n Lambda output: %s',
                parsed_result,
            )
            response.status_code = 502
            response._content = json.dumps({"message": "Internal server error"})
            return response

        response.status_code = int(parsed_result.get("statusCode", 200))
        parsed_headers = parsed_result.get("headers", {})
        if parsed_headers is not None:
            response.headers.update(parsed_headers)
        try:
            result_body = parsed_result.get("body")
            if isinstance(result_body, dict):
                response._content = json.dumps(result_body)
            else:
                body_bytes = to_bytes(to_str(result_body or ""))
                if parsed_result.get("isBase64Encoded", False):
                    body_bytes = base64.b64decode(body_bytes)
                response._content = body_bytes
        except Exception as e:
            LOG.warning("Couldn't set Lambda response content: %s", e)
            response._content = "{}"
        response.multi_value_headers = parsed_result.get("multiValueHeaders") or {}
        return response

    @staticmethod
    def fix_proxy_path_params(path_params):
        proxy_path_param_value = path_params.get("proxy+")
        if not proxy_path_param_value:
            return
        del path_params["proxy+"]
        path_params["proxy"] = proxy_path_param_value

    @staticmethod
    def validate_integration_method(invocation_context: ApiInvocationContext):
        if invocation_context.integration["httpMethod"] != HTTPMethod.POST:
            raise ApiGatewayIntegrationError("Internal server error", status_code=500)

    @classmethod
    def construct_invocation_event(
        cls, method, path, headers, data, query_string_params=None, is_base64_encoded=False
    ):
        query_string_params = query_string_params or parse_request_data(method, path, "")

        single_value_query_string_params = {
            k: v[-1] if isinstance(v, list) else v for k, v in query_string_params.items()
        }
        # Some headers get capitalized like in CloudFront, see
        # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/add-origin-custom-headers.html#add-origin-custom-headers-forward-authorization
        # It seems AWS_PROXY lambda integrations are behind cloudfront, as seen by the returned headers in AWS
        to_capitalize: list[str] = ["authorization"]  # some headers get capitalized
        headers = {
            k.capitalize() if k.lower() in to_capitalize else k: v for k, v in headers.items()
        }

        # AWS canonical header names, converting them to lower-case
        headers = canonicalize_headers(headers)

        return {
            "path": path,
            "headers": headers,
            "multiValueHeaders": multi_value_dict_for_list(headers),
            "body": data,
            "isBase64Encoded": is_base64_encoded,
            "httpMethod": method,
            "queryStringParameters": single_value_query_string_params or None,
            "multiValueQueryStringParameters": dict_multi_values(query_string_params) or None,
        }

    @classmethod
    def process_apigateway_invocation(
        cls,
        func_arn,
        path,
        payload,
        invocation_context: ApiInvocationContext,
        query_string_params=None,
    ) -> str:
        if (path_params := invocation_context.path_params) is None:
            path_params = {}
        if (request_context := invocation_context.context) is None:
            request_context = {}
        try:
            resource_path = invocation_context.resource_path or path
            event = cls.construct_invocation_event(
                invocation_context.method,
                path,
                invocation_context.headers,
                payload,
                query_string_params,
                invocation_context.is_data_base64_encoded,
            )
            path_params = dict(path_params)
            cls.fix_proxy_path_params(path_params)
            event["pathParameters"] = path_params
            event["resource"] = resource_path
            event["requestContext"] = request_context
            event["stageVariables"] = invocation_context.stage_variables
            LOG.debug(
                "Running Lambda function %s from API Gateway invocation: %s %s",
                func_arn,
                invocation_context.method or "GET",
                path,
            )
            asynchronous = invocation_context.headers.get("X-Amz-Invocation-Type") == "'Event'"
            return call_lambda(
                function_arn=func_arn,
                event=to_bytes(json.dumps(event)),
                asynchronous=asynchronous,
                invocation_context=invocation_context,
            )
        except ClientError as e:
            raise IntegrationAccessError() from e
        except Exception as e:
            LOG.warning(
                "Unable to run Lambda function on API Gateway message: %s",
                e,
            )

    def invoke(self, invocation_context: ApiInvocationContext):
        self.validate_integration_method(invocation_context)
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        invocation_context.context = get_event_request_context(invocation_context)
        relative_path, query_string_params = extract_query_string_params(
            path=invocation_context.path_with_query_string
        )
        try:
            path_params = extract_path_params(
                path=relative_path, extracted_path=invocation_context.resource_path
            )
            invocation_context.path_params = path_params
        except Exception:
            pass

        func_arn = uri
        if ":lambda:path" in uri:
            func_arn = uri.split(":lambda:path")[1].split("functions/")[1].split("/invocations")[0]

        if invocation_context.authorizer_type:
            invocation_context.context["authorizer"] = invocation_context.authorizer_result

        payload = self.request_templates.render(invocation_context)

        result = self.process_apigateway_invocation(
            func_arn=func_arn,
            path=relative_path,
            payload=payload,
            invocation_context=invocation_context,
            query_string_params=query_string_params,
        )

        response = LambdaResponse()
        response.headers.update({"content-type": "application/json"})
        parsed_result = json.loads(str(result or "{}"))
        parsed_result = common.json_safe(parsed_result)
        parsed_result = {} if parsed_result is None else parsed_result

        if set(parsed_result) - {
            "body",
            "statusCode",
            "headers",
            "isBase64Encoded",
            "multiValueHeaders",
        }:
            LOG.warning(
                'Lambda output should follow the next JSON format: { "isBase64Encoded": true|false, "statusCode": httpStatusCode, "headers": { "headerName": "headerValue", ... },"body": "..."}\n Lambda output: %s',
                parsed_result,
            )
            response.status_code = 502
            response._content = json.dumps({"message": "Internal server error"})
            return response

        response.status_code = int(parsed_result.get("statusCode", 200))
        parsed_headers = parsed_result.get("headers", {})
        if parsed_headers is not None:
            response.headers.update(parsed_headers)
        try:
            result_body = parsed_result.get("body")
            if isinstance(result_body, dict):
                response._content = json.dumps(result_body)
            else:
                body_bytes = to_bytes(result_body or "")
                if parsed_result.get("isBase64Encoded", False):
                    body_bytes = base64.b64decode(body_bytes)
                response._content = body_bytes
        except Exception as e:
            LOG.warning("Couldn't set Lambda response content: %s", e)
            response._content = "{}"
        response.multi_value_headers = parsed_result.get("multiValueHeaders") or {}

        # apply custom response template
        self.update_content_length(response)
        invocation_context.response = response

        return invocation_context.response


class LambdaIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        # invocation_context.context = helpers.get_event_request_context(invocation_context)
        invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)
        headers = invocation_context.headers

        # resolve integration parameters
        integration_parameters = self.request_params_resolver.resolve(context=invocation_context)
        headers.update(integration_parameters.get("headers", {}))

        if invocation_context.authorizer_type:
            invocation_context.context["authorizer"] = invocation_context.authorizer_result

        func_arn = self._lambda_integration_uri(invocation_context)
        # integration type "AWS" is only supported for WebSocket APIs and REST
        # API (v1), but the template selection expression is only supported for
        # Websockets
        if invocation_context.is_websocket_request():
            template_key = self.render_template_selection_expression(invocation_context)
            payload = self.request_templates.render(invocation_context, template_key)
        else:
            payload = self.request_templates.render(invocation_context)

        asynchronous = headers.get("X-Amz-Invocation-Type", "").strip("'") == "Event"
        try:
            result = call_lambda(
                function_arn=func_arn,
                event=to_bytes(payload or ""),
                asynchronous=asynchronous,
                invocation_context=invocation_context,
            )
        except ClientError as e:
            raise IntegrationAccessError() from e

        # default lambda status code is 200
        response = LambdaResponse()
        response.status_code = 200
        response._content = result

        if asynchronous:
            response._content = ""

        # response template
        invocation_context.response = response
        self.response_templates.render(invocation_context)
        invocation_context.response.headers["Content-Length"] = str(len(response.content or ""))

        headers = self.response_params_resolver.resolve(invocation_context)
        invocation_context.response.headers.update(headers)

        return invocation_context.response

    def _lambda_integration_uri(self, invocation_context: ApiInvocationContext):
        """
        https://docs.aws.amazon.com/apigateway/latest/developerguide/aws-api-gateway-stage-variables-reference.html
        """
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        variables = {"stageVariables": invocation_context.stage_variables}
        uri = VtlTemplate().render_vtl(uri, variables)
        if ":lambda:path" in uri:
            uri = uri.split(":lambda:path")[1].split("functions/")[1].split("/invocations")[0]
        return uri


class KinesisIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        integration = invocation_context.integration
        integration_type_orig = integration.get("type") or integration.get("integrationType") or ""
        integration_type = integration_type_orig.upper()
        uri = integration.get("uri") or integration.get("integrationUri") or ""
        integration_subtype = integration.get("integrationSubtype")

        if uri.endswith("kinesis:action/PutRecord") or integration_subtype == "Kinesis-PutRecord":
            target = "Kinesis_20131202.PutRecord"
        elif uri.endswith("kinesis:action/PutRecords"):
            target = "Kinesis_20131202.PutRecords"
        elif uri.endswith("kinesis:action/ListStreams"):
            target = "Kinesis_20131202.ListStreams"
        else:
            LOG.info(
                f"Unexpected API Gateway integration URI '{uri}' for integration type {integration_type}",
            )
            target = ""

        try:
            # xXx this "event" request context is used in multiple places, we probably
            # want to refactor this into a model class.
            # I'd argue we should not make a decision on the event_request_context inside the integration because,
            # it's different between API types (REST, HTTP, WebSocket) and per event version
            invocation_context.context = helpers.get_event_request_context(invocation_context)
            invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)

            # integration type "AWS" is only supported for WebSocket APIs and REST
            # API (v1), but the template selection expression is only supported for
            # Websockets
            if invocation_context.is_websocket_request():
                template_key = self.render_template_selection_expression(invocation_context)
                payload = self.request_templates.render(invocation_context, template_key)
            else:
                # For HTTP APIs with a specified integration_subtype,
                # a key-value map specifying parameters that are passed to AWS_PROXY integrations
                if integration_type == "AWS_PROXY" and integration_subtype == "Kinesis-PutRecord":
                    payload = self._create_request_parameters(invocation_context)
                else:
                    payload = self.request_templates.render(invocation_context)

        except Exception as e:
            LOG.warning("Unable to convert API Gateway payload to str", e)
            raise

        # forward records to target kinesis stream
        headers = get_internal_mocked_headers(
            service_name="kinesis",
            region_name=invocation_context.region_name,
            role_arn=invocation_context.integration.get("credentials"),
            source_arn=get_source_arn(invocation_context),
        )
        headers["X-Amz-Target"] = target

        result = common.make_http_request(
            url=config.internal_service_url(), data=payload, headers=headers, method="POST"
        )

        # apply response template
        invocation_context.response = result
        self.response_templates.render(invocation_context)
        return invocation_context.response

    @classmethod
    def _validate_required_params(cls, request_parameters: Dict[str, Any]) -> None:
        if not request_parameters:
            raise BadRequestException("Missing required parameters")
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html#Kinesis-PutRecord
        stream_name = request_parameters.get("StreamName")
        partition_key = request_parameters.get("PartitionKey")
        data = request_parameters.get("Data")

        if not stream_name:
            raise BadRequestException("StreamName")

        if not partition_key:
            raise BadRequestException("PartitionKey")

        if not data:
            raise BadRequestException("Data")

    def _create_request_parameters(
        self, invocation_context: ApiInvocationContext
    ) -> Dict[str, Any]:
        request_parameters = invocation_context.integration.get("requestParameters", {})
        self._validate_required_params(request_parameters)

        variables = {
            "request": {
                "header": invocation_context.headers,
                "querystring": invocation_context.query_params(),
                "body": invocation_context.data_as_string(),
                "context": invocation_context.context or {},
                "stage_variables": invocation_context.stage_variables or {},
            }
        }

        if invocation_context.headers.get("Content-Type") == "application/json":
            variables["request"]["body"] = json.loads(invocation_context.data_as_string())
        else:
            # AWS parity no content type still yields a valid response from Kinesis
            variables["request"]["body"] = try_json(invocation_context.data_as_string())

        # Required parameters
        payload = {
            "StreamName": VtlTemplate().render_vtl(request_parameters.get("StreamName"), variables),
            "Data": VtlTemplate().render_vtl(request_parameters.get("Data"), variables),
            "PartitionKey": VtlTemplate().render_vtl(
                request_parameters.get("PartitionKey"), variables
            ),
        }
        # Optional Parameters
        if "ExplicitHashKey" in request_parameters:
            payload["ExplicitHashKey"] = VtlTemplate().render_vtl(
                request_parameters.get("ExplicitHashKey"), variables
            )
        if "SequenceNumberForOrdering" in request_parameters:
            payload["SequenceNumberForOrdering"] = VtlTemplate().render_vtl(
                request_parameters.get("SequenceNumberForOrdering"), variables
            )
        # TODO: XXX we don't support the Region parameter
        # if "Region" in request_parameters:
        #     payload["Region"] = VtlTemplate().render_vtl(
        #         request_parameters.get("Region"), variables
        #     )
        return json.dumps(payload)


class DynamoDBIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        # TODO we might want to do it plain http instead of using boto here, like kinesis
        integration = invocation_context.integration
        uri = integration.get("uri") or integration.get("integrationUri") or ""

        # example: arn:aws:apigateway:us-east-1:dynamodb:action/PutItem&Table=MusicCollection
        action = uri.split(":dynamodb:action/")[1].split("&")[0]

        # render request template
        payload = self.request_templates.render(invocation_context)
        payload = json.loads(payload)

        # determine target method via reflection
        clients = get_service_factory(
            region_name=invocation_context.region_name,
            role_arn=invocation_context.integration.get("credentials"),
        )
        dynamo_client = clients.dynamodb.request_metadata(
            service_principal=ServicePrincipal.apigateway,
            source_arn=get_source_arn(invocation_context),
        )
        method_name = camel_to_snake_case(action)
        client_method = getattr(dynamo_client, method_name, None)
        if not client_method:
            raise Exception(f"Unsupported action {action} in API Gateway integration URI {uri}")

        # run request against DynamoDB backend
        try:
            response = client_method(**payload)
        except ClientError as e:
            response = e.response
            # The request body is packed into the "Error" field. To make the response match AWS, we will remove that
            # field and merge with the response dict
            error = response.pop("Error", {})
            error.pop("Code", None)  # the Code is also something not relayed
            response |= error

        status_code = response.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
        # apply response templates
        response_content = json.dumps(remove_attributes(response, ["ResponseMetadata"]))
        response_obj = requests_response(content=response_content)
        response = self.response_templates.render(invocation_context, response=response_obj)

        # construct final response
        # TODO: set response header based on response templates
        headers = {HEADER_CONTENT_TYPE: APPLICATION_JSON}
        response = requests_response(response, headers=headers, status_code=status_code)

        return response


class S3Integration(BackendIntegration):
    # target ARN patterns
    TARGET_REGEX_PATH_S3_URI = (
        r"^arn:aws:apigateway:[a-zA-Z0-9\-]+:s3:path/(?P<bucket>[^/]+)/(?P<object>.+)$"
    )
    TARGET_REGEX_ACTION_S3_URI = r"^arn:aws:apigateway:[a-zA-Z0-9\-]+:s3:action/(?:GetObject&Bucket\=(?P<bucket>[^&]+)&Key\=(?P<object>.+))$"

    def invoke(self, invocation_context: ApiInvocationContext):
        invocation_path = invocation_context.path_with_query_string
        integration = invocation_context.integration
        path_params = invocation_context.path_params
        relative_path, query_string_params = extract_query_string_params(path=invocation_path)
        uri = integration.get("uri") or integration.get("integrationUri") or ""

        s3 = connect_to().s3
        uri = apply_request_parameters(
            uri,
            integration=integration,
            path_params=path_params,
            query_params=query_string_params,
        )
        uri_match = re.match(self.TARGET_REGEX_PATH_S3_URI, uri) or re.match(
            self.TARGET_REGEX_ACTION_S3_URI, uri
        )
        if not uri_match:
            msg = "Request URI does not match s3 specifications"
            LOG.warning(msg)
            return make_error_response(msg, 400)

        bucket, object_key = uri_match.group("bucket", "object")
        LOG.debug("Getting request for bucket %s object %s", bucket, object_key)

        action = None
        invoke_args = {"Bucket": bucket, "Key": object_key}
        match invocation_context.method:
            case HTTPMethod.GET:
                action = s3.get_object
            case HTTPMethod.PUT:
                invoke_args["Body"] = invocation_context.data
                action = s3.put_object
            case HTTPMethod.DELETE:
                action = s3.delete_object
            case _:
                make_error_response(
                    "The specified method is not allowed against this resource.", 405
                )

        try:
            object = action(**invoke_args)
        except s3.exceptions.NoSuchKey:
            msg = f"Object {object_key} not found"
            LOG.debug(msg)
            return make_error_response(msg, 404)

        headers = mock_aws_request_headers(
            service="s3",
            aws_access_key_id=invocation_context.account_id,
            region_name=invocation_context.region_name,
        )

        if object.get("ContentType"):
            headers["Content-Type"] = object["ContentType"]

        # stream used so large files do not fill memory
        if body := object.get("Body"):
            response = request_response_stream(stream=body, headers=headers)
        else:
            response = requests_response(content="", headers=headers)
        return response


class HTTPIntegration(BackendIntegration):
    @staticmethod
    def _set_http_apigw_headers(headers: Dict[str, Any], invocation_context: ApiInvocationContext):
        del headers["host"]
        headers["x-amzn-apigateway-api-id"] = invocation_context.api_id
        return headers

    def invoke(self, invocation_context: ApiInvocationContext):
        invocation_path = invocation_context.path_with_query_string
        integration = invocation_context.integration
        path_params = invocation_context.path_params
        method = invocation_context.method
        headers = invocation_context.headers

        relative_path, query_string_params = extract_query_string_params(path=invocation_path)
        uri = integration.get("uri") or integration.get("integrationUri") or ""

        # resolve integration parameters
        integration_parameters = self.request_params_resolver.resolve(context=invocation_context)
        headers.update(integration_parameters.get("headers", {}))
        self._set_http_apigw_headers(headers, invocation_context)

        if ":servicediscovery:" in uri:
            # check if this is a servicediscovery integration URI
            client = connect_to().servicediscovery
            service_id = uri.split("/")[-1]
            instances = client.list_instances(ServiceId=service_id)["Instances"]
            instance = (instances or [None])[0]
            if instance and instance.get("Id"):
                uri = "http://%s/%s" % (instance["Id"], invocation_path.lstrip("/"))

        # apply custom request template
        invocation_context.context = helpers.get_event_request_context(invocation_context)
        invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)
        payload = self.request_templates.render(invocation_context)

        if isinstance(payload, dict):
            payload = json.dumps(payload)

        # https://docs.aws.amazon.com/apigateway/latest/developerguide/aws-api-gateway-stage-variables-reference.html
        # HTTP integration URIs
        #
        # A stage variable can be used as part of an HTTP integration URL, as shown in the following examples:
        #
        # A full URI without protocol – http://${stageVariables.<variable_name>}
        # A full domain – http://${stageVariables.<variable_name>}/resource/operation
        # A subdomain – http://${stageVariables.<variable_name>}.example.com/resource/operation
        # A path – http://example.com/${stageVariables.<variable_name>}/bar
        # A query string – http://example.com/foo?q=${stageVariables.<variable_name>}
        render_vars = {"stageVariables": invocation_context.stage_variables}
        rendered_uri = VtlTemplate().render_vtl(uri, render_vars)

        uri = apply_request_parameters(
            rendered_uri,
            integration=integration,
            path_params=path_params,
            query_params=query_string_params,
        )
        result = requests.request(method=method, url=uri, data=payload, headers=headers)
        if not result.ok:
            LOG.debug(
                "Upstream response from <%s> %s returned with status code: %s",
                method,
                uri,
                result.status_code,
            )
        # apply custom response template for non-proxy integration
        invocation_context.response = result
        if integration["type"] != "HTTP_PROXY":
            self.response_templates.render(invocation_context)
        return invocation_context.response


class SQSIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        integration = invocation_context.integration
        uri = integration.get("uri") or integration.get("integrationUri") or ""
        account_id, queue = uri.split("/")[-2:]
        region_name = uri.split(":")[3]

        headers = get_internal_mocked_headers(
            service_name="sqs",
            region_name=region_name,
            role_arn=invocation_context.integration.get("credentials"),
            source_arn=get_source_arn(invocation_context),
        )

        # integration parameters can override headers
        integration_parameters = self.request_params_resolver.resolve(context=invocation_context)
        headers.update(integration_parameters.get("headers", {}))
        if "Accept" not in headers:
            headers["Accept"] = "application/json"

        if invocation_context.is_websocket_request():
            template_key = self.render_template_selection_expression(invocation_context)
            payload = self.request_templates.render(invocation_context, template_key)
        else:
            payload = self.request_templates.render(invocation_context)

        # not sure what the purpose of this is, but it's in the original code
        # TODO: check if this is still needed
        if "GetQueueUrl" in payload or "CreateQueue" in payload:
            new_request = f"{payload}&QueueName={queue}"
        else:
            queue_url = f"{config.internal_service_url()}/queue/{region_name}/{account_id}/{queue}"
            new_request = f"{payload}&QueueUrl={queue_url}"

        url = urljoin(config.internal_service_url(), f"/queue/{region_name}/{account_id}/{queue}")
        response = common.make_http_request(url, method="POST", headers=headers, data=new_request)

        # apply response template
        invocation_context.response = response
        response._content = self.response_templates.render(invocation_context)
        return response


class SNSIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext) -> Response:
        # TODO: check if the logic below is accurate - cover with snapshot tests!
        invocation_context.context = get_event_request_context(invocation_context)
        invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)
        integration = invocation_context.integration
        uri = integration.get("uri") or integration.get("integrationUri") or ""

        try:
            if invocation_context.is_websocket_request():
                template_key = self.render_template_selection_expression(invocation_context)
                payload = self.request_templates.render(invocation_context, template_key)
            else:
                payload = self.request_templates.render(invocation_context)
        except Exception as e:
            LOG.warning("Failed to apply template for SNS integration", e)
            raise
        region_name = uri.split(":")[3]
        headers = mock_aws_request_headers(
            service="sns", aws_access_key_id=invocation_context.account_id, region_name=region_name
        )
        response = make_http_request(
            config.internal_service_url(), method="POST", headers=headers, data=payload
        )

        invocation_context.response = response
        response._content = self.response_templates.render(invocation_context)
        return self.apply_response_parameters(invocation_context, response)


class StepFunctionIntegration(BackendIntegration):
    @classmethod
    def _validate_required_params(cls, request_parameters: Dict[str, Any]) -> None:
        if not request_parameters:
            raise BadRequestException("Missing required parameters")
        # stateMachineArn and input are required
        state_machine_arn_param = request_parameters.get("StateMachineArn")
        input_param = request_parameters.get("Input")

        if not state_machine_arn_param:
            raise BadRequestException("StateMachineArn")

        if not input_param:
            raise BadRequestException("Input")

    def invoke(self, invocation_context: ApiInvocationContext):
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        action = uri.split("/")[-1]

        if invocation_context.integration.get("IntegrationType") == "AWS_PROXY":
            payload = self._create_request_parameters(invocation_context)
        elif APPLICATION_JSON in invocation_context.integration.get("requestTemplates", {}):
            payload = self.request_templates.render(invocation_context)
            payload = json.loads(payload)
        else:
            payload = json.loads(invocation_context.data)

        client = get_service_factory(
            region_name=invocation_context.region_name,
            role_arn=invocation_context.integration.get("credentials"),
        ).stepfunctions

        if isinstance(payload.get("input"), dict):
            payload["input"] = json.dumps(payload["input"])

        # Hot fix since step functions local package responses: Unsupported Operation: 'StartSyncExecution'
        method_name = (
            camel_to_snake_case(action) if action != "StartSyncExecution" else "start_execution"
        )

        try:
            # call method on step function client
            method = getattr(client, method_name)
        except AttributeError:
            msg = f"Invalid step function action: {method_name}"
            LOG.error(msg)
            return StepFunctionIntegration._create_response(
                HTTPStatus.BAD_REQUEST.value,
                headers={"Content-Type": APPLICATION_JSON},
                data=json.dumps({"message": msg}),
            )

        result = method(**payload)
        result = json_safe(remove_attributes(result, ["ResponseMetadata"]))
        response = StepFunctionIntegration._create_response(
            HTTPStatus.OK.value,
            mock_aws_request_headers(
                "stepfunctions",
                aws_access_key_id=invocation_context.account_id,
                region_name=invocation_context.region_name,
            ),
            data=json.dumps(result),
        )
        if action == "StartSyncExecution":
            # poll for the execution result and return it
            result = await_sfn_execution_result(result["executionArn"])
            result_status = result.get("status")
            if result_status != "SUCCEEDED":
                return StepFunctionIntegration._create_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR.value,
                    headers={"Content-Type": APPLICATION_JSON},
                    data=json.dumps(
                        {
                            "message": "StepFunctions execution %s failed with status '%s'"
                            % (result["executionArn"], result_status)
                        }
                    ),
                )

            result = json_safe(result)
            response = requests_response(content=result)

        # apply response templates
        invocation_context.response = response
        response._content = self.response_templates.render(invocation_context)
        return response

    def _create_request_parameters(self, invocation_context):
        request_parameters = invocation_context.integration.get("requestParameters", {})
        self._validate_required_params(request_parameters)

        variables = {
            "request": {
                "header": invocation_context.headers,
                "querystring": invocation_context.query_params(),
                "body": invocation_context.data_as_string(),
                "context": invocation_context.context or {},
                "stage_variables": invocation_context.stage_variables or {},
            }
        }
        rendered_input = VtlTemplate().render_vtl(request_parameters.get("Input"), variables)
        return {
            "stateMachineArn": request_parameters.get("StateMachineArn"),
            "input": rendered_input,
        }


class MockIntegration(BackendIntegration):
    @classmethod
    def check_passthrough_behavior(cls, passthrough_behavior: str, request_template: str):
        return MappingTemplates(passthrough_behavior).check_passthrough_behavior(request_template)

    def invoke(self, invocation_context: ApiInvocationContext) -> Response:
        passthrough_behavior = invocation_context.integration.get("passthroughBehavior") or ""
        request_template = invocation_context.integration.get("requestTemplates", {}).get(
            invocation_context.headers.get(HEADER_CONTENT_TYPE, APPLICATION_JSON)
        )

        # based on the configured passthrough behavior and the existence of template or not,
        # we proceed calling the integration or raise an exception.
        try:
            self.check_passthrough_behavior(passthrough_behavior, request_template)
        except MappingTemplates.UnsupportedMediaType:
            return MockIntegration._create_response(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE.value,
                headers={"Content-Type": APPLICATION_JSON},
                data=json.dumps({"message": f"{HTTPStatus.UNSUPPORTED_MEDIA_TYPE.phrase}"}),
            )

        # request template rendering
        request_payload = self.request_templates.render(invocation_context)

        # mapping is done based on "statusCode" field, we default to 200
        status_code = 200
        if invocation_context.headers.get(HEADER_CONTENT_TYPE) == APPLICATION_JSON:
            try:
                mock_response = json.loads(request_payload)
                status_code = mock_response.get("statusCode", status_code)
            except Exception as e:
                LOG.warning("failed to deserialize request payload after transformation: %s", e)
                http_status = HTTPStatus(500)
                return MockIntegration._create_response(
                    http_status.value,
                    headers={"Content-Type": APPLICATION_JSON},
                    data=json.dumps({"message": f"{http_status.phrase}"}),
                )

        # response template
        response = MockIntegration._create_response(
            status_code, invocation_context.headers, data=request_payload
        )
        response._content = self.response_templates.render(invocation_context, response=response)
        # apply response parameters
        response = self.apply_response_parameters(invocation_context, response)
        if not invocation_context.headers.get(HEADER_CONTENT_TYPE):
            invocation_context.headers.update({HEADER_CONTENT_TYPE: APPLICATION_JSON})
        return response


# TODO: remove once we migrate all usages to `apply_request_parameters` on BackendIntegration
def apply_request_parameters(
    uri: str, integration: Dict[str, Any], path_params: Dict[str, str], query_params: Dict[str, str]
):
    request_parameters = integration.get("requestParameters")
    uri = uri or integration.get("uri") or integration.get("integrationUri") or ""
    if request_parameters:
        for key in path_params:
            # check if path_params is present in the integration request parameters
            request_param_key = f"integration.request.path.{key}"
            request_param_value = f"method.request.path.{key}"
            if request_parameters.get(request_param_key) == request_param_value:
                uri = uri.replace(f"{{{key}}}", path_params[key])

    if integration.get("type") != "HTTP_PROXY" and request_parameters:
        for key in query_params.copy():
            request_query_key = f"integration.request.querystring.{key}"
            request_param_val = f"method.request.querystring.{key}"
            if request_parameters.get(request_query_key, None) != request_param_val:
                query_params.pop(key)

    return add_query_params_to_url(uri, query_params)


class EventBridgeIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        invocation_context.context = get_event_request_context(invocation_context)
        try:
            payload = self.request_templates.render(invocation_context)
        except Exception as e:
            LOG.warning("Failed to apply template for EventBridge integration: %s", e)
            raise
        uri = (
            invocation_context.integration.get("uri")
            or invocation_context.integration.get("integrationUri")
            or ""
        )
        region_name = uri.split(":")[3]
        headers = get_internal_mocked_headers(
            service_name="events",
            region_name=region_name,
            role_arn=invocation_context.integration.get("credentials"),
            source_arn=get_source_arn(invocation_context),
        )
        headers.update({"X-Amz-Target": invocation_context.headers.get("X-Amz-Target")})
        response = make_http_request(
            config.internal_service_url(), method="POST", headers=headers, data=payload
        )

        invocation_context.response = response

        self.response_templates.render(invocation_context)
        invocation_context.response.headers["Content-Length"] = str(len(response.content or ""))
        return invocation_context.response
