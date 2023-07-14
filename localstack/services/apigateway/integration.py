import base64
import json
import logging
import re
from abc import ABC, abstractmethod
from functools import lru_cache
from http import HTTPStatus
from typing import Any, Dict
from urllib.parse import urljoin

import requests
from botocore.exceptions import ClientError
from moto.apigatewayv2.exceptions import BadRequestException
from requests import Response

from localstack import config
from localstack.aws.accounts import get_aws_account_id
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
from localstack.utils.aws import aws_stack
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.aws.aws_responses import (
    LambdaResponse,
    request_response_stream,
    requests_response,
)
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.aws.templating import VtlTemplate
from localstack.utils.collections import dict_multi_values, remove_attributes
from localstack.utils.common import make_http_request, to_str
from localstack.utils.http import add_query_params_to_url, canonicalize_headers, parse_request_data
from localstack.utils.json import json_safe
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
    service_name: str, region_name: str, source_arn: str, role_arn: str | None
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
    headers = aws_stack.mock_aws_request_headers(
        service=service_name, region_name=region_name, access_key=access_key_id
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
    region_name = extract_region_from_arn(function_arn)
    clients = get_service_factory(
        region_name=region_name, role_arn=invocation_context.integration.get("credentials")
    )
    inv_result = clients.awslambda.request_metadata(
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

        keys = parsed_result.keys()
        if "statusCode" not in keys or "body" not in keys:
            LOG.warning(
                'Lambda output should follow the next JSON format: { "isBase64Encoded": true|false, "statusCode": httpStatusCode, "headers": { "headerName": "headerValue", ... },"body": "..."}'
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

    @classmethod
    def construct_invocation_event(
        cls, method, path, headers, data, query_string_params=None, is_base64_encoded=False
    ):
        query_string_params = query_string_params or parse_request_data(method, path, "")

        single_value_query_string_params = {
            k: v[-1] if isinstance(v, list) else v for k, v in query_string_params.items()
        }
        # AWS canonical header names, converting them to lower-case
        headers = canonicalize_headers(headers)
        return {
            "path": path,
            "headers": dict(headers),
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

        keys = parsed_result.keys()

        if not ("statusCode" in keys and "body" in keys):
            LOG.warning(
                'Lambda output should follow the next JSON format: { "isBase64Encoded": true|false, "statusCode": httpStatusCode, "headers": { "headerName": "headerValue", ... },"body": "..."}'
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

        self.response_templates.render(invocation_context)
        return invocation_context.response


class LambdaIntegration(BackendIntegration):
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

    def invoke(self, invocation_context: ApiInvocationContext):
        headers = helpers.create_invocation_headers(invocation_context)
        invocation_context.context = helpers.get_event_request_context(invocation_context)
        invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)
        if invocation_context.authorizer_type:
            invocation_context.context["authorizer"] = invocation_context.authorizer_result

        func_arn = self._lambda_integration_uri(invocation_context)
        event = self.request_templates.render(invocation_context) or b""
        asynchronous = headers.get("X-Amz-Invocation-Type", "").strip("'") == "Event"
        try:
            result = call_lambda(
                function_arn=func_arn,
                event=to_bytes(event),
                asynchronous=asynchronous,
                invocation_context=invocation_context,
            )
        except ClientError as e:
            raise IntegrationAccessError() from e

        response = LambdaResponse()

        if asynchronous:
            response._content = ""
        else:
            # depending on the lambda executor sometimes it returns a string and sometimes a dict
            match result:
                case str():
                    # try to parse the result as json, if it succeeds we assume it's a valid
                    # json string, and we don't do anything.
                    if isinstance(json.loads(result or "{}"), dict):
                        parsed_result = result
                    else:
                        # the docker executor returns a string wrapping a json string,
                        # so we need to remove the outer string
                        parsed_result = json.loads(result or "{}")
                case _:
                    parsed_result = json.loads(str(result or "{}"))
            parsed_result = common.json_safe(parsed_result)
            parsed_result = {} if parsed_result is None else parsed_result
            response._content = parsed_result

        response.status_code = 200
        # apply custom response template
        invocation_context.response = response

        self.response_templates.render(invocation_context)
        invocation_context.response.headers["Content-Length"] = str(len(response.content or ""))
        return invocation_context.response


class KinesisIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        integration = invocation_context.integration
        integration_type_orig = integration.get("type") or integration.get("integrationType") or ""
        integration_type = integration_type_orig.upper()
        uri = integration.get("uri") or integration.get("integrationUri") or ""

        if uri.endswith("kinesis:action/PutRecord"):
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
            # want to refactor this into a model class
            invocation_context.context = helpers.get_event_request_context(invocation_context)
            invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)

            # integration type "AWS" is only supported for WebSocket APIs and REST
            # API (v1), but the template selection expression is only supported for
            # Websockets
            template_key = None
            if invocation_context.is_websocket_request():
                template_key = invocation_context.integration.get(
                    "TemplateSelectionExpression", "$default"
                )
                payload = self.request_templates.render(invocation_context, template_key)
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
            url=config.service_url("kinesis"), data=payload, headers=headers, method="POST"
        )

        # apply response template
        invocation_context.response = result
        self.response_templates.render(invocation_context)
        return invocation_context.response


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
        try:
            object = s3.get_object(Bucket=bucket, Key=object_key)
        except s3.exceptions.NoSuchKey:
            msg = f"Object {object_key} not found"
            LOG.debug(msg)
            return make_error_response(msg, 404)

        headers = aws_stack.mock_aws_request_headers(service="s3")

        if object.get("ContentType"):
            headers["Content-Type"] = object["ContentType"]

        # stream used so large files do not fill memory
        response = request_response_stream(stream=object["Body"], headers=headers)
        return response


class HTTPIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        invocation_path = invocation_context.path_with_query_string
        integration = invocation_context.integration
        path_params = invocation_context.path_params
        method = invocation_context.method
        headers = invocation_context.headers
        relative_path, query_string_params = extract_query_string_params(path=invocation_path)
        uri = integration.get("uri") or integration.get("integrationUri") or ""

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
        request_templates = RequestTemplates()
        payload = request_templates.render(invocation_context)

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
        # apply custom response template
        invocation_context.response = result
        response_templates = ResponseTemplates()
        response_templates.render(invocation_context)
        return invocation_context.response


class SQSIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext):
        integration = invocation_context.integration
        uri = integration.get("uri") or integration.get("integrationUri") or ""

        template = integration["requestTemplates"].get(APPLICATION_JSON)
        account_id, queue = uri.split("/")[-2:]
        region_name = uri.split(":")[3]
        if "GetQueueUrl" in template or "CreateQueue" in template:
            request_templates = RequestTemplates()
            payload = request_templates.render(invocation_context)
            new_request = f"{payload}&QueueName={queue}"
        else:
            request_templates = RequestTemplates()
            payload = request_templates.render(invocation_context)
            queue_url = f"{config.get_edge_url()}/{account_id}/{queue}"
            new_request = f"{payload}&QueueUrl={queue_url}"

        # forward records to target kinesis stream
        headers = get_internal_mocked_headers(
            service_name="sqs",
            region_name=region_name,
            role_arn=invocation_context.integration.get("credentials"),
            source_arn=get_source_arn(invocation_context),
        )

        url = urljoin(config.service_url("sqs"), f"{get_aws_account_id()}/{queue}")
        result = common.make_http_request(url, method="POST", headers=headers, data=new_request)
        return result


class SNSIntegration(BackendIntegration):
    def invoke(self, invocation_context: ApiInvocationContext) -> Response:
        # TODO: check if the logic below is accurate - cover with snapshot tests!
        invocation_context.context = get_event_request_context(invocation_context)
        invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)
        integration = invocation_context.integration
        uri = integration.get("uri") or integration.get("integrationUri") or ""

        try:
            payload = self.request_templates.render(invocation_context)
        except Exception as e:
            LOG.warning("Failed to apply template for SNS integration", e)
            raise
        region_name = uri.split(":")[3]
        headers = aws_stack.mock_aws_request_headers(service="sns", region_name=region_name)
        result = make_http_request(
            config.service_url("sns"), method="POST", headers=headers, data=payload
        )
        return self.apply_response_parameters(invocation_context, result)


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

        client = connect_to().stepfunctions
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
            HTTPStatus.OK.value, aws_stack.mock_aws_request_headers(), data=result
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
            config.service_url("events"), method="POST", headers=headers, data=payload
        )

        invocation_context.response = response

        response_templates = ResponseTemplates()
        response_templates.render(invocation_context)
        invocation_context.response.headers["Content-Length"] = str(len(response.content or ""))
        return invocation_context.response
