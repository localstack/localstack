import base64
import json
import logging
import re
from typing import Any, Dict, Union
from urllib.parse import urljoin

import requests
from flask import Response as FlaskResponse
from jsonschema import ValidationError, validate
from requests.models import Response

from localstack import config
from localstack.constants import (
    APPLICATION_JSON,
    HEADER_LOCALSTACK_AUTHORIZATION,
    TEST_AWS_ACCOUNT_ID,
)
from localstack.services.apigateway import helpers
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import (
    extract_path_params,
    extract_query_string_params,
    get_cors_response,
    make_error_response,
)
from localstack.services.apigateway.integration import (
    RequestTemplates,
    ResponseTemplates,
    SnsIntegration,
    VtlTemplate,
)
from localstack.services.awslambda import lambda_api
from localstack.services.kinesis import kinesis_listener
from localstack.services.stepfunctions.stepfunctions_utils import await_sfn_execution_result
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import (
    LambdaResponse,
    flask_to_requests_response,
    request_response_stream,
    requests_response,
)
from localstack.utils.common import camel_to_snake_case, json_safe, to_bytes, to_str

# set up logger
from localstack.utils.http import add_query_params_to_url

LOG = logging.getLogger(__name__)

# target ARN patterns
TARGET_REGEX_PATH_S3_URI = (
    r"^arn:aws:apigateway:[a-zA-Z0-9\-]+:s3:path/(?P<bucket>[^/]+)/(?P<object>.+)$"
)
TARGET_REGEX_ACTION_S3_URI = r"^arn:aws:apigateway:[a-zA-Z0-9\-]+:s3:action/(?:GetObject&Bucket\=(?P<bucket>[^&]+)&Key\=(?P<object>.+))$"

# TODO: refactor / split up this file into suitable submodules


class AuthorizationError(Exception):
    pass


class RequestValidator:
    __slots__ = ["context", "apigateway_client"]

    def __init__(self, context: ApiInvocationContext, apigateway_client):
        self.context = context
        self.apigateway_client = apigateway_client

    def is_request_valid(self) -> bool:
        # make all the positive checks first
        if self.context.resource is None or "resourceMethods" not in self.context.resource:
            return True

        resource_methods = self.context.resource["resourceMethods"]
        if self.context.method not in resource_methods:
            return True

        # check if there is validator for the resource
        resource = resource_methods[self.context.method]
        if not (resource.get("requestValidatorId") or "").strip():
            return True

        # check if there is a validator for this request
        validator = self.apigateway_client.get_request_validator(
            restApiId=self.context.api_id, requestValidatorId=resource["requestValidatorId"]
        )
        if validator is None:
            return True

        # are we validating the body?
        if self.should_validate_body(validator):
            is_body_valid = self.validate_body(resource)
            if not is_body_valid:
                return is_body_valid

        if self.should_validate_request(validator):
            is_valid_parameters = self.validate_parameters_and_headers(resource)
            if not is_valid_parameters:
                return is_valid_parameters

        return True

    def validate_body(self, resource):
        # we need a model to validate the body
        if "requestModels" not in resource or not resource["requestModels"]:
            return False

        schema_name = resource["requestModels"].get(APPLICATION_JSON)
        model = self.apigateway_client.get_model(
            restApiId=self.context.api_id,
            modelName=schema_name,
        )
        if not model:
            return False

        try:
            validate(instance=json.loads(self.context.data), schema=json.loads(model["schema"]))
            return True
        except ValidationError as e:
            LOG.warning("failed to validate request body", e)
            return False

    # TODO implement parameters and headers
    def validate_parameters_and_headers(self, resource):
        return True

    @staticmethod
    def should_validate_body(validator):
        return validator["validateRequestBody"]

    @staticmethod
    def should_validate_request(validator):
        return validator.get("validateRequestParameters")


# ------------
# API METHODS
# ------------


def run_authorizer(invocation_context: ApiInvocationContext, authorizer: Dict):
    # TODO implement authorizers
    pass


def authorize_invocation(invocation_context: ApiInvocationContext):
    client = aws_stack.connect_to_service("apigateway")
    authorizers = client.get_authorizers(restApiId=invocation_context.api_id, limit=100).get(
        "items", []
    )
    for authorizer in authorizers:
        run_authorizer(invocation_context, authorizer)


def validate_api_key(api_key: str, stage: str):

    usage_plan_ids = []

    client = aws_stack.connect_to_service("apigateway")
    usage_plans = client.get_usage_plans()
    for item in usage_plans.get("items", []):
        api_stages = item.get("apiStages", [])
        usage_plan_ids.extend(
            item.get("id") for api_stage in api_stages if api_stage.get("stage") == stage
        )

    for usage_plan_id in usage_plan_ids:
        usage_plan_keys = client.get_usage_plan_keys(usagePlanId=usage_plan_id)
        for key in usage_plan_keys.get("items", []):
            if key.get("value") == api_key:
                return True

    return False


def is_api_key_valid(is_api_key_required: bool, headers: Dict[str, str], stage: str):
    if not is_api_key_required:
        return True

    api_key = headers.get("X-API-Key")
    if not api_key:
        return False

    return validate_api_key(api_key, stage)


def update_content_length(response: Response):
    if response and response.content is not None:
        response.headers["Content-Length"] = str(len(response.content))


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


def apply_response_parameters(invocation_context: ApiInvocationContext):
    response = invocation_context.response
    integration = invocation_context.integration

    int_responses = integration.get("integrationResponses") or {}
    if not int_responses:
        return response
    entries = list(int_responses.keys())
    return_code = str(response.status_code)
    if return_code not in entries:
        if len(entries) > 1:
            LOG.info("Found multiple integration response status codes: %s", entries)
            return response
        return_code = entries[0]
    response_params = int_responses[return_code].get("responseParameters", {})
    for key, value in response_params.items():
        # TODO: add support for method.response.body, etc ...
        if str(key).lower().startswith("method.response.header."):
            header_name = key[len("method.response.header.") :]
            response.headers[header_name] = value.strip("'")
    return response


def invoke_rest_api_from_request(invocation_context: ApiInvocationContext):
    helpers.set_api_id_stage_invocation_path(invocation_context)
    try:
        return invoke_rest_api(invocation_context)
    except AuthorizationError as e:
        api_id = invocation_context.api_id
        return make_error_response("Not authorized to invoke REST API %s: %s" % (api_id, e), 403)


def invoke_rest_api(invocation_context: ApiInvocationContext):
    invocation_path = invocation_context.path_with_query_string
    raw_path = invocation_context.path or invocation_path
    method = invocation_context.method
    headers = invocation_context.headers

    # run gateway authorizers for this request
    authorize_invocation(invocation_context)

    extracted_path, resource = helpers.get_target_resource_details(invocation_context)
    if not resource:
        return make_error_response("Unable to find path %s" % invocation_context.path, 404)

    # validate request
    validator = RequestValidator(invocation_context, aws_stack.connect_to_service("apigateway"))
    if not validator.is_request_valid():
        return make_error_response("Invalid request body", 400)

    api_key_required = resource.get("resourceMethods", {}).get(method, {}).get("apiKeyRequired")
    if not is_api_key_valid(api_key_required, headers, invocation_context.stage):
        return make_error_response("Access denied - invalid API key", 403)

    integrations = resource.get("resourceMethods", {})
    integration = integrations.get(method, {})
    if not integration:
        # HttpMethod: '*'
        # ResourcePath: '/*' - produces 'X-AMAZON-APIGATEWAY-ANY-METHOD'
        integration = integrations.get("ANY", {}) or integrations.get(
            "X-AMAZON-APIGATEWAY-ANY-METHOD", {}
        )
    integration = integration.get("methodIntegration")
    if not integration:
        if method == "OPTIONS" and "Origin" in headers:
            # default to returning CORS headers if this is an OPTIONS request
            return get_cors_response(headers)
        return make_error_response(
            "Unable to find integration for: %s %s (%s)" % (method, invocation_path, raw_path),
            404,
        )

    res_methods = resource.get("resourceMethods", {})
    meth_integration = res_methods.get(method, {}).get("methodIntegration", {})
    int_responses = meth_integration.get("integrationResponses", {})
    response_templates = int_responses.get("200", {}).get("responseTemplates", {})

    # update fields in invocation context, then forward request to next handler
    invocation_context.resource = resource
    invocation_context.resource_path = extracted_path
    invocation_context.response_templates = response_templates
    invocation_context.integration = integration

    return invoke_rest_api_integration(invocation_context)


def invoke_rest_api_integration(invocation_context: ApiInvocationContext):
    try:
        response = invoke_rest_api_integration_backend(invocation_context)
        # TODO remove this setter once all the integrations are migrated to the new response
        #  handling
        invocation_context.response = response
        response = apply_response_parameters(invocation_context)
        return response
    except Exception as e:
        msg = f"Error invoking integration for API Gateway ID '{invocation_context.api_id}': {e}"
        LOG.exception(msg)
        return make_error_response(msg, 400)


# TODO: refactor this to have a class per integration type to make it easy to
# test the encapsulated logic
def invoke_rest_api_integration_backend(invocation_context: ApiInvocationContext):
    # define local aliases from invocation context
    invocation_path = invocation_context.path_with_query_string
    method = invocation_context.method
    data = invocation_context.data
    headers = invocation_context.headers
    api_id = invocation_context.api_id
    stage = invocation_context.stage
    resource_path = invocation_context.resource_path
    response_templates = invocation_context.response_templates
    integration = invocation_context.integration

    # extract integration type and path parameters
    relative_path, query_string_params = extract_query_string_params(path=invocation_path)
    integration_type_orig = integration.get("type") or integration.get("integrationType") or ""
    integration_type = integration_type_orig.upper()
    uri = integration.get("uri") or integration.get("integrationUri") or ""
    # XXX we need replace the internal Authorization header with an Authorization header set from
    # the customer, even if it's empty that's what's expected in the integration.
    custom_auth_header = invocation_context.headers.pop(HEADER_LOCALSTACK_AUTHORIZATION, "")
    invocation_context.headers["Authorization"] = custom_auth_header

    try:
        path_params = extract_path_params(path=relative_path, extracted_path=resource_path)
        invocation_context.path_params = path_params
    except Exception:
        path_params = {}

    if (uri.startswith("arn:aws:apigateway:") and ":lambda:path" in uri) or uri.startswith(
        "arn:aws:lambda"
    ):
        if integration_type in ["AWS", "AWS_PROXY"]:
            func_arn = uri
            if ":lambda:path" in uri:
                func_arn = (
                    uri.split(":lambda:path")[1].split("functions/")[1].split("/invocations")[0]
                )

            invocation_context.context = helpers.get_event_request_context(invocation_context)
            invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)
            if invocation_context.authorizer_type:
                authorizer_context = {
                    invocation_context.authorizer_type: invocation_context.auth_context
                }
                invocation_context.context["authorizer"] = authorizer_context

            request_templates = RequestTemplates()
            payload = request_templates.render(invocation_context)

            # TODO: change this signature to InvocationContext as well!
            result = lambda_api.process_apigateway_invocation(
                func_arn,
                relative_path,
                payload,
                stage,
                api_id,
                headers,
                is_base64_encoded=invocation_context.is_data_base64_encoded,
                path_params=path_params,
                query_string_params=query_string_params,
                method=method,
                resource_path=resource_path,
                request_context=invocation_context.context,
                stage_variables=invocation_context.stage_variables,
            )

            if isinstance(result, FlaskResponse):
                response = flask_to_requests_response(result)
            elif isinstance(result, Response):
                response = result
            else:
                response = LambdaResponse()
                parsed_result = (
                    result if isinstance(result, dict) else json.loads(str(result or "{}"))
                )
                parsed_result = common.json_safe(parsed_result)
                parsed_result = {} if parsed_result is None else parsed_result
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
                update_content_length(response)
                response.multi_value_headers = parsed_result.get("multiValueHeaders") or {}

            # apply custom response template
            invocation_context.response = response

            response_templates = ResponseTemplates()
            response_templates.render(invocation_context)
            invocation_context.response.headers["Content-Length"] = str(len(response.content or ""))
            return invocation_context.response

        raise Exception(
            f'API Gateway integration type "{integration_type}", action "{uri}", method "{method}"'
        )

    elif integration_type == "AWS":
        if "kinesis:action/" in uri:
            if uri.endswith("kinesis:action/PutRecord"):
                target = kinesis_listener.ACTION_PUT_RECORD
            elif uri.endswith("kinesis:action/PutRecords"):
                target = kinesis_listener.ACTION_PUT_RECORDS
            elif uri.endswith("kinesis:action/ListStreams"):
                target = kinesis_listener.ACTION_LIST_STREAMS
            else:
                LOG.info(
                    f"Unexpected API Gateway integration URI '{uri}' for integration type {integration_type}",
                )
                target = ""

            try:
                invocation_context.context = helpers.get_event_request_context(invocation_context)
                invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)
                request_templates = RequestTemplates()
                payload = request_templates.render(invocation_context)

            except Exception as e:
                LOG.warning("Unable to convert API Gateway payload to str", e)
                raise

            # forward records to target kinesis stream
            headers = aws_stack.mock_aws_request_headers(
                service="kinesis", region_name=invocation_context.region_name
            )
            headers["X-Amz-Target"] = target

            result = common.make_http_request(
                url=config.service_url("kineses"), data=payload, headers=headers, method="POST"
            )

            # apply response template
            invocation_context.response = result
            response_templates = ResponseTemplates()
            response_templates.render(invocation_context)
            return invocation_context.response

        elif "states:action/" in uri:
            action = uri.split("/")[-1]

            if APPLICATION_JSON in integration.get("requestTemplates", {}):
                request_templates = RequestTemplates()
                payload = request_templates.render(invocation_context)
                payload = json.loads(payload)
            else:
                # XXX decoding in py3 sounds wrong, this actually might break
                payload = json.loads(data.decode("utf-8"))
            client = aws_stack.connect_to_service("stepfunctions")

            if isinstance(payload.get("input"), dict):
                payload["input"] = json.dumps(payload["input"])

            # Hot fix since step functions local package responses: Unsupported Operation: 'StartSyncExecution'
            method_name = (
                camel_to_snake_case(action) if action != "StartSyncExecution" else "start_execution"
            )

            try:
                method = getattr(client, method_name)
            except AttributeError:
                msg = "Invalid step function action: %s" % method_name
                LOG.error(msg)
                return make_error_response(msg, 400)

            result = method(**payload)
            result = json_safe({k: result[k] for k in result if k not in "ResponseMetadata"})
            response = requests_response(
                content=result,
                headers=aws_stack.mock_aws_request_headers(),
            )

            if action == "StartSyncExecution":
                # poll for the execution result and return it
                result = await_sfn_execution_result(result["executionArn"])
                result_status = result.get("status")
                if result_status != "SUCCEEDED":
                    return make_error_response(
                        "StepFunctions execution %s failed with status '%s'"
                        % (result["executionArn"], result_status),
                        500,
                    )
                result = json_safe(result)
                response = requests_response(content=result)

            # apply response templates
            invocation_context.response = response
            response_templates = ResponseTemplates()
            response_templates.render(invocation_context)
            # response = apply_request_response_templates(
            #     response, response_templates, content_type=APPLICATION_JSON
            # )
            return response
        # https://docs.aws.amazon.com/apigateway/api-reference/resource/integration/
        elif ("s3:path/" in uri or "s3:action/" in uri) and method == "GET":
            s3 = aws_stack.connect_to_service("s3")
            uri = apply_request_parameters(
                uri,
                integration=integration,
                path_params=path_params,
                query_params=query_string_params,
            )
            uri_match = re.match(TARGET_REGEX_PATH_S3_URI, uri) or re.match(
                TARGET_REGEX_ACTION_S3_URI, uri
            )
            if uri_match:
                bucket, object_key = uri_match.group("bucket", "object")
                LOG.debug("Getting request for bucket %s object %s", bucket, object_key)
                try:
                    object = s3.get_object(Bucket=bucket, Key=object_key)
                except s3.exceptions.NoSuchKey:
                    msg = "Object %s not found" % object_key
                    LOG.debug(msg)
                    return make_error_response(msg, 404)

                headers = aws_stack.mock_aws_request_headers(service="s3")

                if object.get("ContentType"):
                    headers["Content-Type"] = object["ContentType"]

                # stream used so large files do not fill memory
                response = request_response_stream(stream=object["Body"], headers=headers)
                return response
            else:
                msg = "Request URI does not match s3 specifications"
                LOG.warning(msg)
                return make_error_response(msg, 400)

        if method == "POST":
            if uri.startswith("arn:aws:apigateway:") and ":sqs:path" in uri:
                template = integration["requestTemplates"][APPLICATION_JSON]
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
                headers = aws_stack.mock_aws_request_headers(service="sqs", region_name=region_name)

                url = urljoin(config.service_url("sqs"), f"{TEST_AWS_ACCOUNT_ID}/{queue}")
                result = common.make_http_request(
                    url, method="POST", headers=headers, data=new_request
                )
                return result
            elif uri.startswith("arn:aws:apigateway:") and ":sns:path" in uri:
                invocation_context.context = helpers.get_event_request_context(invocation_context)
                invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)

                integration_response = SnsIntegration().invoke(invocation_context)
                return apply_request_response_templates(
                    integration_response, response_templates, content_type=APPLICATION_JSON
                )

        raise Exception(
            'API Gateway AWS integration action URI "%s", method "%s" not yet implemented'
            % (uri, method)
        )

    elif integration_type == "AWS_PROXY":
        if uri.startswith("arn:aws:apigateway:") and ":dynamodb:action" in uri:
            # arn:aws:apigateway:us-east-1:dynamodb:action/PutItem&Table=MusicCollection
            table_name = uri.split(":dynamodb:action")[1].split("&Table=")[1]
            action = uri.split(":dynamodb:action")[1].split("&Table=")[0]

            if "PutItem" in action and method == "PUT":
                response_template = response_templates.get("application/json")

                if response_template is None:
                    msg = "Invalid response template defined in integration response."
                    LOG.info("%s Existing: %s", msg, response_templates)
                    return make_error_response(msg, 404)

                response_template = json.loads(response_template)
                if response_template["TableName"] != table_name:
                    msg = "Invalid table name specified in integration response template."
                    return make_error_response(msg, 404)

                dynamo_client = aws_stack.connect_to_resource("dynamodb")
                table = dynamo_client.Table(table_name)

                event_data = {}
                data_dict = json.loads(data)
                for key, _ in response_template["Item"].items():
                    event_data[key] = data_dict[key]

                table.put_item(Item=event_data)
                response = requests_response(event_data)
                return response
        else:
            raise Exception(
                'API Gateway action uri "%s", integration type %s not yet implemented'
                % (uri, integration_type)
            )

    elif integration_type in ["HTTP_PROXY", "HTTP"]:

        if ":servicediscovery:" in uri:
            # check if this is a servicediscovery integration URI
            client = aws_stack.connect_to_service("servicediscovery")
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

        uri = apply_request_parameters(
            uri, integration=integration, path_params=path_params, query_params=query_string_params
        )
        result = requests.request(method=method, url=uri, data=payload, headers=headers)
        # apply custom response template
        invocation_context.response = result
        response_templates = ResponseTemplates()
        response_templates.render(invocation_context)
        return invocation_context.response

    elif integration_type == "MOCK":

        # TODO: apply tell don't ask principle inside ResponseTemplates or InvocationContext
        invocation_context.stage_variables = helpers.get_stage_variables(invocation_context)
        invocation_context.response = requests_response({})

        response_templates = ResponseTemplates()
        response_templates.render(invocation_context)

        return invocation_context.response

    if method == "OPTIONS":
        # fall back to returning CORS headers if this is an OPTIONS request
        return get_cors_response(headers)

    raise Exception(
        'API Gateway integration type "%s", method "%s", URI "%s" not yet implemented'
        % (integration_type, method, uri)
    )


def apply_request_response_templates(
    data: Union[Response, bytes],
    templates: Dict[str, str],
    content_type: str = None,
    as_json: bool = False,
):
    """Apply the matching request/response template (if it exists) to the payload data and return the result"""

    content_type = content_type or APPLICATION_JSON
    is_response = isinstance(data, Response)
    templates = templates or {}
    template = templates.get(content_type)
    if not template:
        return data
    content = (data.content if is_response else data) or ""
    result = VtlTemplate().render_vtl(template, content, as_json=as_json)
    if is_response:
        data._content = result
        update_content_length(data)
        return data
    return result
