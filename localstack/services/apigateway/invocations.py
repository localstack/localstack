import json
import logging
from typing import Dict

from jsonschema import ValidationError, validate
from requests.models import Response
from werkzeug.exceptions import NotFound

from localstack.aws.connect import connect_to
from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway import helpers
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.services.apigateway.helpers import (
    EMPTY_MODEL,
    ModelResolver,
    extract_path_params,
    extract_query_string_params,
    get_apigateway_store,
    get_cors_response,
    make_error_response,
    select_integration_response,
)
from localstack.services.apigateway.integration import (
    ApiGatewayIntegrationError,
    DynamoDBIntegration,
    EventBridgeIntegration,
    HTTPIntegration,
    KinesisIntegration,
    LambdaIntegration,
    LambdaProxyIntegration,
    MockIntegration,
    S3Integration,
    SNSIntegration,
    SQSIntegration,
    StepFunctionIntegration,
)
from localstack.services.apigateway.models import ApiGatewayStore
from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)


class AuthorizationError(Exception):
    pass


class RequestValidator:
    __slots__ = ["context", "rest_api_container"]

    def __init__(self, context: ApiInvocationContext, store: ApiGatewayStore = None):
        self.context = context
        store = store or get_apigateway_store(
            account_id=context.account_id, region=context.region_name
        )
        if not (container := store.rest_apis.get(context.api_id)):
            # TODO: find the right exception
            raise NotFound()
        self.rest_api_container = container

    def is_request_valid(self) -> bool:
        # make all the positive checks first
        if self.context.resource is None or "resourceMethods" not in self.context.resource:
            return True

        resource_methods = self.context.resource["resourceMethods"]
        if self.context.method not in resource_methods and "ANY" not in resource_methods:
            return True

        # check if there is validator for the resource
        resource = resource_methods.get(self.context.method, resource_methods.get("ANY", {}))
        if not (resource.get("requestValidatorId") or "").strip():
            return True

        # check if there is a validator for this request
        validator = self.rest_api_container.validators.get(resource["requestValidatorId"])
        if not validator:
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
        # if there's no model to validate the body, use the Empty model
        # https://docs.aws.amazon.com/cdk/api/v1/docs/@aws-cdk_aws-apigateway.EmptyModel.html
        if not (request_models := resource.get("requestModels")):
            model_name = EMPTY_MODEL
        else:
            model_name = request_models.get(APPLICATION_JSON, EMPTY_MODEL)

        model_resolver = ModelResolver(
            rest_api_container=self.rest_api_container,
            model_name=model_name,
        )

        # try to get the resolved model first
        resolved_schema = model_resolver.get_resolved_model()
        if not resolved_schema:
            LOG.exception(
                "An exception occurred while trying to validate the request: could not find the model"
            )
            return False

        try:
            # if the body is empty, replace it with an empty JSON body
            validate(
                instance=json.loads(self.context.data or "{}"),
                schema=resolved_schema,
            )
            return True
        except ValidationError as e:
            LOG.warning("failed to validate request body %s", e)
            return False
        except json.JSONDecodeError as e:
            LOG.warning("failed to validate request body, request data is not valid JSON %s", e)
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
    region_name = invocation_context.region_name or aws_stack.get_region()
    client = connect_to(region_name=region_name).apigateway
    authorizers = client.get_authorizers(restApiId=invocation_context.api_id, limit=100).get(
        "items", []
    )
    for authorizer in authorizers:
        run_authorizer(invocation_context, authorizer)


def validate_api_key(api_key: str, invocation_context: ApiInvocationContext):

    usage_plan_ids = []
    client = connect_to(
        aws_access_key_id=invocation_context.account_id, region_name=invocation_context.region_name
    ).apigateway

    usage_plans = client.get_usage_plans()
    for item in usage_plans.get("items", []):
        api_stages = item.get("apiStages", [])
        for api_stage in api_stages:
            if (
                api_stage.get("stage") == invocation_context.stage
                and api_stage.get("apiId") == invocation_context.api_id
            ):
                usage_plan_ids.append(item.get("id"))

    for usage_plan_id in usage_plan_ids:
        usage_plan_keys = client.get_usage_plan_keys(usagePlanId=usage_plan_id)
        for key in usage_plan_keys.get("items", []):
            if key.get("value") == api_key:
                # check if the key is enabled
                api_key = client.get_api_key(apiKey=key.get("id"))
                return api_key.get("enabled") in ("true", True)

    return False


def is_api_key_valid(invocation_context: ApiInvocationContext) -> bool:
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-key-source.html
    client = connect_to(
        aws_access_key_id=invocation_context.account_id, region_name=invocation_context.region_name
    ).apigateway
    rest_api = client.get_rest_api(restApiId=invocation_context.api_id)

    if rest_api.get("apiKeySource") != "HEADER":
        # When the apiKeySource is set to AUTHORIZER, the authorizer is supposed to return the API key as a field
        # `usageIdentifierKey`
        # see https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
        # Authorizers are only mocked, so we can't validate the key. Return True in that case
        return True

    api_key = invocation_context.headers.get("X-API-Key")
    if not api_key:
        return False

    return validate_api_key(api_key, invocation_context)


def update_content_length(response: Response):
    if response and response.content is not None:
        response.headers["Content-Length"] = str(len(response.content))


def apply_response_parameters(invocation_context: ApiInvocationContext):
    response = invocation_context.response
    integration = invocation_context.integration

    int_responses = integration.get("integrationResponses") or {}
    if not int_responses:
        return response

    integration_type_orig = integration.get("type") or integration.get("integrationType") or ""
    integration_type = integration_type_orig.upper()
    if integration_type == "AWS_PROXY":
        LOG.warning("AWS_PROXY integration type should not apply response parameters")
        return response

    return_code = str(response.status_code)
    # Selecting the right integration response
    selected_integration_response = select_integration_response(return_code, invocation_context)
    # set status code of integration response
    response.status_code = selected_integration_response["statusCode"]
    response_params = selected_integration_response.get("responseParameters") or {}
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
    validator = RequestValidator(invocation_context)
    if not validator.is_request_valid():
        return make_error_response("Invalid request body", 400)

    api_key_required = resource.get("resourceMethods", {}).get(method, {}).get("apiKeyRequired")
    if api_key_required and not is_api_key_valid(invocation_context):
        return make_error_response("Access denied - invalid API key", 403)

    resource_methods = resource.get("resourceMethods", {})
    resource_method = resource_methods.get(method, {})
    if not resource_method:
        # HttpMethod: '*'
        # ResourcePath: '/*' - produces 'X-AMAZON-APIGATEWAY-ANY-METHOD'
        resource_method = resource_methods.get("ANY", {}) or resource_methods.get(
            "X-AMAZON-APIGATEWAY-ANY-METHOD", {}
        )
    method_integration = resource_method.get("methodIntegration")
    if not method_integration:
        if method == "OPTIONS" and "Origin" in headers:
            # default to returning CORS headers if this is an OPTIONS request
            return get_cors_response(headers)
        return make_error_response(
            "Unable to find integration for: %s %s (%s)" % (method, invocation_path, raw_path),
            404,
        )

    # update fields in invocation context, then forward request to next handler
    invocation_context.resource_path = extracted_path
    invocation_context.integration = method_integration

    return invoke_rest_api_integration(invocation_context)


def invoke_rest_api_integration(invocation_context: ApiInvocationContext):
    try:
        response = invoke_rest_api_integration_backend(invocation_context)
        # TODO remove this setter once all the integrations are migrated to the new response
        #  handling
        invocation_context.response = response
        response = apply_response_parameters(invocation_context)
        return response
    except ApiGatewayIntegrationError as e:
        LOG.warning(
            "Error while invoking integration for ApiGateway ID %s: %s",
            invocation_context.api_id,
            e,
            exc_info=LOG.isEnabledFor(logging.DEBUG),
        )
        return e.to_response()
    except Exception as e:
        msg = f"Error invoking integration for API Gateway ID '{invocation_context.api_id}': {e}"
        LOG.exception(msg)
        return make_error_response(msg, 400)


# This function is patched downstream for backend integrations that are only available
# in Pro (potentially to be replaced with a runtime hook in the future).
def invoke_rest_api_integration_backend(invocation_context: ApiInvocationContext):
    # define local aliases from invocation context
    invocation_path = invocation_context.path_with_query_string
    method = invocation_context.method
    headers = invocation_context.headers
    resource_path = invocation_context.resource_path
    integration = invocation_context.integration
    # extract integration type and path parameters
    relative_path, query_string_params = extract_query_string_params(path=invocation_path)
    integration_type_orig = integration.get("type") or integration.get("integrationType") or ""
    integration_type = integration_type_orig.upper()
    integration_method = integration.get("httpMethod")
    uri = integration.get("uri") or integration.get("integrationUri") or ""

    try:
        invocation_context.path_params = extract_path_params(
            path=relative_path, extracted_path=resource_path
        )
    except Exception:
        invocation_context.path_params = {}

    if (uri.startswith("arn:aws:apigateway:") and ":lambda:path" in uri) or uri.startswith(
        "arn:aws:lambda"
    ):
        if integration_type == "AWS_PROXY":
            return LambdaProxyIntegration().invoke(invocation_context)
        elif integration_type == "AWS":
            return LambdaIntegration().invoke(invocation_context)

    elif integration_type == "AWS":
        if "kinesis:action/" in uri:
            return KinesisIntegration().invoke(invocation_context)

        if "states:action/" in uri:
            return StepFunctionIntegration().invoke(invocation_context)

        if ":dynamodb:action" in uri:
            return DynamoDBIntegration().invoke(invocation_context)

        if "s3:path/" in uri or "s3:action/" in uri:
            return S3Integration().invoke(invocation_context)

        if integration_method == "POST" and ":sqs:path" in uri:
            return SQSIntegration().invoke(invocation_context)

        if method == "POST" and ":sns:path" in uri:
            return SNSIntegration().invoke(invocation_context)

        if (
            method == "POST"
            and uri.startswith("arn:aws:apigateway:")
            and "events:action/PutEvents" in uri
        ):
            return EventBridgeIntegration().invoke(invocation_context)

    elif integration_type in ["HTTP_PROXY", "HTTP"]:
        return HTTPIntegration().invoke(invocation_context)

    elif integration_type == "MOCK":
        return MockIntegration().invoke(invocation_context)

    if method == "OPTIONS":
        # fall back to returning CORS headers if this is an OPTIONS request
        return get_cors_response(headers)

    raise Exception(
        f'API Gateway integration type "{integration_type}", method "{method}", URI "{uri}" not yet implemented'
    )
