import json
import logging

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
    get_apigateway_store_for_invocation,
    get_cors_response,
    make_error_response,
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
from localstack.utils.aws.aws_responses import requests_response

LOG = logging.getLogger(__name__)


class AuthorizationError(Exception):
    message: str
    status_code: int

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def to_response(self):
        return requests_response({"message": self.message}, status_code=self.status_code)


# we separate those 2 exceptions to allow better GatewayResponse support later on
class BadRequestParameters(Exception):
    message: str

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def to_response(self):
        return requests_response({"message": self.message}, status_code=400)


class BadRequestBody(Exception):
    message: str

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def to_response(self):
        return requests_response({"message": self.message}, status_code=400)


class RequestValidator:
    __slots__ = ["context", "rest_api_container"]

    def __init__(self, context: ApiInvocationContext, store: ApiGatewayStore = None):
        self.context = context
        store = store or get_apigateway_store_for_invocation(context=context)
        if not (container := store.rest_apis.get(context.api_id)):
            # TODO: find the right exception
            raise NotFound()
        self.rest_api_container = container

    def validate_request(self) -> None:
        """
        :raises BadRequestParameters if the request has required parameters which are not present
        :raises BadRequestBody if the request has required body validation with a model and it does not respect it
        :return: None
        """
        # make all the positive checks first
        if self.context.resource is None or "resourceMethods" not in self.context.resource:
            return

        resource_methods = self.context.resource["resourceMethods"]
        if self.context.method not in resource_methods and "ANY" not in resource_methods:
            return

        # check if there is validator for the resource
        resource = resource_methods.get(self.context.method, resource_methods.get("ANY", {}))
        if not (resource.get("requestValidatorId") or "").strip():
            return

        # check if there is a validator for this request
        validator = self.rest_api_container.validators.get(resource["requestValidatorId"])
        if not validator:
            return

        if self.should_validate_request(validator) and (
            missing_parameters := self._get_missing_required_parameters(resource)
        ):
            message = f"Missing required request parameters: [{', '.join(missing_parameters)}]"
            raise BadRequestParameters(message=message)

        if self.should_validate_body(validator) and not self._is_body_valid(resource):
            raise BadRequestBody(message="Invalid request body")

        return

    def _is_body_valid(self, resource) -> bool:
        # if there's no model to validate the body, use the Empty model
        # https://docs.aws.amazon.com/cdk/api/v1/docs/@aws-cdk_aws-apigateway.EmptyModel.html
        if not (request_models := resource.get("requestModels")):
            model_name = EMPTY_MODEL
        else:
            model_name = request_models.get(
                APPLICATION_JSON, request_models.get("$default", EMPTY_MODEL)
            )

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

    def _get_missing_required_parameters(self, resource) -> list[str]:
        missing_params = []
        if not (request_parameters := resource.get("requestParameters")):
            return missing_params

        for request_parameter, required in sorted(request_parameters.items()):
            if not required:
                continue

            param_type, param_value = request_parameter.removeprefix("method.request.").split(".")
            match param_type:
                case "header":
                    is_missing = param_value not in self.context.headers
                case "path":
                    is_missing = param_value not in self.context.resource_path
                case "querystring":
                    is_missing = param_value not in self.context.query_params()
                case _:
                    # TODO: method.request.body is not specified in the documentation, and requestModels should do it
                    # verify this
                    is_missing = False

            if is_missing:
                missing_params.append(param_value)

        return missing_params

    @staticmethod
    def should_validate_body(validator):
        return validator["validateRequestBody"]

    @staticmethod
    def should_validate_request(validator):
        return validator.get("validateRequestParameters")


# ------------
# API METHODS
# ------------


def validate_api_key(api_key: str, invocation_context: ApiInvocationContext):
    usage_plan_ids = []
    client = connect_to(
        aws_access_key_id=invocation_context.account_id, region_name=invocation_context.region_name
    ).apigateway

    usage_plans = client.get_usage_plans()
    for item in usage_plans.get("items", []):
        api_stages = item.get("apiStages", [])
        usage_plan_ids.extend(
            item.get("id")
            for api_stage in api_stages
            if (
                api_stage.get("stage") == invocation_context.stage
                and api_stage.get("apiId") == invocation_context.api_id
            )
        )
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

    # The source of the API key for metering requests according to a usage plan.
    # Valid values are:
    # - HEADER to read the API key from the X-API-Key header of a request.
    # - AUTHORIZER to read the API key from the UsageIdentifierKey from a custom authorizer.

    api_key_source = rest_api.get("apiKeySource")
    match api_key_source:
        case "HEADER":
            api_key = invocation_context.headers.get("X-API-Key")
            return validate_api_key(api_key, invocation_context) if api_key else False
        case "AUTHORIZER":
            api_key = invocation_context.auth_identity.get("apiKey")
            return validate_api_key(api_key, invocation_context) if api_key else False


def update_content_length(response: Response):
    if response and response.content is not None:
        response.headers["Content-Length"] = str(len(response.content))


def invoke_rest_api_from_request(invocation_context: ApiInvocationContext):
    helpers.set_api_id_stage_invocation_path(invocation_context)
    try:
        return invoke_rest_api(invocation_context)
    except AuthorizationError as e:
        LOG.warning(
            "Authorization error while invoking API Gateway ID %s: %s",
            invocation_context.api_id,
            e,
            exc_info=LOG.isEnabledFor(logging.DEBUG),
        )
        return e.to_response()


def invoke_rest_api(invocation_context: ApiInvocationContext):
    invocation_path = invocation_context.path_with_query_string
    raw_path = invocation_context.path or invocation_path
    method = invocation_context.method
    headers = invocation_context.headers

    extracted_path, resource = helpers.get_target_resource_details(invocation_context)
    if not resource:
        return make_error_response("Unable to find path %s" % invocation_context.path, 404)

    # validate request
    validator = RequestValidator(invocation_context)
    try:
        validator.validate_request()
    except (BadRequestParameters, BadRequestBody) as e:
        return e.to_response()

    api_key_required = resource.get("resourceMethods", {}).get(method, {}).get("apiKeyRequired")
    if api_key_required and not is_api_key_valid(invocation_context):
        raise AuthorizationError("Forbidden", 403)

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
    method = invocation_context.method
    headers = invocation_context.headers
    integration = invocation_context.integration
    integration_type_orig = integration.get("type") or integration.get("integrationType") or ""
    integration_type = integration_type_orig.upper()
    integration_method = integration.get("httpMethod")
    uri = integration.get("uri") or integration.get("integrationUri") or ""

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
