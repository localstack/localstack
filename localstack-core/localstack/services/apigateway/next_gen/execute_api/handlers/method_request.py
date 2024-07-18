import json
import logging

from jsonschema import ValidationError, validate

from localstack.aws.api.apigateway import Method
from localstack.constants import APPLICATION_JSON
from localstack.http import Response
from localstack.services.apigateway.helpers import EMPTY_MODEL, ModelResolver
from localstack.services.apigateway.models import RestApiContainer

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import InvocationRequest, RestApiInvocationContext
from ..gateway_response import BadRequestBodyError, BadRequestParametersError

LOG = logging.getLogger(__name__)


class MethodRequestHandler(RestApiGatewayHandler):
    """
    This class will mostly take care of Request validation with Models
    See https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings-method-request.html
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        self.validate_request(
            context.resource_method,
            context.deployment.rest_api,
            context.invocation_request,
        )

    def validate_request(
        self, method: Method, rest_api: RestApiContainer, request: InvocationRequest
    ) -> None:
        """
        :raises BadRequestParametersError if the request has required parameters which are not present
        :raises BadRequestBodyError if the request has required body validation with a model and it does not respect it
        :return: None
        """

        # check if there is validator for the method
        if not (request_validator_id := method.get("requestValidatorId") or "").strip():
            return

        # check if there is a validator for this request
        if not (validator := rest_api.validators.get(request_validator_id)):
            # TODO Should we raise an exception instead?
            LOG.exception("No validator were found with matching id: '%s'", request_validator_id)
            return

        if self.should_validate_request(validator) and (
            missing_parameters := self._get_missing_required_parameters(method, request)
        ):
            message = f"Missing required request parameters: [{', '.join(missing_parameters)}]"
            raise BadRequestParametersError(message=message)

        if self.should_validate_body(validator) and not self._is_body_valid(
            method, rest_api, request
        ):
            raise BadRequestBodyError(message="Invalid request body")

        return

    @staticmethod
    def _is_body_valid(
        method: Method, rest_api: RestApiContainer, request: InvocationRequest
    ) -> bool:
        # if there's no model to validate the body, use the Empty model
        # https://docs.aws.amazon.com/cdk/api/v1/docs/@aws-cdk_aws-apigateway.EmptyModel.html
        if not (request_models := method.get("requestModels")):
            model_name = EMPTY_MODEL
        else:
            model_name = request_models.get(
                APPLICATION_JSON, request_models.get("$default", EMPTY_MODEL)
            )

        model_resolver = ModelResolver(
            rest_api_container=rest_api,
            model_name=model_name,
        )

        # try to get the resolved model first
        resolved_schema = model_resolver.get_resolved_model()
        if not resolved_schema:
            LOG.exception(
                "An exception occurred while trying to validate the request: could not resolve the model '%s'",
                model_name,
            )
            return False

        try:
            # if the body is empty, replace it with an empty JSON body
            validate(
                instance=json.loads(request.get("body") or "{}"),
                schema=resolved_schema,
            )
            return True
        except ValidationError as e:
            LOG.debug("failed to validate request body %s", e)
            return False
        except json.JSONDecodeError as e:
            LOG.debug("failed to validate request body, request data is not valid JSON %s", e)
            return False

    @staticmethod
    def _get_missing_required_parameters(method: Method, request: InvocationRequest) -> list[str]:
        missing_params = []
        if not (request_parameters := method.get("requestParameters")):
            return missing_params

        case_sensitive_headers = list(request.get("headers").keys())

        for request_parameter, required in sorted(request_parameters.items()):
            if not required:
                continue

            param_type, param_value = request_parameter.removeprefix("method.request.").split(".")
            match param_type:
                case "header":
                    is_missing = param_value not in case_sensitive_headers
                case "path":
                    path = request.get("path_parameters", "")
                    is_missing = param_value not in path
                case "querystring":
                    is_missing = param_value not in request.get("query_string_parameters", [])
                case _:
                    # This shouldn't happen
                    LOG.debug("Found an invalid request parameter: %s", request_parameter)
                    is_missing = False

            if is_missing:
                missing_params.append(param_value)

        return missing_params

    @staticmethod
    def should_validate_body(validator):
        return validator.get("validateRequestBody")

    @staticmethod
    def should_validate_request(validator):
        return validator.get("validateRequestParameters")
