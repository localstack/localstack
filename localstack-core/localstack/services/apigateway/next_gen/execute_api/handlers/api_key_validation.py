import logging
from typing import Optional

from localstack.aws.api.apigateway import ApiKey, ApiKeySourceType, RestApi
from localstack.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import IdentityContext, InvocationRequest, RestApiInvocationContext
from ..gateway_response import InvalidAPIKeyError
from ..moto_helpers import get_api_key, get_usage_plan_keys, get_usage_plans

LOG = logging.getLogger(__name__)


class ApiKeyValidationHandler(RestApiGatewayHandler):
    """
    Handles Api key validation.
    If an api key is required, we will validate that a usage plan associated with that stage
    has a usage plan key with the corresponding value.
    """

    # TODO We currently do not support rate limiting or quota limit. As such we are not raising any related Exception

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        method = context.resource_method

        # If api key is not required by the method, we can exit the handler
        if not method.get("apiKeyRequired"):
            return

        identity = context.context_variables["identity"]
        request = context.invocation_request
        rest_api = context.deployment.rest_api.rest_api

        # Look for the api key value in the request. If it is not found, raise an exception
        if not (api_key_value := self.get_request_api_key(rest_api, request, identity)):
            LOG.debug("API Key is empty")
            raise InvalidAPIKeyError("Forbidden")

        # Get the validated key, if no key is found, raise an exception
        if not (validated_key := self.get_validated_key(api_key_value, context)):
            LOG.debug("Provided API Key is not valid")
            raise InvalidAPIKeyError("Forbidden")

        # Update context's identity with the key value and Id
        if not identity["apikey"]:
            LOG.debug("Updating $context.identity.apiKey='%s'", validated_key["value"])
            identity["apiKey"] = validated_key["value"]

        LOG.debug("Updating $context.identity.apiKeyId='%s'", validated_key["id"])
        identity["apiKeyId"] = validated_key["id"]

    def validate_api_key(
        self, api_key_value, context: RestApiInvocationContext
    ) -> Optional[ApiKey]:
        api_id = context.api_id
        stage = context.stage
        account_id = context.account_id
        region = context.region

        # Get usage plans from the store
        usage_plans = get_usage_plans(account_id=account_id, region_name=region)

        # Loop through usage plans and keep ids of the plans associated with the deployment stage
        usage_plan_ids = []
        for usage_plan in usage_plans:
            api_stages = usage_plan.get("apiStages", [])
            usage_plan_ids.extend(
                usage_plan.get("id")
                for api_stage in api_stages
                if (api_stage.get("stage") == stage and api_stage.get("apiId") == api_id)
            )
        if not usage_plan_ids:
            LOG.debug("No associated usage plans found stage '%s'", stage)
            return

        # Loop through plans with an association with the stage find a key with matching value
        for usage_plan_id in usage_plan_ids:
            usage_plan_keys = get_usage_plan_keys(
                usage_plan_id=usage_plan_id, account_id=account_id, region_name=region
            )
            for key in usage_plan_keys:
                if key["value"] == api_key_value:
                    api_key = get_api_key(
                        api_key_id=key["id"], account_id=account_id, region_name=region
                    )
                    LOG.debug("Found Api Key '%s'", api_key["id"])
                    return api_key if api_key["enabled"] else None

    def get_request_api_key(
        self, rest_api: RestApi, request: InvocationRequest, identity: IdentityContext
    ) -> Optional[str]:
        """https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-key-source.html
        The source of the API key for metering requests according to a usage plan.
        Valid values are:
        - HEADER to read the API key from the X-API-Key header of a request.
        - AUTHORIZER to read the API key from the Context Variables.
        """
        match api_key_source := rest_api.get("apiKeySource"):
            case ApiKeySourceType.HEADER:
                LOG.debug("Looking for api key in header 'X-API-Key'")
                return request.get("raw_headers", {}).get("X-API-Key")
            case ApiKeySourceType.AUTHORIZER:
                LOG.debug("Looking for api key in Identity Context")
                return identity.get("apiKey")
            case _:
                LOG.debug("Api Key Source is not valid: '%s'", api_key_source)
