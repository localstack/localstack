import json
import logging

from moto.apigateway import models as apigateway_models
from moto.apigateway.exceptions import (
    DeploymentNotFoundException,
    NoIntegrationDefined,
    RestAPINotFound,
    StageStillActive,
    UsagePlanNotFoundException,
)
from moto.apigateway.responses import APIGatewayResponse
from moto.core.utils import camelcase_to_underscores

from localstack.services.apigateway.helpers import TAG_KEY_CUSTOM_ID, apply_json_patch_safe
from localstack.utils.common import str_to_bool
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)


def apply_patches():
    # TODO refactor patches in this module (e.g., use @patch decorator, simplify, ...)

    def apigateway_models_Stage_init(
        self, cacheClusterEnabled=False, cacheClusterSize=None, **kwargs
    ):
        apigateway_models_Stage_init_orig(
            self,
            cacheClusterEnabled=cacheClusterEnabled,
            cacheClusterSize=cacheClusterSize,
            **kwargs,
        )

        if (cacheClusterSize or cacheClusterEnabled) and not self.cache_cluster_status:
            self.cache_cluster_status = "AVAILABLE"

    apigateway_models_Stage_init_orig = apigateway_models.Stage.__init__
    apigateway_models.Stage.__init__ = apigateway_models_Stage_init

    @patch(APIGatewayResponse.integrations)
    def apigateway_response_integrations(fn, self, request, *args, **kwargs):
        result = fn(self, request, *args, **kwargs)

        if self.method not in ["PUT", "PATCH"]:
            return result

        url_path_parts = self.path.split("/")
        function_id = url_path_parts[2]
        resource_id = url_path_parts[4]
        method_type = url_path_parts[6]

        integration = self.backend.get_integration(function_id, resource_id, method_type)
        if not integration:
            return result

        if self.method == "PUT":
            timeout_milliseconds = self._get_param("timeoutInMillis")
            cache_key_parameters = self._get_param("cacheKeyParameters") or []
            content_handling = self._get_param("contentHandling")
            integration.cache_namespace = resource_id
            integration.timeout_in_millis = timeout_milliseconds
            integration.cache_key_parameters = cache_key_parameters
            integration.content_handling = content_handling
            return 201, {}, json.dumps(integration.to_json())

        if self.method == "PATCH":
            patch_operations = self._get_param("patchOperations")
            apply_json_patch_safe(integration.to_json(), patch_operations, in_place=True)
            # fix data types
            if integration.timeout_in_millis:
                integration.timeout_in_millis = int(integration.timeout_in_millis)
            if skip_verification := (integration.tls_config or {}).get("insecureSkipVerification"):
                integration.tls_config["insecureSkipVerification"] = str_to_bool(skip_verification)
            return 200, {}, json.dumps(integration.to_json())

        return result

    @patch(APIGatewayResponse.usage_plan_individual)
    def apigateway_response_usage_plan_individual(
        fn, self, request, full_url, headers, *args, **kwargs
    ):
        self.setup_class(request, full_url, headers)
        if self.method == "PATCH":
            url_path_parts = self.path.split("/")
            usage_plan_id = url_path_parts[2]
            patch_operations = self._get_param("patchOperations")
            usage_plan = self.backend.usage_plans.get(usage_plan_id)
            if not usage_plan:
                raise UsagePlanNotFoundException()

            apply_json_patch_safe(usage_plan.to_json(), patch_operations, in_place=True)
            # fix certain attributes after running the patch updates
            if isinstance(usage_plan.api_stages, (dict, str)):
                usage_plan.api_stages = [usage_plan.api_stages]
            api_stages = usage_plan.api_stages or []
            for i in range(len(api_stages)):
                if isinstance(api_stages[i], str) and ":" in api_stages[i]:
                    api_id, stage = api_stages[i].split(":")
                    api_stages[i] = {"apiId": api_id, "stage": stage}

            return 200, {}, json.dumps(usage_plan.to_json())
        return fn(self, request, full_url, headers, *args, **kwargs)

    def backend_update_deployment(self, function_id, deployment_id, patch_operations):
        rest_api = self.get_rest_api(function_id)
        deployment = rest_api.get_deployment(deployment_id)
        deployment = deployment.to_json() or {}
        apply_json_patch_safe(deployment, patch_operations, in_place=True)
        return deployment

    # define json-patch operations for backend models

    def backend_model_apply_operations(self, patch_operations):
        # run pre-actions
        if isinstance(self, apigateway_models.Stage) and [
            op for op in patch_operations if "/accessLogSettings" in op.get("path", "")
        ]:
            self.access_log_settings = self.access_log_settings or {}
        # apply patches
        apply_json_patch_safe(self, patch_operations, in_place=True)
        # run post-actions
        if isinstance(self, apigateway_models.Stage):
            bool_params = ["cacheClusterEnabled", "tracingEnabled"]
            for bool_param in bool_params:
                if getattr(self, camelcase_to_underscores(bool_param), None):
                    value = getattr(self, camelcase_to_underscores(bool_param), None)
                    setattr(self, camelcase_to_underscores(bool_param), str_to_bool(value))
        return self

    model_classes = [
        apigateway_models.Authorizer,
        apigateway_models.DomainName,
        apigateway_models.MethodResponse,
    ]
    for model_class in model_classes:
        model_class.apply_operations = (
            model_class.apply_patch_operations
        ) = backend_model_apply_operations

    # fix data types for some json-patch operation values

    @patch(apigateway_models.Stage._get_default_method_settings)
    def _get_default_method_settings(fn, self):
        result = fn(self)
        default_settings = self.method_settings.get("*/*", {})
        result["cacheDataEncrypted"] = default_settings.get("cacheDataEncrypted", False)
        result["throttlingRateLimit"] = default_settings.get("throttlingRateLimit", 10000.0)
        result["metricsEnabled"] = default_settings.get("metricsEnabled", False)
        result["dataTraceEnabled"] = default_settings.get("dataTraceEnabled", False)
        result["unauthorizedCacheControlHeaderStrategy"] = default_settings.get(
            "unauthorizedCacheControlHeaderStrategy", "SUCCEED_WITH_RESPONSE_HEADER"
        )
        result["cacheTtlInSeconds"] = default_settings.get("cacheTtlInSeconds", 300)
        result["cachingEnabled"] = default_settings.get("cachingEnabled", False)
        result["requireAuthorizationForCacheControl"] = default_settings.get(
            "requireAuthorizationForCacheControl", True
        )
        return result

    # patch integration error responses
    @patch(apigateway_models.Resource.get_integration)
    def apigateway_models_resource_get_integration(fn, self, method_type):
        resource_method = self.resource_methods.get(method_type, {})
        if not resource_method.method_integration:
            raise NoIntegrationDefined()
        return resource_method.method_integration

    if not hasattr(apigateway_models.APIGatewayBackend, "update_deployment"):
        apigateway_models.APIGatewayBackend.update_deployment = backend_update_deployment

    @patch(apigateway_models.RestAPI.to_dict)
    def apigateway_models_rest_api_to_dict(fn, self):
        resp = fn(self)
        resp["policy"] = None
        if self.policy:
            # Strip whitespaces for TF compatibility (not entirely sure why we need double-dumps,
            # but otherwise: "error normalizing policy JSON: invalid character 'V' after top-level value")
            resp["policy"] = json.dumps(json.dumps(json.loads(self.policy), separators=(",", ":")))[
                1:-1
            ]

        if not self.tags:
            resp["tags"] = None

        resp["disableExecuteApiEndpoint"] = (
            str(resp.get("disableExecuteApiEndpoint")).lower() == "true"
        )

        return resp

    @patch(apigateway_models.Stage.to_json)
    def apigateway_models_stage_to_json(fn, self):
        result = fn(self)

        if "documentationVersion" not in result:
            result["documentationVersion"] = getattr(self, "documentation_version", None)

        return result

    @patch(APIGatewayResponse.individual_deployment)
    def individual_deployment(fn, self, request, full_url, headers, *args, **kwargs):
        result = fn(self, request, full_url, headers, *args, **kwargs)
        if self.method == "PATCH":
            url_path_parts = self.path.split("/")
            function_id = url_path_parts[2]
            deployment_id = url_path_parts[4]
            patch_operations = self._get_param("patchOperations")
            deployment = self.backend.update_deployment(
                function_id, deployment_id, patch_operations
            )
            return 201, {}, json.dumps(deployment)
        return result

    @patch(apigateway_models.APIGatewayBackend.create_rest_api)
    def create_rest_api(fn, self, *args, tags=None, **kwargs):
        """
        https://github.com/localstack/localstack/pull/4413/files
        Add ability to specify custom IDs for API GW REST APIs via tags
        """
        tags = tags or {}
        result = fn(self, *args, tags=tags, **kwargs)
        # TODO: lower the custom_id when getting it from the tags, as AWS is case insensitive
        if custom_id := tags.get(TAG_KEY_CUSTOM_ID):
            self.apis.pop(result.id)
            result.id = custom_id
            self.apis[custom_id] = result
        return result

    @patch(apigateway_models.APIGatewayBackend.get_rest_api, pass_target=False)
    def get_rest_api(self, function_id):
        for key in self.apis.keys():
            if key.lower() == function_id.lower():
                return self.apis[key]
        raise RestAPINotFound()

    @patch(apigateway_models.RestAPI.delete_deployment, pass_target=False)
    def patch_delete_deployment(self, deployment_id: str) -> apigateway_models.Deployment:
        if deployment_id not in self.deployments:
            raise DeploymentNotFoundException()
        deployment = self.deployments[deployment_id]
        if deployment.stage_name and (
            (stage := self.stages.get(deployment.stage_name))
            and stage.deployment_id == deployment.id
        ):
            # Stage is still active
            raise StageStillActive()

        return self.deployments.pop(deployment_id)
