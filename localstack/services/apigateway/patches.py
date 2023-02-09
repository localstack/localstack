import json
import logging
from typing import Dict, Optional, Tuple

from moto.apigateway import models as apigateway_models
from moto.apigateway.exceptions import (
    NoIntegrationDefined,
    RestAPINotFound,
    UsagePlanNotFoundException,
)
from moto.apigateway.responses import APIGatewayResponse
from moto.core.utils import camelcase_to_underscores

from localstack.services.apigateway.helpers import TAG_KEY_CUSTOM_ID, apply_json_patch_safe
from localstack.utils.collections import ensure_list
from localstack.utils.common import DelSafeDict, str_to_bool, to_str
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

    def _patch_api_gateway_entity(self, entity: Dict) -> Optional[Tuple[int, Dict, str]]:
        not_supported_attributes = ["/id", "/region_name", "/create_date"]

        patch_operations = self._get_param("patchOperations")

        model_attributes = list(entity.keys())
        for operation in patch_operations:
            path_start = operation["path"].strip("/").split("/")[0]
            path_start_usc = camelcase_to_underscores(path_start)
            if path_start not in model_attributes and path_start_usc in model_attributes:
                operation["path"] = operation["path"].replace(path_start, path_start_usc)
            if operation["path"] in not_supported_attributes:
                msg = f'Invalid patch path {operation["path"]}'
                return 400, {}, msg

        apply_json_patch_safe(entity, patch_operations, in_place=True)
        # apply some type fixes - TODO refactor/generalize
        if "disable_execute_api_endpoint" in entity:
            entity["disableExecuteApiEndpoint"] = bool(entity.pop("disable_execute_api_endpoint"))
        if "binary_media_types" in entity:
            entity["binaryMediaTypes"] = ensure_list(entity.pop("binary_media_types"))

    def apigateway_response_resource_individual(self, request, full_url, headers):
        if request.method in ["GET", "DELETE"]:
            return apigateway_response_resource_individual_orig(self, request, full_url, headers)
        if request.method == "POST":
            _, _, result = apigateway_response_resource_individual_orig(
                self, request, full_url, headers
            )
            return 201, {}, result

        self.setup_class(request, full_url, headers)
        function_id = self.path.replace("/restapis/", "", 1).split("/")[0]

        if self.method == "PATCH":
            resource_id = self.path.split("/")[4]
            resource = self.backend.get_resource(function_id, resource_id)
            if not isinstance(resource.__dict__, DelSafeDict):
                resource.__dict__ = DelSafeDict(resource.__dict__)
            result = _patch_api_gateway_entity(self, resource.__dict__)
            if result is not None:
                return result
            return 200, {}, json.dumps(resource.to_dict())

        return 404, {}, ""

    def apigateway_response_resource_methods(self, request, *args, **kwargs):
        result = apigateway_response_resource_methods_orig(self, request, *args, **kwargs)

        if self.method == "PUT" and self._get_param("requestParameters"):
            request_parameters = self._get_param("requestParameters")
            url_path_parts = self.path.split("/")
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]
            resource = self.backend.get_resource(function_id, resource_id)
            resource.resource_methods[method_type].request_parameters = request_parameters
            method = resource.resource_methods[method_type]
            result = 201, {}, json.dumps(method.to_json())
        if len(result) != 3:
            return result

        if self.method == "PATCH":
            patch_operations = self._get_param("patchOperations")
            url_path_parts = self.path.split("/")
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]
            method = self.backend.get_method(function_id, resource_id, method_type)
            method.apply_operations(patch_operations)
            return 200, {}, json.dumps(method.to_json())

        authorization_type = self._get_param("authorizationType")
        if authorization_type in ["CUSTOM", "COGNITO_USER_POOLS"]:
            data = json.loads(result[2])
            if not data.get("authorizerId"):
                payload = json.loads(to_str(request.data))
                if "authorizerId" in payload:
                    data["authorizerId"] = payload["authorizerId"]
                    result = result[0], result[1], json.dumps(data)
                    return result
        return 201, {}, result[2]

    def apigateway_response_integrations(self, request, *args, **kwargs):
        result = apigateway_response_integrations_orig(self, request, *args, **kwargs)

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
            request_parameters = self._get_param("requestParameters") or {}
            cache_key_parameters = self._get_param("cacheKeyParameters") or []
            content_handling = self._get_param("contentHandling")
            integration.cache_namespace = resource_id
            integration.timeout_in_millis = timeout_milliseconds
            integration.request_parameters = request_parameters
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

        return result

    def apigateway_response_usage_plan_individual(
        self, request, full_url, headers, *args, **kwargs
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
        return apigateway_response_usage_plan_individual_orig(
            self, request, full_url, headers, *args, **kwargs
        )

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
        apigateway_models.Stage,
    ]
    for model_class in model_classes:
        model_class.apply_operations = (
            model_class.apply_patch_operations
        ) = backend_model_apply_operations

    # fix data types for some json-patch operation values

    def method_apply_operations(self, patch_operations):
        params = self.request_parameters or {}
        bool_params_prefixes = ["method.request.querystring", "method.request.header"]

        for param, value in params.items():
            for param_prefix in bool_params_prefixes:
                if param.startswith(param_prefix):
                    params[param] = str_to_bool(value)

        for op in patch_operations:
            path = op["path"]
            value = op["value"]
            if op["op"] == "replace":
                if "/httpMethod" in path:
                    self.http_method = value
                if "/authorizationType" in path:
                    self.authorization_type = value
                if "/authorizerId" in path:
                    self.authorizer_id = value
                if "/authorizationScopes" in path:
                    self.authorization_scopes = value
                if "/apiKeyRequired" in path:
                    self.api_key_required = str_to_bool(value) or False
                if "/requestParameters" in path:
                    self.request_parameters = value
                if "/requestModels" in path:
                    self.request_models = value
                if "/operationName" in path:
                    self.operation_name = value
                if "/requestValidatorId" in path:
                    self.request_validator_id = value
        return self

    apigateway_models.Method.apply_operations = method_apply_operations

    def method_response_apply_operations(self, patch_operations):
        result = method_response_apply_operations_orig(self, patch_operations)
        params = self.get("responseParameters") or {}
        bool_params_prefixes = ["method.response.querystring", "method.response.header"]
        for param, value in params.items():
            for param_prefix in bool_params_prefixes:
                if param.startswith(param_prefix) and not isinstance(value, bool):
                    params[param] = str(value) in {"true", "True"}
        return result

    method_response_apply_operations_orig = apigateway_models.MethodResponse.apply_operations
    apigateway_models.MethodResponse.apply_operations = method_response_apply_operations

    def stage_apply_operations(self, patch_operations):
        result = stage_apply_operations_orig(self, patch_operations)
        key_mappings = {
            "metrics/enabled": ("metricsEnabled", bool),
            "logging/loglevel": ("loggingLevel", str),
            "logging/dataTrace": ("dataTraceEnabled", bool),
            "throttling/burstLimit": ("throttlingBurstLimit", int),
            "throttling/rateLimit": ("throttlingRateLimit", float),
            "caching/enabled": ("cachingEnabled", bool),
            "caching/ttlInSeconds": ("cacheTtlInSeconds", int),
            "caching/dataEncrypted": ("cacheDataEncrypted", bool),
            "caching/requireAuthorizationForCacheControl": (
                "requireAuthorizationForCacheControl",
                bool,
            ),
            "caching/unauthorizedCacheControlHeaderStrategy": (
                "unauthorizedCacheControlHeaderStrategy",
                str,
            ),
        }

        def cast_value(value, value_type):
            if value is None:
                return value
            if value_type == bool:
                return str(value) in {"true", "True"}
            return value_type(value)

        method_settings = getattr(self, camelcase_to_underscores("methodSettings"), {})
        setattr(self, camelcase_to_underscores("methodSettings"), method_settings)
        for operation in patch_operations:
            path = operation["path"]
            parts = path.strip("/").split("/")
            if len(parts) >= 4:
                if operation["op"] not in ["add", "replace"]:
                    continue
                key1 = "/".join(parts[:-2])
                setting_key = f"{parts[-2]}/{parts[-1]}"
                setting_name, setting_type = key_mappings.get(setting_key)
                keys = [key1]
                for key in keys:
                    setting = method_settings[key] = method_settings.get(key) or {}
                    value = operation.get("value")
                    value = cast_value(value, setting_type)
                    setting[setting_name] = value
            if operation["op"] == "remove":
                method_settings.pop(path, None)
                method_settings.pop(path.lstrip("/"), None)
        return result

    stage_apply_operations_orig = apigateway_models.Stage.apply_operations
    apigateway_models.Stage.apply_operations = stage_apply_operations

    # patch integration error responses
    def apigateway_models_resource_get_integration(self, method_type):
        resource_method = self.resource_methods.get(method_type, {})
        if not resource_method.method_integration:
            raise NoIntegrationDefined()
        return resource_method.method_integration

    apigateway_response_resource_individual_orig = APIGatewayResponse.resource_individual
    APIGatewayResponse.resource_individual = apigateway_response_resource_individual

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

    def individual_deployment(self, request, full_url, headers, *args, **kwargs):
        result = individual_deployment_orig(self, request, full_url, headers, *args, **kwargs)
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

    apigateway_models.Resource.get_integration = apigateway_models_resource_get_integration
    apigateway_response_resource_methods_orig = APIGatewayResponse.resource_methods
    APIGatewayResponse.resource_methods = apigateway_response_resource_methods
    individual_deployment_orig = APIGatewayResponse.individual_deployment
    APIGatewayResponse.individual_deployment = individual_deployment
    apigateway_response_integrations_orig = APIGatewayResponse.integrations
    APIGatewayResponse.integrations = apigateway_response_integrations

    apigateway_response_usage_plan_individual_orig = APIGatewayResponse.usage_plan_individual
    APIGatewayResponse.usage_plan_individual = apigateway_response_usage_plan_individual
