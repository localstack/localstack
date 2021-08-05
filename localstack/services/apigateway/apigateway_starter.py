import json
import logging
import re
from urllib.parse import parse_qs, urlparse

from moto.apigateway import models as apigateway_models
from moto.apigateway.exceptions import NoIntegrationDefined, UsagePlanNotFoundException
from moto.apigateway.responses import APIGatewayResponse
from moto.core.utils import camelcase_to_underscores

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.apigateway.helpers import (
    TAG_KEY_CUSTOM_ID,
    apply_json_patch_safe,
    import_api_from_openapi_spec,
)
from localstack.services.infra import start_moto_server
from localstack.utils.common import DelSafeDict, short_uid, str_to_bool, to_str

LOG = logging.getLogger(__name__)

# additional REST API attributes
REST_API_ATTRIBUTES = [
    "apiKeySource",
    "disableExecuteApiEndpoint",
    "minimumCompressionSize",
]


def apply_patches():
    def apigateway_models_Stage_init(
        self, cacheClusterEnabled=False, cacheClusterSize=None, **kwargs
    ):
        apigateway_models_Stage_init_orig(
            self,
            cacheClusterEnabled=cacheClusterEnabled,
            cacheClusterSize=cacheClusterSize,
            **kwargs,
        )

        if (cacheClusterSize or cacheClusterEnabled) and not self.get("cacheClusterStatus"):
            self["cacheClusterStatus"] = "AVAILABLE"

    apigateway_models_Stage_init_orig = apigateway_models.Stage.__init__
    apigateway_models.Stage.__init__ = apigateway_models_Stage_init

    def apigateway_models_backend_delete_method(self, function_id, resource_id, method_type):
        resource = self.get_resource(function_id, resource_id)
        method = resource.get_method(method_type)
        if not method:
            return
        return resource.resource_methods.pop(method_type)

    def apigateway_models_resource_delete_integration(self, method_type):
        if method_type in self.resource_methods:
            return self.resource_methods[method_type].pop("methodIntegration", {})

        return {}

    def apigateway_models_Integration_init(
        self,
        integration_type,
        uri,
        http_method,
        request_templates=None,
        pass_through_behavior="WHEN_NO_MATCH",
        cache_key_parameters=[],
        *args,
        **kwargs,
    ):
        apigateway_models_Integration_init_orig(
            self,
            integration_type=integration_type,
            uri=uri,
            http_method=http_method,
            request_templates=request_templates,
            *args,
            **kwargs,
        )

        self["passthroughBehavior"] = pass_through_behavior
        self["cacheKeyParameters"] = cache_key_parameters
        self["cacheNamespace"] = self.get("cacheNamespace") or short_uid()

        # httpMethod not present in response if integration_type is None, verified against AWS
        if integration_type == "MOCK":
            self["httpMethod"] = None
        if request_templates:
            self["requestTemplates"] = request_templates

    def apigateway_models_backend_put_rest_api(self, function_id, body, query_params):
        rest_api = self.get_rest_api(function_id)
        return import_api_from_openapi_spec(rest_api, function_id, body, query_params)

    # import rest_api

    def apigateway_response_restapis_individual(self, request, full_url, headers):
        if request.method in ["GET", "DELETE"]:
            return apigateway_response_restapis_individual_orig(self, request, full_url, headers)

        self.setup_class(request, full_url, headers)
        function_id = self.path.replace("/restapis/", "", 1).split("/")[0]

        if self.method == "PATCH":
            not_supported_attributes = ["/id", "/region_name", "/createdDate"]

            rest_api = self.backend.apis.get(function_id)
            if not rest_api:
                msg = "Invalid API identifier specified %s:%s" % (
                    TEST_AWS_ACCOUNT_ID,
                    function_id,
                )
                return 404, {}, msg

            patch_operations = self._get_param("patchOperations")
            model_attributes = list(rest_api.__dict__.keys())
            for operation in patch_operations:
                if operation["path"] in not_supported_attributes:
                    msg = "Invalid patch path %s" % (operation["path"])
                    return 400, {}, msg
                path_start = operation["path"].strip("/").split("/")[0]
                path_start_usc = camelcase_to_underscores(path_start)
                if path_start not in model_attributes and path_start_usc in model_attributes:
                    operation["path"] = operation["path"].replace(path_start, path_start_usc)

            rest_api.__dict__ = DelSafeDict(rest_api.__dict__)
            apply_json_patch_safe(rest_api.__dict__, patch_operations, in_place=True)

            # fix data types after patches have been applied
            rest_api.minimum_compression_size = int(rest_api.minimum_compression_size or -1)
            endpoint_configs = rest_api.endpoint_configuration or {}
            if isinstance(endpoint_configs.get("vpcEndpointIds"), str):
                endpoint_configs["vpcEndpointIds"] = [endpoint_configs["vpcEndpointIds"]]

            return 200, {}, json.dumps(self.backend.get_rest_api(function_id).to_dict())

        # handle import rest_api via swagger file
        if self.method == "PUT":
            body = json.loads(to_str(self.body))
            rest_api = self.backend.put_rest_api(function_id, body, self.querystring)
            return 200, {}, json.dumps(rest_api.to_dict())

        return 400, {}, ""

    def apigateway_response_resource_methods(self, request, *args, **kwargs):
        result = apigateway_response_resource_methods_orig(self, request, *args, **kwargs)

        if self.method == "PUT" and self._get_param("requestParameters"):
            request_parameters = self._get_param("requestParameters")
            url_path_parts = self.path.split("/")
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]
            resource = self.backend.get_resource(function_id, resource_id)
            resource.resource_methods[method_type]["requestParameters"] = request_parameters
            method = resource.resource_methods[method_type]
            result = 200, {}, json.dumps(method)
        if len(result) != 3:
            return result
        authorization_type = self._get_param("authorizationType")
        if authorization_type in ["CUSTOM", "COGNITO_USER_POOLS"]:
            data = json.loads(result[2])
            if not data.get("authorizerId"):
                payload = json.loads(to_str(request.data))
                if "authorizerId" in payload:
                    data["authorizerId"] = payload["authorizerId"]
                    result = result[0], result[1], json.dumps(data)
        return result

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
            integration["timeoutInMillis"] = timeout_milliseconds
            integration["requestParameters"] = request_parameters
            integration["cacheKeyParameters"] = cache_key_parameters
            integration["contentHandling"] = content_handling
            return 200, {}, json.dumps(integration)

        if self.method == "PATCH":
            patch_operations = self._get_param("patchOperations")
            apply_json_patch_safe(integration, patch_operations, in_place=True)
            # fix data types
            if integration.get("timeoutInMillis"):
                integration["timeoutInMillis"] = int(integration.get("timeoutInMillis"))
            skip_verification = (integration.get("tlsConfig") or {}).get("insecureSkipVerification")
            if skip_verification:
                integration["tlsConfig"]["insecureSkipVerification"] = str_to_bool(
                    skip_verification
                )

        return result

    def apigateway_response_integration_responses(self, request, *args, **kwargs):
        result = apigateway_response_integration_responses_orig(self, request, *args, **kwargs)
        response_parameters = self._get_param("responseParameters")

        if self.method == "PUT" and response_parameters:
            url_path_parts = self.path.split("/")
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]
            status_code = url_path_parts[9]

            integration_response = self.backend.get_integration_response(
                function_id, resource_id, method_type, status_code
            )
            integration_response["responseParameters"] = response_parameters

            return 200, {}, json.dumps(integration_response)

        return result

    def apigateway_response_resource_method_responses(self, request, *args, **kwargs):
        result = apigateway_response_resource_method_responses_orig(self, request, *args, **kwargs)
        response_parameters = self._get_param("responseParameters")

        if self.method == "PUT" and response_parameters:
            url_path_parts = self.path.split("/")
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]
            response_code = url_path_parts[8]

            method_response = self.backend.get_method_response(
                function_id, resource_id, method_type, response_code
            )

            method_response["responseParameters"] = response_parameters

            return 200, {}, json.dumps(method_response)

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

            apply_json_patch_safe(usage_plan, patch_operations, in_place=True)
            # fix certain attributes after running the patch updates
            if isinstance(usage_plan.get("apiStages"), (dict, str)):
                usage_plan["apiStages"] = [usage_plan["apiStages"]]
            api_stages = usage_plan.get("apiStages") or []
            for i in range(len(api_stages)):
                if isinstance(api_stages[i], str) and ":" in api_stages[i]:
                    api_id, stage = api_stages[i].split(":")
                    api_stages[i] = {"apiId": api_id, "stage": stage}

            return 200, {}, json.dumps(usage_plan)
        result = apigateway_response_usage_plan_individual_orig(
            self, request, full_url, headers, *args, **kwargs
        )
        return result

    def backend_update_deployment(self, function_id, deployment_id, patch_operations):
        rest_api = self.get_rest_api(function_id)
        deployment = rest_api.get_deployment(deployment_id)
        deployment = deployment or {}
        apply_json_patch_safe(deployment, patch_operations, in_place=True)
        return deployment

    # define json-patch operations for backend models

    def backend_model_apply_operations(self, patch_operations):
        # run pre-actions
        if isinstance(self, apigateway_models.Stage):
            if [op for op in patch_operations if "/accessLogSettings" in op.get("path", "")]:
                self["accessLogSettings"] = self.get("accessLogSettings") or {}
        # apply patches
        apply_json_patch_safe(self, patch_operations, in_place=True)
        # run post-actions
        if isinstance(self, apigateway_models.Stage):
            bool_params = ["cacheClusterEnabled", "tracingEnabled"]
            for bool_param in bool_params:
                if self.get(bool_param):
                    self[bool_param] = str_to_bool(self.get(bool_param))
        return self

    model_classes = [
        apigateway_models.Authorizer,
        apigateway_models.DomainName,
        apigateway_models.Method,
        apigateway_models.MethodResponse,
        apigateway_models.Stage,
    ]
    for model_class in model_classes:
        model_class.apply_operations = (
            model_class.apply_patch_operations
        ) = backend_model_apply_operations

    # fix data types for some json-patch operation values

    def method_apply_operations(self, patch_operations):
        result = method_apply_operations_orig(self, patch_operations)
        params = self.get("requestParameters") or {}
        bool_params_prefixes = ["method.request.querystring", "method.request.header"]
        list_params = ["authorizationScopes"]
        for param, value in params.items():
            for param_prefix in bool_params_prefixes:
                if param.startswith(param_prefix):
                    params[param] = str_to_bool(value)
        for list_param in list_params:
            value = self.get(list_param)
            if value and not isinstance(value, list):
                self[list_param] = [value]
        return result

    method_apply_operations_orig = apigateway_models.Method.apply_operations
    apigateway_models.Method.apply_operations = method_apply_operations

    def method_response_apply_operations(self, patch_operations):
        result = method_response_apply_operations_orig(self, patch_operations)
        params = self.get("responseParameters") or {}
        bool_params_prefixes = ["method.response.querystring", "method.response.header"]
        for param, value in params.items():
            for param_prefix in bool_params_prefixes:
                if param.startswith(param_prefix) and not isinstance(value, bool):
                    params[param] = str(value) in ["true", "True"]
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
                return str(value) in ["true", "True"]
            return value_type(value)

        method_settings = self["methodSettings"] = self.get("methodSettings") or {}
        for operation in patch_operations:
            path = operation["path"]
            parts = path.strip("/").split("/")
            if len(parts) >= 4:
                if operation["op"] not in ["add", "replace"]:
                    continue
                key1 = "/".join(parts[:-2])
                setting_key = "%s/%s" % (parts[-2], parts[-1])
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
        if "methodIntegration" not in resource_method:
            raise NoIntegrationDefined()
        return resource_method["methodIntegration"]

    if not hasattr(apigateway_models.APIGatewayBackend, "put_rest_api"):
        apigateway_response_restapis_individual_orig = APIGatewayResponse.restapis_individual
        APIGatewayResponse.restapis_individual = apigateway_response_restapis_individual
        apigateway_models.APIGatewayBackend.put_rest_api = apigateway_models_backend_put_rest_api

    if not hasattr(apigateway_models.APIGatewayBackend, "delete_method"):
        apigateway_models.APIGatewayBackend.delete_method = apigateway_models_backend_delete_method

    if not hasattr(apigateway_models.APIGatewayBackend, "update_deployment"):
        apigateway_models.APIGatewayBackend.update_deployment = backend_update_deployment

    apigateway_models_RestAPI_to_dict_orig = apigateway_models.RestAPI.to_dict

    def apigateway_models_RestAPI_to_dict(self):
        resp = apigateway_models_RestAPI_to_dict_orig(self)
        resp["policy"] = None
        if self.policy:
            # Strip whitespaces for TF compatibility (not entirely sure why we need double-dumps,
            # but otherwise: "error normalizing policy JSON: invalid character 'V' after top-level value")
            resp["policy"] = json.dumps(json.dumps(json.loads(self.policy), separators=(",", ":")))[
                1:-1
            ]
        for attr in REST_API_ATTRIBUTES:
            if attr not in resp:
                resp[attr] = getattr(self, camelcase_to_underscores(attr), None)
        resp["disableExecuteApiEndpoint"] = bool(
            re.match(
                r"true",
                resp.get("disableExecuteApiEndpoint") or "",
                flags=re.IGNORECASE,
            )
        )

        return resp

    apigateway_response_restapis_orig = APIGatewayResponse.restapis

    # https://github.com/localstack/localstack/issues/171
    def apigateway_response_restapis(self, request, full_url, headers):
        parsed_qs = parse_qs(urlparse(full_url).query)
        modes = parsed_qs.get("mode", [])

        status, _, rest_api = apigateway_response_restapis_orig(self, request, full_url, headers)

        if "import" not in modes:
            return status, _, rest_api

        function_id = json.loads(rest_api)["id"]
        body = json.loads(request.data.decode("utf-8"))
        self.backend.put_rest_api(function_id, body, parsed_qs)

        return 200, {}, rest_api

    def individual_deployment(self, request, full_url, headers, *args, **kwargs):
        result = individual_deployment_orig(self, request, full_url, headers, *args, **kwargs)
        if self.method == "PATCH" and len(result) >= 3 and result[2] in ["null", None, str(None)]:
            url_path_parts = self.path.split("/")
            function_id = url_path_parts[2]
            deployment_id = url_path_parts[4]
            patch_operations = self._get_param("patchOperations")
            deployment = self.backend.update_deployment(
                function_id, deployment_id, patch_operations
            )
            return 200, {}, json.dumps(deployment)
        return result

    # patch create_rest_api to allow using static API IDs defined via tags

    def create_rest_api(self, *args, tags={}, **kwargs):
        result = create_rest_api_orig(self, *args, tags=tags, **kwargs)
        tags = tags or {}
        custom_id = tags.get(TAG_KEY_CUSTOM_ID)
        if custom_id:
            self.apis.pop(result.id)
            result.id = custom_id
            self.apis[custom_id] = result
        return result

    create_rest_api_orig = apigateway_models.APIGatewayBackend.create_rest_api
    apigateway_models.APIGatewayBackend.create_rest_api = create_rest_api
    apigateway_models.Resource.get_integration = apigateway_models_resource_get_integration
    apigateway_models.Resource.delete_integration = apigateway_models_resource_delete_integration
    apigateway_response_resource_methods_orig = APIGatewayResponse.resource_methods
    APIGatewayResponse.resource_methods = apigateway_response_resource_methods
    individual_deployment_orig = APIGatewayResponse.individual_deployment
    APIGatewayResponse.individual_deployment = individual_deployment
    apigateway_response_integrations_orig = APIGatewayResponse.integrations
    APIGatewayResponse.integrations = apigateway_response_integrations
    apigateway_response_integration_responses_orig = APIGatewayResponse.integration_responses
    APIGatewayResponse.integration_responses = apigateway_response_integration_responses
    apigateway_response_resource_method_responses_orig = (
        APIGatewayResponse.resource_method_responses
    )
    APIGatewayResponse.resource_method_responses = apigateway_response_resource_method_responses
    apigateway_response_usage_plan_individual_orig = APIGatewayResponse.usage_plan_individual
    APIGatewayResponse.usage_plan_individual = apigateway_response_usage_plan_individual
    apigateway_models_Integration_init_orig = apigateway_models.Integration.__init__
    apigateway_models.Integration.__init__ = apigateway_models_Integration_init
    apigateway_models.RestAPI.to_dict = apigateway_models_RestAPI_to_dict
    APIGatewayResponse.restapis = apigateway_response_restapis


def start_apigateway(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_APIGATEWAY
    apply_patches()
    result = start_moto_server(
        key="apigateway",
        name="API Gateway",
        asynchronous=asynchronous,
        port=port,
        backend_port=backend_port,
        update_listener=update_listener,
    )
    return result
