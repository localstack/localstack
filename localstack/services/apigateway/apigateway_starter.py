import re
import json
import logging
from urllib.parse import parse_qs, urlparse
from moto.core.utils import camelcase_to_underscores
from moto.apigateway import models as apigateway_models
from moto.apigateway.models import Resource, Integration
from moto.apigateway.responses import APIGatewayResponse
from moto.apigateway.exceptions import NoIntegrationDefined
from moto.apigateway.utils import create_id
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.common import short_uid, to_str, DelSafeDict
from localstack.services.infra import start_moto_server
from localstack.services.apigateway.helpers import apply_json_patch_safe

LOG = logging.getLogger(__name__)

TRUE_STRINGS = ['true', 'True']

# additional REST API attributes
REST_API_ATTRIBUTES = ['disableExecuteApiEndpoint', 'apiKeySource', 'minimumCompressionSize']


def apply_patches():
    def apigateway_models_Stage_init(self, cacheClusterEnabled=False, cacheClusterSize=None, **kwargs):
        apigateway_models_Stage_init_orig(self, cacheClusterEnabled=cacheClusterEnabled,
            cacheClusterSize=cacheClusterSize, **kwargs)

        if (cacheClusterSize or cacheClusterEnabled) and not self.get('cacheClusterStatus'):
            self['cacheClusterStatus'] = 'AVAILABLE'

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
            return self.resource_methods[method_type].pop('methodIntegration', {})

        return {}

    def apigateway_models_Integration_init(self, integration_type, uri, http_method,
            request_templates=None, pass_through_behavior='WHEN_NO_MATCH', cache_key_parameters=[], *args, **kwargs):
        apigateway_models_Integration_init_orig(
            self, integration_type=integration_type, uri=uri, http_method=http_method,
            request_templates=request_templates, *args, **kwargs
        )

        self['passthroughBehavior'] = pass_through_behavior
        self['cacheKeyParameters'] = cache_key_parameters
        self['cacheNamespace'] = self.get('cacheNamespace') or short_uid()

        # httpMethod not present in response if integration_type is None, verified against AWS
        if integration_type == 'MOCK':
            self['httpMethod'] = None
        if request_templates:
            self['requestTemplates'] = request_templates

    def apigateway_models_backend_put_rest_api(self, function_id, body, query_params):
        rest_api = self.get_rest_api(function_id)
        # Remove default root, then add paths from API spec
        rest_api.resources = {}

        def get_or_create_path(path):
            parts = path.rstrip('/').replace('//', '/').split('/')
            parent_id = ''
            if len(parts) > 1:
                parent_path = '/'.join(parts[:-1])
                parent = get_or_create_path(parent_path)
                parent_id = parent.id
            existing = [r for r in rest_api.resources.values() if
                r.path_part == (parts[-1] or '/') and
                (r.parent_id or '') == (parent_id or '')]
            if existing:
                return existing[0]
            return add_path(path, parts, parent_id=parent_id)

        def add_path(path, parts, parent_id=''):
            child_id = create_id()
            path = path or '/'
            child = Resource(
                id=child_id,
                region_name=rest_api.region_name,
                api_id=rest_api.id,
                path_part=parts[-1] or '/',
                parent_id=parent_id
            )
            for m, payload in body['paths'].get(path, {}).items():
                m = m.upper()
                payload = payload['x-amazon-apigateway-integration']

                child.add_method(
                    m, None, None
                )
                integration = Integration(
                    http_method=m,
                    uri=payload.get('uri'),
                    integration_type=payload['type'],
                    pass_through_behavior=payload.get('passthroughBehavior'),
                    request_templates=payload.get('requestTemplates') or {}
                )
                integration.create_integration_response(
                    status_code=payload.get('responses', {}).get('default', {}).get('statusCode', 200),
                    selection_pattern=None,
                    response_templates=None,
                    content_handling=None
                )
                child.resource_methods[m]['methodIntegration'] = integration

            rest_api.resources[child_id] = child
            return child

        basepath_mode = (query_params.get('basepath') or ['prepend'])[0]
        base_path = (body.get('basePath') or '') if basepath_mode == 'prepend' else ''
        for path in body.get('paths', {}):
            get_or_create_path(base_path + path)

        policy = body.get('x-amazon-apigateway-policy')
        if policy:
            policy = json.dumps(policy) if isinstance(policy, dict) else str(policy)
            rest_api.policy = policy
        minimum_compression_size = body.get('x-amazon-apigateway-minimum-compression-size')
        if minimum_compression_size is not None:
            rest_api.minimum_compression_size = int(minimum_compression_size)

        return rest_api

    # import rest_api

    def apigateway_response_restapis_individual(self, request, full_url, headers):
        if request.method in ['GET', 'DELETE']:
            return apigateway_response_restapis_individual_orig(self, request, full_url, headers)

        self.setup_class(request, full_url, headers)
        function_id = self.path.replace('/restapis/', '', 1).split('/')[0]

        if self.method == 'PATCH':
            not_supported_attributes = ['/id', '/region_name', '/createdDate']

            rest_api = self.backend.apis.get(function_id)
            if not rest_api:
                msg = 'Invalid API identifier specified %s:%s' % (TEST_AWS_ACCOUNT_ID, function_id)
                return 404, {}, msg

            patch_operations = self._get_param('patchOperations')
            model_attributes = list(rest_api.__dict__.keys())
            for operation in patch_operations:
                if operation['path'] in not_supported_attributes:
                    msg = 'Invalid patch path %s' % (operation['path'])
                    return 400, {}, msg
                path_stripped = operation['path'].strip('/')
                path_underscores = camelcase_to_underscores(path_stripped)
                if path_stripped not in model_attributes and path_underscores in model_attributes:
                    operation['path'] = operation['path'].replace(path_stripped, path_underscores)

            rest_api.__dict__ = DelSafeDict(rest_api.__dict__)
            apply_json_patch_safe(rest_api.__dict__, patch_operations, in_place=True)

            # fix data types after patches have been applied
            # if rest_api.minimum_compression_size:
            rest_api.minimum_compression_size = int(rest_api.minimum_compression_size or -1)

            return 200, {}, json.dumps(self.backend.get_rest_api(function_id).to_dict())

        # handle import rest_api via swagger file
        if self.method == 'PUT':
            body = json.loads(to_str(self.body))
            rest_api = self.backend.put_rest_api(function_id, body, self.querystring)
            return 200, {}, json.dumps(rest_api.to_dict())

        return 400, {}, ''

    def apigateway_response_resource_methods(self, request, *args, **kwargs):
        result = apigateway_response_resource_methods_orig(self, request, *args, **kwargs)

        if self.method == 'PUT' and self._get_param('requestParameters'):
            request_parameters = self._get_param('requestParameters')
            url_path_parts = self.path.split('/')
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]
            resource = self.backend.get_resource(function_id, resource_id)
            resource.resource_methods[method_type]['requestParameters'] = request_parameters
            method = resource.resource_methods[method_type]
            result = 200, {}, json.dumps(method)
        if len(result) != 3:
            return result
        authorization_type = self._get_param('authorizationType')
        if authorization_type in ['CUSTOM', 'COGNITO_USER_POOLS']:
            data = json.loads(result[2])
            if not data.get('authorizerId'):
                payload = json.loads(to_str(request.data))
                if 'authorizerId' in payload:
                    data['authorizerId'] = payload['authorizerId']
                    result = result[0], result[1], json.dumps(data)
        return result

    def apigateway_response_integrations(self, request, *args, **kwargs):
        result = apigateway_response_integrations_orig(self, request, *args, **kwargs)

        if self.method not in ['PUT', 'PATCH']:
            return result

        url_path_parts = self.path.split('/')
        function_id = url_path_parts[2]
        resource_id = url_path_parts[4]
        method_type = url_path_parts[6]

        integration = self.backend.get_integration(function_id, resource_id, method_type)
        if not integration:
            return result

        if self.method == 'PUT':
            timeout_milliseconds = self._get_param('timeoutInMillis')
            request_parameters = self._get_param('requestParameters') or {}
            cache_key_parameters = self._get_param('cacheKeyParameters') or []
            content_handling = self._get_param('contentHandling')
            integration['timeoutInMillis'] = timeout_milliseconds
            integration['requestParameters'] = request_parameters
            integration['cacheKeyParameters'] = cache_key_parameters
            integration['contentHandling'] = content_handling
            return 200, {}, json.dumps(integration)

        if self.method == 'PATCH':
            patch_operations = self._get_param('patchOperations')
            apply_json_patch_safe(integration, patch_operations, in_place=True)
            # fix data types
            if integration.get('timeoutInMillis'):
                integration['timeoutInMillis'] = int(integration.get('timeoutInMillis'))
            skip_verification = (integration.get('tlsConfig') or {}).get('insecureSkipVerification')
            if skip_verification:
                integration['tlsConfig']['insecureSkipVerification'] = str(skip_verification) in TRUE_STRINGS

        return result

    def apigateway_response_integration_responses(self, request, *args, **kwargs):
        result = apigateway_response_integration_responses_orig(self, request, *args, **kwargs)
        response_parameters = self._get_param('responseParameters')

        if self.method == 'PUT' and response_parameters:
            url_path_parts = self.path.split('/')
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]
            status_code = url_path_parts[9]

            integration_response = self.backend.get_integration_response(
                function_id, resource_id, method_type, status_code
            )
            integration_response['responseParameters'] = response_parameters

            return 200, {}, json.dumps(integration_response)

        return result

    def apigateway_response_resource_method_responses(self, request, *args, **kwargs):
        result = apigateway_response_resource_method_responses_orig(self, request, *args, **kwargs)
        response_parameters = self._get_param('responseParameters')

        if self.method == 'PUT' and response_parameters:
            url_path_parts = self.path.split('/')
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]
            response_code = url_path_parts[8]

            method_response = self.backend.get_method_response(function_id, resource_id, method_type, response_code)

            method_response['responseParameters'] = response_parameters

            return 200, {}, json.dumps(method_response)

        return result

    def backend_update_deployment(self, function_id, deployment_id, patch_operations):
        rest_api = self.get_rest_api(function_id)
        deployment = rest_api.get_deployment(deployment_id)
        deployment = deployment or {}
        apply_json_patch_safe(deployment, patch_operations, in_place=True)
        return deployment

    # define json-patch operations for backend models

    def backend_model_apply_operations(self, patch_operations):
        apply_json_patch_safe(self, patch_operations, in_place=True)
        return self

    model_classes = [apigateway_models.Authorizer, apigateway_models.Stage,
        apigateway_models.Method, apigateway_models.MethodResponse]
    for model_class in model_classes:
        model_class.apply_operations = backend_model_apply_operations

    # fix data types for some json-patch operation values

    def method_apply_operations(self, patch_operations):
        result = method_apply_operations_orig(self, patch_operations)
        params = self.get('requestParameters') or {}
        bool_params_prefixes = ['method.request.querystring', 'method.request.header']
        list_params = ['authorizationScopes']
        for param, value in params.items():
            for param_prefix in bool_params_prefixes:
                if param.startswith(param_prefix) and not isinstance(value, bool):
                    params[param] = str(value) in TRUE_STRINGS
        for list_param in list_params:
            value = self.get(list_param)
            if value and not isinstance(value, list):
                self[list_param] = [value]
        return result

    method_apply_operations_orig = apigateway_models.Method.apply_operations
    apigateway_models.Method.apply_operations = method_apply_operations

    def method_response_apply_operations(self, patch_operations):
        result = method_response_apply_operations_orig(self, patch_operations)
        params = self.get('responseParameters') or {}
        bool_params_prefixes = ['method.response.querystring', 'method.response.header']
        for param, value in params.items():
            for param_prefix in bool_params_prefixes:
                if param.startswith(param_prefix) and not isinstance(value, bool):
                    params[param] = str(value) in ['true', 'True']
        return result

    method_response_apply_operations_orig = apigateway_models.MethodResponse.apply_operations
    apigateway_models.MethodResponse.apply_operations = method_response_apply_operations

    def stage_apply_operations(self, patch_operations):
        result = stage_apply_operations_orig(self, patch_operations)
        key_mappings = {
            'metrics/enabled': ('metricsEnabled', bool),
            'logging/loglevel': ('loggingLevel', str),
            'logging/dataTrace': ('dataTraceEnabled', bool),
            'throttling/burstLimit': ('throttlingBurstLimit', int),
            'throttling/rateLimit': ('throttlingRateLimit', float),
            'caching/enabled': ('cachingEnabled', bool),
            'caching/ttlInSeconds': ('cacheTtlInSeconds', int),
            'caching/dataEncrypted': ('cacheDataEncrypted', bool),
            'caching/requireAuthorizationForCacheControl': ('requireAuthorizationForCacheControl', bool),
            'caching/unauthorizedCacheControlHeaderStrategy': ('unauthorizedCacheControlHeaderStrategy', str)
        }

        def cast_value(value, value_type):
            if value is None:
                return value
            if value_type == bool:
                return str(value) in ['true', 'True']
            return value_type(value)

        method_settings = self['methodSettings'] = self.get('methodSettings') or {}
        for operation in patch_operations:
            path = operation['path']
            parts = path.strip('/').split('/')
            if len(parts) >= 4:
                if operation['op'] not in ['add', 'replace']:
                    continue
                key1 = '/'.join(parts[:-2])
                key2 = '/%s' % key1
                setting_key = '%s/%s' % (parts[-2], parts[-1])
                setting_name, setting_type = key_mappings.get(setting_key)
                # keys = [key1, key2]  # TODO remove?
                keys = [key2]
                for key in keys:
                    setting = method_settings[key] = method_settings.get(key) or {}
                    value = operation.get('value')
                    value = cast_value(value, setting_type)
                    setting[setting_name] = value
            if operation['op'] == 'remove':
                method_settings.pop(path, None)
        return result

    stage_apply_operations_orig = apigateway_models.Stage.apply_operations
    apigateway_models.Stage.apply_operations = stage_apply_operations

    # patch integration error responses

    def apigateway_models_resource_get_integration(self, method_type):
        resource_method = self.resource_methods.get(method_type, {})
        if 'methodIntegration' not in resource_method:
            raise NoIntegrationDefined()
        return resource_method['methodIntegration']

    if not hasattr(apigateway_models.APIGatewayBackend, 'put_rest_api'):
        apigateway_response_restapis_individual_orig = APIGatewayResponse.restapis_individual
        APIGatewayResponse.restapis_individual = apigateway_response_restapis_individual
        apigateway_models.APIGatewayBackend.put_rest_api = apigateway_models_backend_put_rest_api

    if not hasattr(apigateway_models.APIGatewayBackend, 'delete_method'):
        apigateway_models.APIGatewayBackend.delete_method = apigateway_models_backend_delete_method

    if not hasattr(apigateway_models.APIGatewayBackend, 'update_deployment'):
        apigateway_models.APIGatewayBackend.update_deployment = backend_update_deployment

    apigateway_models_RestAPI_to_dict_orig = apigateway_models.RestAPI.to_dict

    def apigateway_models_RestAPI_to_dict(self):
        resp = apigateway_models_RestAPI_to_dict_orig(self)
        resp['policy'] = None
        if self.policy:
            # Strip whitespaces for TF compatibility (not entirely sure why we need double-dumps,
            # but otherwise: "error normalizing policy JSON: invalid character 'V' after top-level value")
            resp['policy'] = json.dumps(json.dumps(json.loads(self.policy), separators=(',', ':')))[1:-1]
        for attr in REST_API_ATTRIBUTES:
            if attr not in resp:
                resp[attr] = getattr(self, camelcase_to_underscores(attr), None)
        resp['disableExecuteApiEndpoint'] = bool(re.match(r'true',
            resp.get('disableExecuteApiEndpoint') or '', flags=re.IGNORECASE))

        return resp

    apigateway_response_restapis_orig = APIGatewayResponse.restapis

    # https://github.com/localstack/localstack/issues/171
    def apigateway_response_restapis(self, request, full_url, headers):
        parsed_qs = parse_qs(urlparse(full_url).query)
        modes = parsed_qs.get('mode', [])

        status, _, rest_api = apigateway_response_restapis_orig(self, request, full_url, headers)

        if 'import' not in modes:
            return status, _, rest_api

        function_id = json.loads(rest_api)['id']
        body = json.loads(request.data.decode('utf-8'))
        self.backend.put_rest_api(function_id, body, parsed_qs)

        return 200, {}, rest_api

    def individual_deployment(self, request, full_url, headers, *args, **kwargs):
        result = individual_deployment_orig(self, request, full_url, headers, *args, **kwargs)
        if self.method == 'PATCH' and len(result) >= 3 and result[2] in ['null', None, str(None)]:
            url_path_parts = self.path.split('/')
            function_id = url_path_parts[2]
            deployment_id = url_path_parts[4]
            patch_operations = self._get_param('patchOperations')
            deployment = self.backend.update_deployment(function_id, deployment_id, patch_operations)
            return 200, {}, json.dumps(deployment)
        return result

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
    apigateway_response_resource_method_responses_orig = APIGatewayResponse.resource_method_responses
    APIGatewayResponse.resource_method_responses = apigateway_response_resource_method_responses
    apigateway_models_Integration_init_orig = apigateway_models.Integration.__init__
    apigateway_models.Integration.__init__ = apigateway_models_Integration_init
    apigateway_models.RestAPI.to_dict = apigateway_models_RestAPI_to_dict
    APIGatewayResponse.restapis = apigateway_response_restapis


def start_apigateway(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_APIGATEWAY
    apply_patches()
    result = start_moto_server(
        key='apigateway', name='API Gateway', asynchronous=asynchronous,
        port=port, backend_port=backend_port, update_listener=update_listener
    )
    return result
