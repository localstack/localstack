import re
import json
import logging
from jsonpatch import apply_patch
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

LOG = logging.getLogger(__name__)

# additional REST API attributes
REST_API_ATTRIBUTES = ['disableExecuteApiEndpoint', 'apiKeySource', 'minimumCompressionSize']


def apply_json_patch_safe(subject, patch_operations, in_place=True):
    for operation in patch_operations:
        try:
            return apply_patch(subject, [operation], in_place=in_place)
        except Exception as e:
            if operation['op'] == 'replace' and 'replace a non-existent object' in str(e):
                # fall back to an ADD operation if the REPLACE fails
                operation['op'] = 'add'
                return apply_patch(subject, [operation], in_place=in_place)
            raise


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
            raise NoIntegrationDefined()

        return resource.resource_methods.pop(method_type)

    def apigateway_models_resource_get_method(self, method_type):
        method = self.resource_methods.get(method_type)
        if not method:
            raise NoIntegrationDefined()

        return method

    def apigateway_models_resource_get_integration(self, method_type):
        resource_method = self.resource_methods.get(method_type, {})
        if 'methodIntegration' not in resource_method:
            raise NoIntegrationDefined()

        return resource_method['methodIntegration']

    def apigateway_models_resource_delete_integration(self, method_type):
        if method_type in self.resource_methods:
            return self.resource_methods[method_type].pop('methodIntegration')

        return {}

    def apigateway_models_Integration_init(self, integration_type, uri, http_method,
            request_templates=None, pass_through_behavior='WHEN_NO_MATCH', cache_key_parameters=[], *args, **kwargs):
        apigateway_models_Integration_init_orig(
            self, integration_type=integration_type, uri=uri, http_method=http_method,
            request_templates=request_templates, *args, **kwargs
        )

        self['passthroughBehavior'] = pass_through_behavior
        self['cacheKeyParameters'] = cache_key_parameters
        self['cacheNamespace'] = short_uid()

        # httpMethod not present in response if integration_type is None, verified against AWS
        if integration_type == 'MOCK':
            self['httpMethod'] = None
        if request_templates:
            self['requestTemplates'] = request_templates

    def apigateway_models_backend_put_rest_api(self, function_id, body):
        rest_api = self.get_rest_api(function_id)
        # Remove default root, then add paths from API spec
        rest_api.resources = {}
        for path in body.get('paths', {}):
            child_id = create_id()
            child = Resource(
                id=child_id,
                region_name=rest_api.region_name,
                api_id=rest_api.id,
                path_part=path,
                parent_id='',
            )
            for m, payload in body['paths'][path].items():
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

        return rest_api

    # Implement import rest_api
    # https://github.com/localstack/localstack/issues/2763
    def apigateway_response_restapis_individual(self, request, full_url, headers):

        if request.method in ['GET', 'DELETE']:
            return apigateway_response_restapis_individual_orig(self, request, full_url, headers)

        self.setup_class(request, full_url, headers)
        function_id = self.path.replace('/restapis/', '', 1).split('/')[0]

        if self.method == 'PATCH':
            not_supported_attributes = ['/id', '/region_name', '/create_date']

            rest_api = self.backend.apis.get(function_id)
            if not rest_api:
                msg = 'Invalid API identifier specified %s:%s' % (TEST_AWS_ACCOUNT_ID, function_id)
                return (404, {}, msg)

            patch_operations = self._get_param('patchOperations')
            for operation in patch_operations:
                if operation['path'].strip('/') in REST_API_ATTRIBUTES:
                    operation['path'] = camelcase_to_underscores(operation['path'])
                if operation['path'] in not_supported_attributes:
                    msg = 'Invalid patch path %s' % (operation['path'])
                    return (400, {}, msg)

            rest_api.__dict__ = DelSafeDict(rest_api.__dict__)
            apply_json_patch_safe(rest_api.__dict__, patch_operations, in_place=True)

            return 200, {}, json.dumps(self.backend.get_rest_api(function_id).to_dict())

        # handle import rest_api via swagger file
        if self.method == 'PUT':
            body = json.loads(to_str(self.body))
            rest_api = self.backend.put_rest_api(function_id, body)
            return 200, {}, json.dumps(rest_api.to_dict())

        return 400, {}, ''

    def apigateway_response_resource_methods(self, request, *args, **kwargs):
        result = apigateway_response_resource_methods_orig(self, request, *args, **kwargs)

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
        timeout_milliseconds = self._get_param('timeoutInMillis')
        request_parameters = self._get_param('requestParameters') or {}
        cache_key_parameters = self._get_param('cacheKeyParameters') or []
        content_handling = self._get_param('contentHandling')

        if self.method == 'PUT':
            url_path_parts = self.path.split('/')
            function_id = url_path_parts[2]
            resource_id = url_path_parts[4]
            method_type = url_path_parts[6]

            integration_response = self.backend.get_integration(function_id, resource_id, method_type)

            integration_response['timeoutInMillis'] = timeout_milliseconds
            integration_response['requestParameters'] = request_parameters
            integration_response['cacheKeyParameters'] = cache_key_parameters
            integration_response['contentHandling'] = content_handling
            return 200, {}, json.dumps(integration_response)

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

    if not hasattr(apigateway_models.APIGatewayBackend, 'put_rest_api'):
        apigateway_response_restapis_individual_orig = APIGatewayResponse.restapis_individual
        APIGatewayResponse.restapis_individual = apigateway_response_restapis_individual
        apigateway_models.APIGatewayBackend.put_rest_api = apigateway_models_backend_put_rest_api

    if not hasattr(apigateway_models.APIGatewayBackend, 'delete_method'):
        apigateway_models.APIGatewayBackend.delete_method = apigateway_models_backend_delete_method

    apigateway_models_RestAPI_to_dict_orig = apigateway_models.RestAPI.to_dict

    def apigateway_models_RestAPI_to_dict(self):
        resp = apigateway_models_RestAPI_to_dict_orig(self)
        resp['policy'] = None
        if self.policy:
            # Currently still not found any document about apigateway policy escaped format, just a workaround
            resp['policy'] = json.dumps(json.dumps(json.loads(self.policy)))[1:-1]
        for attr in REST_API_ATTRIBUTES:
            if attr not in resp:
                resp[attr] = getattr(self, camelcase_to_underscores(attr), None)
        resp['disableExecuteApiEndpoint'] = bool(re.match(r'true',
            resp.get('disableExecuteApiEndpoint') or '', flags=re.IGNORECASE))

        return resp

    apigateway_models.Resource.get_method = apigateway_models_resource_get_method
    apigateway_models.Resource.get_integration = apigateway_models_resource_get_integration
    apigateway_models.Resource.delete_integration = apigateway_models_resource_delete_integration
    apigateway_response_resource_methods_orig = APIGatewayResponse.resource_methods
    APIGatewayResponse.resource_methods = apigateway_response_resource_methods
    apigateway_response_integrations_orig = APIGatewayResponse.integrations
    APIGatewayResponse.integrations = apigateway_response_integrations
    apigateway_response_integration_responses_orig = APIGatewayResponse.integration_responses
    APIGatewayResponse.integration_responses = apigateway_response_integration_responses
    apigateway_response_resource_method_responses_orig = APIGatewayResponse.resource_method_responses
    APIGatewayResponse.resource_method_responses = apigateway_response_resource_method_responses
    apigateway_models_Integration_init_orig = apigateway_models.Integration.__init__
    apigateway_models.Integration.__init__ = apigateway_models_Integration_init
    apigateway_models.RestAPI.to_dict = apigateway_models_RestAPI_to_dict


def start_apigateway(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_APIGATEWAY
    apply_patches()
    result = start_moto_server(
        key='apigateway', name='API Gateway', asynchronous=asynchronous,
        port=port, backend_port=backend_port, update_listener=update_listener
    )
    return result
