import json
import logging
from moto.apigateway import models as apigateway_models
from moto.apigateway.models import Resource, Integration
from moto.apigateway.responses import APIGatewayResponse
from moto.apigateway.exceptions import NoIntegrationDefined
from moto.apigateway.utils import create_id
from localstack import config
from localstack.utils.common import short_uid, to_str
from localstack.services.infra import start_moto_server

LOG = logging.getLogger(__name__)


def apply_patches():
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

    def apigateway_models_Integration_init(
            self, integration_type, uri, http_method,
            request_templates=None, pass_through_behavior='WHEN_NO_MATCH', cache_key_parameters=[]
    ):
        super(apigateway_models.Integration, self).__init__()
        self['type'] = integration_type
        self['uri'] = uri
        self['httpMethod'] = http_method
        self['passthroughBehavior'] = pass_through_behavior
        self['cacheKeyParameters'] = cache_key_parameters
        self['cacheNamespace'] = short_uid()
        self['integrationResponses'] = {'200': apigateway_models.IntegrationResponse(200)}
        if request_templates:
            self['requestTemplates'] = request_templates

    apigateway_models.Integration.__init__ = apigateway_models_Integration_init

    def apigateway_models_backend_put_rest_api(self, function_id, body):
        rest_api = self.get_rest_api(function_id)
        # Remove default root, then add paths from API spec
        rest_api.resources = {}
        for path in body['paths']:
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

        # handle import rest_api via swagger file
        if self.method == 'PUT':
            body = json.loads(to_str(self.body))
            if not body.get('paths'):
                return 400, {}, ''

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
                data['authorizerId'] = json.loads(request.data.decode('utf-8'))['authorizerId']
                result = result[0], result[1], json.dumps(data)
        return result

    if not hasattr(apigateway_models.APIGatewayBackend, 'put_rest_api'):
        apigateway_response_restapis_individual_orig = APIGatewayResponse.restapis_individual
        APIGatewayResponse.restapis_individual = apigateway_response_restapis_individual
        apigateway_models.APIGatewayBackend.put_rest_api = apigateway_models_backend_put_rest_api

    if not hasattr(apigateway_models.APIGatewayBackend, 'delete_method'):
        apigateway_models.APIGatewayBackend.delete_method = apigateway_models_backend_delete_method

    apigateway_models.Resource.get_method = apigateway_models_resource_get_method
    apigateway_models.Resource.get_integration = apigateway_models_resource_get_integration
    apigateway_models.Resource.delete_integration = apigateway_models_resource_delete_integration
    apigateway_response_resource_methods_orig = APIGatewayResponse.resource_methods
    APIGatewayResponse.resource_methods = apigateway_response_resource_methods


def start_apigateway(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_APIGATEWAY
    apply_patches()
    result = start_moto_server(
        key='apigateway', name='API Gateway', asynchronous=asynchronous,
        port=port, backend_port=backend_port, update_listener=update_listener
    )
    return result
